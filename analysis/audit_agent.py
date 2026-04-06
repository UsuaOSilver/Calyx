"""
analysis/audit_agent.py

SKANF-Guided AI Audit Agent — closes the loop between bytecode analysis
and human-readable security findings.

Implements Sen Yang's direction: "tell AI how to analyze smart contracts
based on SKANF … can AI agents do better in such smart contracts?"

The core insight: raw bytecode is noise to an LLM.  SKANF's output —
deobfuscated CFG, taint findings, sensitive address annotations, confirmed
exploits — is the structured context that makes LLM reasoning *accurate*
on closed-source contracts that every other tool refuses to analyze.

Multi-provider support via raw HTTP (no extra SDK dependencies):

  Provider       | Key env var       | Default model
  ─────────────── ─────────────────── ───────────────────────────────
  anthropic       ANTHROPIC_API_KEY   claude-sonnet-4-6   (best)
  gemini          GEMINI_API_KEY      gemini-2.0-flash    (free tier)
  groq            GROQ_API_KEY        llama-3.3-70b-versatile (free tier)
  openai          OPENAI_API_KEY      gpt-4o
  openai-compat   OPENAI_API_KEY      set AUDIT_MODEL + AUDIT_BASE_URL

Provider is auto-detected from whichever key is present.  Override with
AUDIT_PROVIDER env var.  Override model with AUDIT_MODEL.

RAG augmentation (optional, automatic):
  If the EVMbench RAG index has been built (scripts/build_rag_index.py),
  AuditAgent auto-loads it and injects 3 similar past findings + 2 false-
  positive distractors into every prompt (NyxLLM 2.0 ICL pattern).
  This significantly improves weaker free-tier models (Gemini Flash, Llama-70B).
  Pass rag=False to disable, or rag=<RAGRetriever> to use a custom instance.

Usage:
    from analysis.audit_agent import AuditAgent

    agent = AuditAgent()                 # auto-detect provider + auto-load RAG
    report = agent.audit(pipeline_result)

    print(report["verdict"])             # VULNERABLE / LIKELY_VULNERABLE / CLEAN
    print(report["vulnerability_summary"])
    for f in report["findings"]:
        print(f["title"], "—", f["severity"])
        print("  Exploit:", f["exploit_scenario"])
        print("  Fix:    ", f["recommendation"])

    # Check RAG status
    print(report.get("rag_examples_used"))  # int — 0 if RAG unavailable

    # Disable RAG explicitly:
    agent = AuditAgent(rag=False)

    # Convenience: check if agent is ready before running pipeline
    if AuditAgent.available():
        ...

Integration with BytecodePipeline:
    result = pipeline.analyze_address("0x...", audit=True)
    # result["audit_report"] contains the full report dict
    # result["audit_error"]  is set on failure, None on success
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger(__name__)

# ── Provider defaults ─────────────────────────────────────────────────────

_PROVIDER_DEFAULTS: Dict[str, Dict[str, str]] = {
    "anthropic": {
        "model":    "claude-sonnet-4-6",
        "base_url": "https://api.anthropic.com/v1/messages",
    },
    "gemini": {
        "model":    "gemini-2.0-flash",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    },
    "groq": {
        "model":    "llama-3.3-70b-versatile",
        "base_url": "https://api.groq.com/openai/v1/chat/completions",
    },
    "openai": {
        "model":    "gpt-4o",
        "base_url": "https://api.openai.com/v1/chat/completions",
    },
}

# Max characters of pipeline context to send (prevents token overrun on small models)
_MAX_CONTEXT_CHARS = 24_000


# ── System prompt ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert EVM smart contract security auditor specializing in closed-source
and obfuscated contracts (bytecode-only, no Solidity source available).

You are using SKANF-style analysis output (IC3/Yale, 2025). SKANF detects
vulnerabilities in obfuscated MEV bots and DeFi contracts via:

1. CFG deobfuscation  — indirect jumps resolved; complete control-flow graph recovered
2. Static taint analysis — tracks attacker-controlled inputs (calldata, CALLVALUE,
   ORIGIN) through the EVM stack to CALL sinks
   - AM1: attacker controls the CALL target address → can redirect fund flows
   - AM2: attacker controls the CALL value (ETH amount) → can drain ETH
3. Sensitive address filter — AM1 findings where the CALL target is a known DeFi
   token (WETH, USDT, USDC, WBTC, etc.) are ERC-20 theft vulnerabilities
4. GNN scoring  — graph neural network estimates exploit probability from CFG topology
5. Transaction history — on-chain evidence of real usage patterns + hot function selectors
6. Fork-EVM validation — Anvil confirms actual exploitability by measuring ETH delta

AM3/AM4/AM5 are pattern-only detections (no taint needed):
  AM3: tx.origin used as access control (phishing risk)
  AM4: approve + transferFrom without balance check (token drain)
  AM5: callback with no return-value check (reentrancy risk)

Your job:
1. Interpret each finding in terms of attacker capability and real-world impact
2. Write a clear, step-by-step exploit scenario for each finding
3. Assess confidence based on signal convergence (taint + GNN + txn history + validation)
4. Recommend a concrete, actionable mitigation
5. Give a final verdict and triage decision

TRUST the taint analysis findings. erc20_sensitive=True means the CALL targets a
real DeFi token — this is high-confidence ERC-20 theft. confirmed=True means an
actual fork-EVM proof-of-exploit succeeded. Do not dismiss findings because you
cannot see Solidity source.

Respond ONLY with valid JSON — no markdown fences, no commentary outside the JSON:
{
  "verdict": "<VULNERABLE|LIKELY_VULNERABLE|CLEAN|INCONCLUSIVE>",
  "vulnerability_summary": "<1-2 sentence summary of the core security issue>",
  "findings": [
    {
      "type": "<AM1|AM2|AM3|AM4|AM5>",
      "title": "<short, specific title>",
      "description": "<what this vulnerability is and why it exists>",
      "exploit_scenario": "<numbered steps: how an attacker exploits this>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "confidence": "<HIGH|MEDIUM|LOW>",
      "recommendation": "<concrete fix — what the developer must change>"
    }
  ],
  "overall_assessment": "<2-3 sentence paragraph suitable for an executive summary>",
  "triage_recommendation": "<BLOCK|FLAG|MONITOR|SAFE>",
  "audit_notes": "<caveats, limitations, or context about this analysis>"
}"""


class AuditAgent:
    """
    LLM-powered security audit agent for SKANF pipeline output.

    Instantiate once; call audit() per contract.  All state is stateless
    between calls — safe to reuse across multiple contracts.

    Args:
        rag: RAGRetriever instance, None (auto-load), or False (disable).
             Auto-load tries detectors/claude_scanner/rag.py; silently
             skips if chromadb/sentence-transformers are missing or the
             index has not been built yet.
    """

    def __init__(self, rag=None) -> None:
        self._provider, self._api_key, self._model, self._base_url = (
            self._resolve_provider()
        )
        if rag is False:
            self._rag = None
        elif rag is not None:
            self._rag = rag
        else:
            self._rag = self._auto_load_rag()

    # ── Public API ────────────────────────────────────────────────────────

    @classmethod
    def available(cls) -> bool:
        """Return True if at least one LLM provider is configured."""
        provider, key, *_ = cls._resolve_provider()
        return bool(key)

    def audit(self, pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run LLM audit on a BytecodePipeline result.

        Args:
            pipeline_result: The dict returned by BytecodePipeline.analyze_bytecode()
                             or analyze_address().  Must contain at least risk_score,
                             am_findings, and gnn_result.

        Returns:
            Audit report dict with keys:
              verdict, vulnerability_summary, findings, overall_assessment,
              triage_recommendation, audit_notes, provider, model,
              rag_examples_used, error
        """
        if not self._api_key:
            return self._error_report(
                "No LLM provider configured. Set one of: "
                "ANTHROPIC_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, OPENAI_API_KEY"
            )

        context, rag_count = self._build_context(pipeline_result, rag=self._rag)
        try:
            raw = self._call_llm(context)
        except Exception as exc:
            log.error(f"AuditAgent LLM call failed: {exc}")
            return self._error_report(str(exc))

        report = self._parse_response(raw)
        report["provider"]          = self._provider
        report["model"]             = self._model
        report["rag_examples_used"] = rag_count
        return report

    # ── RAG auto-load ─────────────────────────────────────────────────────

    @staticmethod
    def _auto_load_rag():
        """
        Try to load RAGRetriever from the pre-built EVMbench index.
        Returns None silently if chromadb/sentence-transformers are missing
        or the index has not been built yet.
        """
        try:
            from detectors.claude_scanner.rag import RAGRetriever
            r = RAGRetriever()
            if r.is_ready():
                log.info(f"AuditAgent: RAG index loaded ({r.count()} docs)")
                return r
            log.debug("AuditAgent: RAG index empty — run scripts/build_rag_index.py to enable")
            return None
        except Exception as e:
            log.debug(f"AuditAgent: RAG not available ({e})")
            return None

    # ── Provider resolution ───────────────────────────────────────────────

    @staticmethod
    def _resolve_provider():
        """Pick provider from env vars; return (provider, api_key, model, base_url)."""
        explicit = os.environ.get("AUDIT_PROVIDER", "").lower()

        # Priority: explicit override → anthropic → gemini → groq → openai → none
        candidates = (
            [explicit] if explicit in _PROVIDER_DEFAULTS
            else ["anthropic", "gemini", "groq", "openai"]
        )

        key_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini":    "GEMINI_API_KEY",
            "groq":      "GROQ_API_KEY",
            "openai":    "OPENAI_API_KEY",
        }

        for provider in candidates:
            env_key = key_map.get(provider, "OPENAI_API_KEY")
            api_key = os.environ.get(env_key, "")
            if api_key:
                defaults  = _PROVIDER_DEFAULTS[provider]
                model     = os.environ.get("AUDIT_MODEL", defaults["model"])
                base_url  = os.environ.get("AUDIT_BASE_URL", defaults["base_url"])
                return provider, api_key, model, base_url

        return "anthropic", "", "", _PROVIDER_DEFAULTS["anthropic"]["base_url"]

    # ── Context building ──────────────────────────────────────────────────

    @staticmethod
    def _build_context(result: Dict[str, Any], rag=None):
        """
        Build the user-turn message from a pipeline result.

        Uses ContextBuilder if available; falls back to a compact inline summary
        so the agent always has enough data to reason from.

        If rag is provided, prepends a few-shot block of similar past findings
        (positive examples) and false-positive distractors (negative examples)
        before the SKANF output.

        Returns:
            (context_str, rag_examples_used)  — rag_examples_used is 0 if RAG
            was not available or returned no results.
        """
        try:
            from analysis.context_builder import ContextBuilder
            full_context = ContextBuilder(result).build()
        except Exception:
            full_context = AuditAgent._compact_context(result)

        # Trim to token-safe size (rough char proxy: 1 token ≈ 4 chars)
        if len(full_context) > _MAX_CONTEXT_CHARS:
            full_context = (
                full_context[:_MAX_CONTEXT_CHARS]
                + f"\n\n[... context truncated at {_MAX_CONTEXT_CHARS} chars ...]"
            )

        addr    = result.get("address") or "(bytecode only)"
        network = result.get("network", "ethereum")

        rag_block, rag_count = AuditAgent._build_rag_block(result, rag)

        parts = [f"Audit target: {addr} on {network}", ""]
        if rag_block:
            parts += [rag_block, ""]
        parts += ["=== SKANF PIPELINE ANALYSIS OUTPUT ===", "", full_context]

        return "\n".join(parts), rag_count

    @staticmethod
    def _build_rag_block(result: Dict[str, Any], rag) -> tuple:
        """
        Retrieve similar past findings and false-positive distractors from RAG.

        Query is built from am_findings types + descriptions so retrieval is
        targeted to the actual patterns detected in this contract.

        Returns:
            (block_str, examples_used)  — block_str is "" if RAG unavailable.
        """
        if rag is None:
            return "", 0

        # Build query from detected findings
        findings = result.get("am_findings", [])
        query_parts = []
        for f in findings[:5]:
            t = f.get("type", "")
            d = f.get("description", "")
            if t or d:
                query_parts.append(f"{t}: {d}")
        if not query_parts:
            query_parts = [
                f"risk:{result.get('risk_level', 'UNKNOWN')}",
                "smart contract vulnerability reentrancy access control",
            ]
        query = " | ".join(query_parts)[:500]

        lines = []
        total = 0

        try:
            positives = rag.retrieve(query, k=3)
            if positives:
                lines.append(
                    "=== SIMILAR PAST VULNERABILITY FINDINGS (few-shot examples) ==="
                )
                lines.append(
                    "These are confirmed real findings from past audits. "
                    "Use them to calibrate severity, description quality, and exploit steps."
                )
                lines.append("")
                for i, ex in enumerate(positives, 1):
                    lines.append(
                        f"--- Example {i} [{ex['doc_type']}] "
                        f"(similarity={ex['similarity']:.2f}) ---"
                    )
                    lines.append(f"Title: {ex['title']}")
                    lines.append(ex["text"][:600])
                    lines.append("")
                total += len(positives)
        except Exception as e:
            log.debug(f"RAG retrieve failed: {e}")

        try:
            negatives = rag.retrieve_negatives(query, k=2)
            if negatives:
                lines.append("=== FALSE POSITIVE PATTERNS TO AVOID ===")
                lines.append(
                    "These are plausible-sounding but incorrect findings from past audits. "
                    "Do NOT report similar patterns unless you have stronger evidence."
                )
                lines.append("")
                for i, ex in enumerate(negatives, 1):
                    lines.append(
                        f"--- False positive {i} (similarity={ex['similarity']:.2f}) ---"
                    )
                    lines.append(f"Title: {ex['title']}")
                    lines.append(ex["text"][:400])
                    lines.append("")
        except Exception as e:
            log.debug(f"RAG retrieve_negatives failed: {e}")

        return "\n".join(lines), total

    @staticmethod
    def _compact_context(result: Dict[str, Any]) -> str:
        """Fallback compact context when ContextBuilder is unavailable."""
        lines = [
            f"Risk score: {result.get('risk_score', 0):.3f}",
            f"Risk level: {result.get('risk_level', 'UNKNOWN')}",
            "",
            "Findings:",
        ]
        for f in result.get("am_findings", []):
            lines.append(
                f"  [{f.get('type')}] {f.get('severity', '').upper()} "
                f"@ PC {f.get('pc', '?')} — {f.get('description', '')}"
            )
            if f.get("erc20_sensitive"):
                lines.append(f"    ERC-20 sensitive: {f.get('sensitive_token_addr')}")
            if f.get("confirmed"):
                lines.append(f"    CONFIRMED exploit: {f.get('eth_drained_wei')} wei drained")
            elif f.get("failure_reason"):
                lines.append(f"    Exploit attempt: {f.get('failure_reason')}")

        gnn = result.get("gnn_result", {})
        lines += [
            "",
            f"GNN exploit probability: {gnn.get('exploit_probability', 0):.3f}",
            f"GNN risk level: {gnn.get('risk_level', 'UNKNOWN')}",
        ]

        txn = result.get("txn_result", {})
        if txn:
            lines.append(f"Transaction anomaly score: {txn.get('anomaly_score', 0):.3f}")

        return "\n".join(lines)

    # ── LLM dispatch ─────────────────────────────────────────────────────

    def _call_llm(self, context: str) -> str:
        """Route to the appropriate provider API and return the raw response text."""
        if self._provider == "anthropic":
            return self._call_anthropic(context)
        elif self._provider == "gemini":
            return self._call_gemini(context)
        else:
            # groq + openai + openai-compat all use the same schema
            return self._call_openai_compat(context)

    def _call_anthropic(self, context: str) -> str:
        resp = requests.post(
            self._base_url,
            headers={
                "x-api-key":         self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      self._model,
                "max_tokens": 2048,
                "system":     _SYSTEM_PROMPT,
                "messages":   [{"role": "user", "content": context}],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    def _call_gemini(self, context: str) -> str:
        url = self._base_url.format(model=self._model) + f"?key={self._api_key}"
        resp = requests.post(
            url,
            headers={"content-type": "application/json"},
            json={
                "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": context}]}],
                "generationConfig": {
                    "maxOutputTokens": 2048,
                    "temperature":     0.0,
                },
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    def _call_openai_compat(self, context: str) -> str:
        resp = requests.post(
            self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "content-type":  "application/json",
            },
            json={
                "model":       self._model,
                "max_tokens":  2048,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": context},
                ],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    # ── Response parsing ─────────────────────────────────────────────────

    @staticmethod
    def _parse_response(raw: str) -> Dict[str, Any]:
        """
        Parse the LLM response into a report dict.

        Handles common LLM quirks:
          - JSON wrapped in markdown fences (```json ... ```)
          - Trailing commas
          - Minor whitespace issues
        """
        # Strip markdown code fences if present
        text = raw.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
        if fence:
            text = fence.group(1).strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting the first {...} block
        brace_match = re.search(r"\{[\s\S]+\}", text)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        # Fallback: return raw text wrapped in a minimal report
        log.warning("AuditAgent: could not parse LLM response as JSON")
        return {
            "verdict":              "INCONCLUSIVE",
            "vulnerability_summary": "LLM response could not be parsed as structured JSON.",
            "findings":             [],
            "overall_assessment":   raw[:1000],
            "triage_recommendation": "FLAG",
            "audit_notes":          "Raw LLM output stored in overall_assessment.",
            "error":                "json_parse_failed",
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _error_report(message: str) -> Dict[str, Any]:
        return {
            "verdict":               "INCONCLUSIVE",
            "vulnerability_summary": "",
            "findings":              [],
            "overall_assessment":    "",
            "triage_recommendation": "FLAG",
            "audit_notes":           "",
            "provider":              None,
            "model":                 None,
            "rag_examples_used":     0,
            "error":                 message,
        }
