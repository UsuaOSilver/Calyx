"""
analysis/context_builder.py

Structured LLM Context Builder — Hackathon P2 (SKANF author future direction #1).

SKANF author: "tells AI how to analyze smart contract based on SKANF… deobfuscate
CFG as context for LLM agent… guide AI agent to use historical transactions."

This module packages the full BytecodePipeline output into a structured, human- and
machine-readable context document ready to be passed to any LLM for deeper analysis
or as a final deliverable for a security audit report.

Output formats:
  - Markdown: `build()` → rich markdown suitable for audit reports or LLM prompts
  - JSON:     `build_json()` → machine-readable structured dict for API consumers

Usage:
    from analysis.context_builder import ContextBuilder

    builder = ContextBuilder(pipeline_result)
    md_context  = builder.build()        # markdown string
    json_context = builder.build_json()  # dict

    # Save report
    with open("report.md", "w") as f:
        f.write(md_context)
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional


# Severity display helpers
_SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
_RISK_LEVEL_EMOJI = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🟢 LOW",
    "UNKNOWN":  "⚪ UNKNOWN",
}


class ContextBuilder:
    """
    Converts a BytecodePipeline result dict into rich, structured context.

    Designed to serve both human readers (markdown audit report) and LLM agents
    (structured JSON with per-stage analysis ready for in-context reasoning).
    """

    def __init__(self, pipeline_result: Dict[str, Any]) -> None:
        self._r = pipeline_result

    # ── Public API ────────────────────────────────────────────────────────────

    def build(self) -> str:
        """
        Build a markdown context document from the pipeline result.

        Returns:
            Full markdown string suitable for audit reports, LLM prompts, or
            sharing as a standalone security assessment.
        """
        r = self._r
        address  = r.get("address") or "N/A"
        network  = r.get("network", "ethereum")
        risk_lvl = _RISK_LEVEL_EMOJI.get(r.get("risk_level", "UNKNOWN"), "⚪ UNKNOWN")
        score    = r.get("risk_score", 0.0)
        now      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        lines: List[str] = [
            f"# Calyx Security Analysis — {address}",
            f"",
            f"**Network:** {network}  |  **Generated:** {now}  |  **Risk Level:** {risk_lvl}  |  **Risk Score:** {score:.3f}",
            f"",
        ]

        # ── Executive Summary ─────────────────────────────────────────────────
        lines += self._section_exec_summary(r, address, risk_lvl, score)

        # ── CFG Deobfuscation ─────────────────────────────────────────────────
        lines += self._section_cfg(r)

        # ── Taint Analysis Findings ───────────────────────────────────────────
        lines += self._section_taint(r)

        # ── Pattern Detector Findings ─────────────────────────────────────────
        lines += self._section_patterns(r)

        # ── GNN Scoring ───────────────────────────────────────────────────────
        lines += self._section_gnn(r)

        # ── Transaction Evidence ──────────────────────────────────────────────
        lines += self._section_txn(r)

        # ── Exploit Validation ────────────────────────────────────────────────
        lines += self._section_exploits(r)

        # ── Risk Breakdown ────────────────────────────────────────────────────
        lines += self._section_risk_breakdown(r)

        # ── TAC-Style Control Flow Summary (T1 -- arXiv:2506.19624) ─────────
        lines += self._section_tac_summary(r)

        # ── LLM Prompt Guidance ───────────────────────────────────────────────
        lines += self._section_llm_guidance(r)

        return "\n".join(lines)

    def build_json(self) -> Dict[str, Any]:
        """
        Build a machine-readable structured context dict.

        Returns:
            Dict with all pipeline sub-results, findings, and metadata,
            suitable for API consumers or LLM tool-call responses.
        """
        r = self._r
        findings    = r.get("am_findings", [])
        confirmed   = r.get("confirmed_exploits", [])
        taint_res   = r.get("taint_result", {})
        gnn_res     = r.get("gnn_result", {})
        txn_res     = r.get("txn_result", {})
        cfg_deob    = r.get("cfg_deob", {})
        cfg_profile = r.get("cfg_profile", {})
        txn_guided  = r.get("txn_guided_taint", {})

        return {
            "metadata": {
                "address":    r.get("address"),
                "network":    r.get("network", "ethereum"),
                "generated":  datetime.utcnow().isoformat() + "Z",
                "tool":       "Calyx SKANF-Lite v1.0",
            },
            "risk": {
                "score":       r.get("risk_score", 0.0),
                "level":       r.get("risk_level", "UNKNOWN"),
                "breakdown":   r.get("breakdown", {}),
            },
            "findings": {
                "total":         len(findings),
                "am_types":      sorted({f["type"] for f in findings}),
                "items":         findings,
                "confirmed":     confirmed,
            },
            "cfg": {
                "deobfuscation": cfg_deob,
                "profile":       cfg_profile,
            },
            "taint_analysis": {
                "caller_guarded": taint_res.get("caller_guarded", False),
                "am_types_found": taint_res.get("am_types_found", []),
                "error":          taint_res.get("error"),
            },
            "gnn": {
                "exploit_probability": gnn_res.get("exploit_probability", 0.0),
                "risk_level":          gnn_res.get("risk_level", "UNKNOWN"),
                "block_count":         gnn_res.get("block_count", 0),
                "edge_count":          gnn_res.get("edge_count", 0),
            },
            "transactions": {
                "anomaly_score":    txn_res.get("anomaly_score", 0.0),
                "anomaly_flags":    txn_res.get("anomaly_flags", []),
                "guided_taint":     {
                    "txn_count":       txn_guided.get("txn_count", 0),
                    "evidence_txns":   txn_guided.get("evidence_txns", []),
                    "hot_selectors":   txn_guided.get("hot_selectors", []),
                } if txn_guided else None,
            },
        }

    # ── Section builders ──────────────────────────────────────────────────────

    @staticmethod
    def _section_exec_summary(
        r: Dict[str, Any],
        address: str,
        risk_lvl: str,
        score: float,
    ) -> List[str]:
        findings   = r.get("am_findings", [])
        confirmed  = r.get("confirmed_exploits", [])
        am_types   = sorted({f["type"] for f in findings})
        error      = r.get("error")

        lines = ["## Executive Summary", ""]
        if error:
            lines += [f"> **Error:** {error}", ""]
            return lines

        lines += [
            f"| Field | Value |",
            f"|---|---|",
            f"| Risk Level | {risk_lvl} |",
            f"| Risk Score | {score:.3f} / 1.000 |",
            f"| Total Findings | {len(findings)} |",
            f"| Vulnerability Types | {', '.join(am_types) if am_types else 'None'} |",
            f"| Confirmed Exploits | {len(confirmed)} |",
            f"",
        ]

        # Plain-language summary
        if not findings:
            lines.append("> No vulnerability signals detected across all analysis stages.")
        else:
            sev_counts: Dict[str, int] = {}
            for f in findings:
                sev_counts[f.get("severity", "low")] = sev_counts.get(f.get("severity", "low"), 0) + 1
            sev_summary = ", ".join(
                f"{cnt} {sev.upper()}" for sev, cnt in sorted(sev_counts.items())
            )
            lines.append(
                f"> Detected **{len(findings)} findings** ({sev_summary}) "
                f"spanning types: **{', '.join(am_types)}**."
            )
            if confirmed:
                lines.append(
                    f"> **{len(confirmed)} exploit(s) confirmed** via fork-EVM validation."
                )
        lines.append("")
        return lines

    @staticmethod
    def _section_cfg(r: Dict[str, Any]) -> List[str]:
        cfg_deob    = r.get("cfg_deob", {})
        cfg_profile = r.get("cfg_profile", {})
        if not cfg_deob and not cfg_profile:
            return []

        lines = ["## CFG Analysis", ""]
        lines += [
            "### Deobfuscation (Gap 1)",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Basic Blocks | {cfg_deob.get('block_count', 'N/A')} |",
            f"| CFG Edges | {cfg_deob.get('edge_count', 'N/A')} |",
            f"| Resolved Jumps | {cfg_deob.get('resolved', 'N/A')} |",
            f"| Over-approximated | {cfg_deob.get('approximated', 'N/A')} |",
            "",
        ]

        if cfg_profile:
            obs  = cfg_profile.get("obfuscation_score", 0.0)
            asmt = cfg_profile.get("assessment", "N/A")
            ijmp = cfg_profile.get("indirect_jump_count", 0)
            lines += [
                "### Obfuscation Profile",
                "",
                f"| Metric | Value |",
                f"|---|---|",
                f"| Obfuscation Score | {obs:.3f} |",
                f"| Assessment | {asmt} |",
                f"| Indirect Jump Count | {ijmp} |",
                "",
            ]
        return lines

    @staticmethod
    def _section_taint(r: Dict[str, Any]) -> List[str]:
        taint_res = r.get("taint_result", {})
        findings  = [f for f in r.get("am_findings", []) if f["type"] in ("AM1", "AM2")]
        if not taint_res and not findings:
            return []

        lines = ["## Taint Analysis (Gap 2)", ""]
        guarded = taint_res.get("caller_guarded", False)
        lines.append(f"**Caller guard detected:** {'Yes — AM1 suppressed' if guarded else 'No'}")
        lines.append("")

        if not findings:
            lines.append("> No AM1/AM2 data-flow vulnerabilities detected.")
            lines.append("")
            return lines

        lines.append("### Findings")
        lines.append("")
        for f in findings:
            sev_icon = _SEVERITY_EMOJI.get(f.get("severity", "low"), "")
            lines += [
                f"#### {sev_icon} {f['type']} — PC {f.get('pc', 'N/A')}",
                "",
                f"**Severity:** {f.get('severity', 'N/A').upper()}  |  "
                f"**Taint Source:** `{f.get('taint_source', 'N/A')}`",
                "",
                f"{f.get('description', '')}",
                "",
            ]
            if f.get("confirmed"):
                lines.append(
                    f"> **Confirmed** by fork-EVM — {f.get('eth_drained_wei', 0)} wei drained."
                )
                lines.append("")
        return lines

    @staticmethod
    def _section_patterns(r: Dict[str, Any]) -> List[str]:
        findings = [f for f in r.get("am_findings", []) if f["type"] in ("AM3", "AM4", "AM5", "AM7", "AM8")]
        if not findings:
            return []

        lines = ["## Pattern Detector (AM3–AM8)", ""]
        for f in findings:
            sev_icon = _SEVERITY_EMOJI.get(f.get("severity", "low"), "")
            lines += [
                f"#### {sev_icon} {f['type']} — PC {f.get('pc', 'N/A')}",
                "",
                f"**Severity:** {f.get('severity', 'N/A').upper()}",
                "",
                f"{f.get('description', '')}",
                "",
            ]
        return lines

    @staticmethod
    def _section_gnn(r: Dict[str, Any]) -> List[str]:
        gnn = r.get("gnn_result", {})
        if not gnn:
            return []

        lines = ["## GNN Analysis", ""]
        lines += [
            f"| Metric | Value |",
            f"|---|---|",
            f"| Exploit Probability | {gnn.get('exploit_probability', 0.0):.3f} |",
            f"| Risk Level | {gnn.get('risk_level', 'N/A')} |",
            f"| Basic Blocks | {gnn.get('block_count', 'N/A')} |",
            f"| CFG Edges | {gnn.get('edge_count', 'N/A')} |",
            "",
        ]
        return lines

    @staticmethod
    def _section_txn(r: Dict[str, Any]) -> List[str]:
        txn_res    = r.get("txn_result", {})
        txn_guided = r.get("txn_guided_taint", {})
        if not txn_res and not txn_guided:
            return []

        lines = ["## Transaction Analysis", ""]
        if txn_res:
            anomaly = txn_res.get("anomaly_score", 0.0)
            flags   = txn_res.get("anomaly_flags", [])
            lines += [
                f"**Anomaly Score:** {anomaly:.3f}  |  "
                f"**Flags:** {', '.join(flags) if flags else 'None'}",
                "",
            ]

        if txn_guided and txn_guided.get("txn_count", 0) > 0:
            cnt     = txn_guided["txn_count"]
            hot     = txn_guided.get("hot_selectors", [])
            ev_txns = txn_guided.get("evidence_txns", [])

            lines += [
                "### Historical Transaction Evidence (Txn-Guided Taint — P1)",
                "",
                f"Analyzed **{cnt}** recent transactions.",
                "",
            ]

            if hot:
                lines += ["**Most-called function selectors:**", ""]
                lines.append("| Selector | Calls | % |")
                lines.append("|---|---|---|")
                for sel in hot[:5]:
                    lines.append(
                        f"| `{sel['selector']}` | {sel['count']} | {sel['pct']}% |"
                    )
                lines.append("")

            if ev_txns:
                lines += [
                    f"**{len(ev_txns)} evidence transaction(s) matching vulnerability patterns:**",
                    "",
                    "| Hash | Block | From | AM Type | ETH Value (wei) | Note |",
                    "|---|---|---|---|---|---|",
                ]
                for tx in ev_txns[:10]:
                    h = tx["hash"]
                    short_hash = h[:10] + "..." if len(h) > 10 else h
                    lines.append(
                        f"| `{short_hash}` | {tx.get('block', '')} | "
                        f"`{str(tx.get('from', ''))[:10]}...` | "
                        f"{tx.get('am_type', '')} | {tx.get('eth_value_wei', 0)} | "
                        f"{tx.get('note', '')} |"
                    )
                lines.append("")
        return lines

    @staticmethod
    def _section_exploits(r: Dict[str, Any]) -> List[str]:
        all_findings  = r.get("am_findings", [])
        confirmed     = r.get("confirmed_exploits", [])
        # Findings that were attempted but not confirmed (have a failure_reason)
        attempted = [
            f for f in all_findings
            if f.get("failure_reason") and f.get("failure_reason") not in (
                "not_exploitable_type", "validator_unavailable"
            )
        ]

        if not confirmed and not attempted:
            return []

        lines = ["## Exploit Validation (Gap 3)", ""]
        lines.append(
            "> Structured failure log implemented as a Calyx extension to SKANF "
            "(original artifact omits this — SKANF author, Discord 2026-03-11: "
            '"we do not include this part, you can extend it if necessary").'
        )
        lines.append("")

        if confirmed:
            lines.append(f"**{len(confirmed)} exploit(s) CONFIRMED via fork-EVM (Anvil):**")
            lines.append("")
            for ex in confirmed:
                lines.append(
                    f"- **{ex['type']}** at PC {ex.get('pc', 'N/A')}: "
                    f"{ex.get('eth_drained_wei', 0)} wei drained"
                )
            lines.append("")

        if attempted:
            lines.append("**Attempted but not confirmed — structured failure log:**")
            lines.append("")
            lines.append("| Type | PC | Failure Reason | Detail |")
            lines.append("|---|---|---|---|")
            for f in attempted:
                reason = f.get("failure_reason", "unknown")
                detail = f.get("error") or ""
                lines.append(
                    f"| {f.get('type', '?')} | {f.get('pc', '?')} "
                    f"| `{reason}` | {detail[:80]} |"
                )
            lines.append("")

        return lines

    @staticmethod
    def _section_risk_breakdown(r: Dict[str, Any]) -> List[str]:
        breakdown = r.get("breakdown", {})
        if not breakdown:
            return []

        lines = ["## Risk Score Breakdown", ""]
        lines += [
            f"| Component | Weight | Contribution |",
            f"|---|---|---|",
            f"| GNN Score | 30% | {breakdown.get('gnn_contribution', 0.0):.3f} |",
            f"| Findings  | 55% | {breakdown.get('findings_contribution', 0.0):.3f} |",
            f"| Txn Anomaly | 15% | {breakdown.get('txn_contribution', 0.0):.3f} |",
            f"| **Total** | **100%** | **{r.get('risk_score', 0.0):.3f}** |",
            "",
        ]
        return lines

    @staticmethod
    def _section_tac_summary(r: Dict[str, Any]) -> List[str]:
        """TAC-style control flow summary (T1 -- arXiv:2506.19624).
        Structured block representation for LLM reasoning on closed-source contracts.
        Addresses Sen Yang direction: making control-flow information readable."""
        cfg_deob    = r.get("cfg_deob", {})
        cfg_profile = r.get("cfg_profile", {})
        func_split  = r.get("function_split", {})
        if not cfg_deob and not cfg_profile:
            return []
        obs  = cfg_profile.get("obfuscation_score", 0.0) if cfg_profile else 0.0
        asmt = cfg_profile.get("assessment", "unknown") if cfg_profile else "unknown"
        lines = [
            "## TAC-Style Control Flow Summary (T1)",
            "",
            "> Structured control-flow for LLM analysis (arXiv:2506.19624 + SKANF author direction).",
            "",
            "```",
            f"BYTECODE_SIZE   : {cfg_profile.get('instruction_count', 'N/A') if cfg_profile else 'N/A'} instructions",
            f"CFG_BLOCKS      : {cfg_deob.get('block_count', 'N/A')}",
            f"CFG_EDGES       : {cfg_deob.get('edge_count', 'N/A')}",
            f"RESOLVED_JUMPS  : {cfg_deob.get('resolved', 'N/A')}",
            f"OBF_SCORE       : {obs:.3f}  [{asmt.upper()}]",
        ]
        functions = func_split.get("functions", {}) if func_split else {}
        if functions:
            lines.append(f"FUNCTION_COUNT  : {len(functions)}")
            lines.append("FUNCTION_DISPATCH_TABLE:")
            for sel, info in list(functions.items())[:10]:
                lines.append(f"  {sel:>12s}  ->  JUMPDEST@{info.get('entry_pc', '?')}")
        lines += ["```", ""]
        return lines

    @staticmethod
    def _build_tac_summary(r: Dict[str, Any]) -> Dict[str, Any]:
        cfg_deob   = r.get("cfg_deob", {})
        cfg_profile = r.get("cfg_profile", {})
        func_split  = r.get("function_split", {})
        return {
            "block_count":       cfg_deob.get("block_count") if cfg_deob else None,
            "edge_count":        cfg_deob.get("edge_count") if cfg_deob else None,
            "obfuscation_score": cfg_profile.get("obfuscation_score", 0.0) if cfg_profile else 0.0,
            "assessment":        cfg_profile.get("assessment", "unknown") if cfg_profile else "unknown",
            "functions":         func_split.get("functions", {}) if func_split else {},
            "function_count":    func_split.get("function_count", 0) if func_split else 0,
        }

    @staticmethod
    def _section_llm_guidance(r: Dict[str, Any]) -> List[str]:
        """Append an LLM prompt fragment with all key findings summarized."""
        findings   = r.get("am_findings", [])
        am_types   = sorted({f["type"] for f in findings})
        risk_level = r.get("risk_level", "UNKNOWN")
        risk_score = r.get("risk_score", 0.0)
        address    = r.get("address") or "unknown"

        lines = [
            "---",
            "",
            "## LLM Context Summary",
            "",
            "> This section is designed as a ready-to-use prompt fragment for",
            "> LLM-based deeper analysis (per SKANF author future direction #1).",
            "",
            "```",
            f"CONTRACT: {address}",
            f"RISK: {risk_level} ({risk_score:.3f})",
            f"VULNERABILITIES DETECTED: {', '.join(am_types) if am_types else 'NONE'}",
            "",
        ]

        for f in findings[:10]:
            lines.append(
                f"  [{f['type']}] severity={f.get('severity','?').upper()} "
                f"pc={f.get('pc','?')} "
                f"taint={f.get('taint_source','pattern')} — "
                f"{f.get('description','')[:120]}"
            )
        lines += [
            "```",
            "",
            "_End of Calyx SKANF-Lite analysis context._",
        ]
        return lines
