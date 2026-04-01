"""
analysis/bytecode_pipeline.py

Full SKANF closed-source contract analysis pipeline (LLM-free).

Pipeline stages:
  Stage 3a: CFGDeobfuscator   — resolve indirect jumps; complete CFG (Gap 1)
  Stage 3b: CFGProfiler       — obfuscation score from resolved CFG
  Stage 4:  TxnAnalyzer       — historical transaction anomaly flags (optional)
  Stage 5a: TaintAnalyzer     — static taint analysis for AM1/AM2 (Gap 2)
  Stage 5b: AMPatternDetector — heuristic AM3/AM4/AM5 pattern detection
  Stage 5c: BytecodeGNNAnalyzer — GNN inference on deobfuscated CFG graphs
  Stage 5d: SimilarityScanner — opcode n-gram Jaccard vs exploit corpus (LookAhead signal)
  Stage 5e: CFGProfiler.detect_complex_defi_patterns — flash loan / multi-hop complexity
  Stage 6:  RiskScorer        — 3-signal weighted risk score
  Stage 7:  ExploitValidator  — fork-EVM confirmation via Anvil (Gap 3, optional)

All stages are LLM-free.  Stage 7 additionally requires ETHEREUM_RPC_URL and
Anvil installed; it is silently skipped when unavailable.

Usage:
    from analysis.bytecode_pipeline import BytecodePipeline

    pipeline = BytecodePipeline()

    # From raw bytecode hex (no API keys required)
    result = pipeline.analyze_bytecode(bytecode_hex="0x608060...")

    # From a contract address (requires ETHERSCAN_API_KEY for bytecode fetch)
    result = pipeline.analyze_address("0x00000000003b3cc22af3ae1eac0440bcee416b40")

    # With fork-EVM exploit validation (requires ETHEREUM_RPC_URL + Anvil)
    result = pipeline.analyze_bytecode(bytecode_hex, validate=True,
                                       address="0x...")

    print(result["risk_level"])          # CRITICAL | HIGH | MEDIUM | LOW
    print(result["am_types_found"])      # ["AM1", "AM2", "AM3"]
    print(result["confirmed_exploits"])  # findings confirmed by Anvil
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from detectors.bytecode_analyzer.cfg_deobfuscator import CFGDeobfuscator
from detectors.bytecode_analyzer.cfg_profiler import CFGProfiler, AMPatternDetector
from detectors.bytecode_analyzer.taint_analyzer import TaintAnalyzer
from detectors.gnn_analyzer.bytecode_analyzer import BytecodeGNNAnalyzer
from detectors.risk_scorer.scorer import RiskScorer

log = logging.getLogger(__name__)


class BytecodePipeline:
    """
    Orchestrates full SKANF-style bytecode analysis without any LLM calls.

    Instantiate once; call analyze_bytecode() or analyze_address() per contract.
    """

    def __init__(self) -> None:
        self._deobfuscator = CFGDeobfuscator()
        self._profiler     = CFGProfiler()
        self._taint        = TaintAnalyzer()
        self._detector     = AMPatternDetector()   # AM3/AM4/AM5 only
        self._gnn          = BytecodeGNNAnalyzer()
        self._scorer       = RiskScorer()
        self._txn          = None   # lazy-loaded on first address analysis
        self._validator    = None   # lazy-loaded when validate=True
        self._similarity   = None   # lazy-loaded (SimilarityScanner)

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_bytecode(
        self,
        bytecode_hex: str,
        address:      Optional[str] = None,
        network:      str           = "ethereum",
        validate:     bool          = False,
        audit:        bool          = False,
    ) -> Dict[str, Any]:
        """
        Run the full pipeline on raw bytecode.

        Args:
            bytecode_hex: Raw hex bytecode (with or without 0x prefix).
            address:      Contract address — enables TxnAnalyzer + ExploitValidator.
            network:      Chain name for TxnAnalyzer ("ethereum", "polygon", etc.).
            validate:     If True, attempt fork-EVM exploit confirmation (Gap 3).
                          Requires ETHEREUM_RPC_URL env var and Anvil in PATH.
            audit:        If True, run AuditAgent LLM analysis as a final stage.
                          Requires at least one of: ANTHROPIC_API_KEY, GEMINI_API_KEY,
                          GROQ_API_KEY, OPENAI_API_KEY.  Adds "audit_report" key.

        Returns:
            Full result dict including risk_score, risk_level, all findings,
            confirmed_exploits, per-stage sub-results, and optionally audit_report.
        """
        # Stage 3a: CFG deobfuscation (Gap 1) — resolve indirect jumps
        cfg_deob = self._deobfuscator.resolve_cfg(bytecode_hex)
        log.info(
            f"CFG deobfuscation: {len(cfg_deob['blocks'])} blocks, "
            f"{len(cfg_deob['edges'])} edges, "
            f"resolved={cfg_deob['resolved']}, approximated={cfg_deob['approximated']}"
        )

        # Stage 3b: CFG profiling (obfuscation score)
        cfg_profile = self._profiler.profile(bytecode_hex)
        log.info(
            f"CFG profile: {cfg_profile['instruction_count']} instructions, "
            f"obfuscation={cfg_profile['obfuscation_score']:.3f} ({cfg_profile['assessment']})"
        )

        # Stage 4: Transaction analysis (optional, requires Etherscan key + address)
        txn_score  = 0.0
        txn_result: Dict[str, Any] = {}
        if address:
            txn_result = self._run_txn_analysis(address, network)
            txn_score  = txn_result.get("anomaly_score", 0.0)

        # Stage 5a: Static taint analysis for AM1/AM2 (Gap 2)
        taint_result = self._taint.analyze(bytecode_hex)
        taint_findings = taint_result["findings"]
        log.info(
            f"Taint analysis: {len(taint_findings)} findings "
            f"— types: {taint_result['am_types_found']}, "
            f"caller_guarded={taint_result['caller_guarded']}"
        )

        # Stage 5b: Pattern detection for AM3/AM4/AM5
        am_result    = self._detector.detect(bytecode_hex)
        am_findings  = am_result["findings"]
        log.info(
            f"AM pattern detector: {len(am_findings)} findings "
            f"— types: {am_result['am_types_found']}"
        )

        # Merge all findings; taint findings (AM1/AM2) take precedence
        all_findings = taint_findings + am_findings
        all_types    = sorted({f["type"] for f in all_findings})

        # Stage 5c: Bytecode GNN scoring
        gnn_result = self._gnn.analyze(bytecode_hex)
        gnn_score  = gnn_result["exploit_probability"]
        log.info(
            f"GNN: prob={gnn_score:.3f} ({gnn_result['risk_level']}) "
            f"— {gnn_result['block_count']} blocks, {gnn_result['edge_count']} edges"
        )

        # Stage 5d: Opcode n-gram similarity vs exploit corpus (LookAhead signal)
        similarity_result = self._run_similarity_scan(bytecode_hex)
        if similarity_result:
            log.info(
                f"Similarity: max_jaccard={similarity_result.get('max_similarity', 0):.3f}, "
                f"matches={similarity_result.get('match_count', 0)}"
            )

        # Stage 5e: Complex DeFi pattern detection (flash loan / multi-hop swap)
        complexity_result = self._profiler.detect_complex_defi_patterns(bytecode_hex)
        log.info(
            f"Complexity: score={complexity_result.get('complexity_score', 0):.3f}, "
            f"review_recommended={complexity_result.get('review_recommended', False)}"
        )

        # Stage 6: Risk scoring
        score = self._scorer.score(
            gnn_score=gnn_score,
            llm_findings=all_findings,
            txn_anomaly_score=txn_score,
        )

        # Stage 7: Fork-EVM exploit validation (Gap 3, optional)
        confirmed_exploits: List[Dict[str, Any]] = []
        if validate and address:
            validated = self._run_exploit_validation(address, all_findings)
            confirmed_exploits = [f for f in validated if f.get("confirmed")]
            if confirmed_exploits:
                log.info(
                    f"Exploit validation: {len(confirmed_exploits)} confirmed "
                    f"({sum(f['eth_drained_wei'] for f in confirmed_exploits)} wei drained)"
                )
                # Re-score with confirmed flags set
                score = self._scorer.score(
                    gnn_score=gnn_score,
                    llm_findings=validated,
                    txn_anomaly_score=txn_score,
                )

        result = {
            "address":           address,
            "network":           network,
            "risk_score":        score["risk_score"],
            "risk_level":        score["risk_level"],
            "breakdown":         score["breakdown"],
            # All findings (AM1/AM2 from taint, AM3/AM4/AM5 from pattern detector)
            "am_findings":       all_findings,
            "am_types_found":    all_types,
            "confirmed_exploits": confirmed_exploits,
            # Per-stage sub-results
            "cfg_deob":          {
                "resolved":     cfg_deob["resolved"],
                "approximated": cfg_deob["approximated"],
                "block_count":  len(cfg_deob["blocks"]),
                "edge_count":   len(cfg_deob["edges"]),
            },
            "cfg_profile":       cfg_profile,
            "taint_result":      taint_result,
            "gnn_result":        gnn_result,
            "similarity":        similarity_result,   # Stage 5d — LookAhead signal
            "complexity":        complexity_result,   # Stage 5e — LookAhead signal
            "txn_result":        txn_result,
            "error":             None,
        }

        # Stage 8: LLM Audit (optional — requires an API key)
        if audit:
            result["audit_report"], result["audit_error"] = (
                self._run_audit(result)
            )

        return result

    def analyze_address(
        self,
        address:  str,
        network:  str  = "ethereum",
        validate: bool = False,
        audit:    bool = False,
    ) -> Dict[str, Any]:
        """
        Fetch bytecode from Etherscan, then run analyze_bytecode().

        Requires ETHERSCAN_API_KEY environment variable.
        Pass validate=True to also run fork-EVM exploit confirmation (Gap 3).
        Pass audit=True to run LLM audit agent as a final stage (Stage 8).

        Also runs TxnGuidedTaintAnalyzer (P1) and ContextBuilder (P2)
        when address is available.
        """
        try:
            from integrations.etherscan_client import EtherscanClient
            api_key = os.environ.get("ETHERSCAN_API_KEY", "")
            client  = EtherscanClient(api_key=api_key, network=network)
            bcode   = client.get_bytecode(address)
            bytecode_hex = bcode.get("bytecode", "0x") if isinstance(bcode, dict) else bcode
        except Exception as e:
            return {
                "address":    address,
                "network":    network,
                "risk_score": 0.0,
                "risk_level": "UNKNOWN",
                "error":      f"bytecode fetch failed: {e}",
            }

        if not bytecode_hex or bytecode_hex in ("0x", ""):
            return {
                "address":    address,
                "network":    network,
                "risk_score": 0.0,
                "risk_level": "UNKNOWN",
                "error":      "no bytecode returned (EOA or unverified contract?)",
            }

        result = self.analyze_bytecode(
            bytecode_hex, address=address, network=network, validate=validate,
            audit=audit,
        )

        # P1: Txn-guided taint — correlate findings with real historical txns
        taint_findings = result.get("am_findings", [])
        result["txn_guided_taint"] = self._run_txn_guided_taint(
            address, network, taint_findings
        )

        # P2: Build structured LLM context
        result["context"] = self._build_context(result)

        return result

    # ── Private ───────────────────────────────────────────────────────────────

    def _run_similarity_scan(self, bytecode_hex: str) -> Dict[str, Any]:
        """Lazy-load SimilarityScanner and run opcode n-gram scan. Returns {} on failure."""
        if self._similarity is None:
            try:
                from detectors.bytecode_analyzer.similarity_scanner import SimilarityScanner
                self._similarity = SimilarityScanner()
            except Exception as e:
                log.debug(f"SimilarityScanner init failed: {e}")
                return {}
        try:
            return self._similarity.scan(bytecode_hex)
        except Exception as e:
            log.warning(f"SimilarityScanner.scan failed: {e}")
            return {}

    def _run_txn_analysis(self, address: str, network: str) -> Dict[str, Any]:
        """Lazy-load TxnAnalyzer and run it. Returns empty dict on failure."""
        if self._txn is None:
            try:
                from integrations.etherscan_client import EtherscanClient
                from detectors.bytecode_analyzer.txn_analyzer import TxnAnalyzer
                api_key    = os.environ.get("ETHERSCAN_API_KEY", "")
                client     = EtherscanClient(api_key=api_key)
                self._txn  = TxnAnalyzer(etherscan_client=client)
            except Exception as e:
                log.warning(f"TxnAnalyzer init failed: {e}")
                return {}
        try:
            return self._txn.analyze(address)
        except Exception as e:
            log.warning(f"TxnAnalyzer.analyze({address}) failed: {e}")
            return {}

    def _run_txn_guided_taint(
        self,
        address:        str,
        network:        str,
        taint_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run TxnGuidedTaintAnalyzer (P1). Silently skips on failure."""
        try:
            from integrations.etherscan_client import EtherscanClient
            from analysis.txn_guided_taint import TxnGuidedTaintAnalyzer
            api_key = os.environ.get("ETHERSCAN_API_KEY", "")
            client  = EtherscanClient(api_key=api_key, network=network)
            analyzer = TxnGuidedTaintAnalyzer(client)
            return analyzer.analyze(address, taint_findings)
        except Exception as e:
            log.warning(f"TxnGuidedTaint failed: {e}")
            return {}

    def _build_context(self, result: Dict[str, Any]) -> str:
        """Build markdown context string (P2). Returns empty string on failure."""
        try:
            from analysis.context_builder import ContextBuilder
            return ContextBuilder(result).build()
        except Exception as e:
            log.warning(f"ContextBuilder failed: {e}")
            return ""

    def _run_audit(
        self, result: Dict[str, Any]
    ) -> tuple:
        """
        Run AuditAgent LLM analysis (Stage 8). Returns (report_dict, error_str).
        Silently degrades — pipeline result is always returned even if audit fails.
        """
        try:
            from analysis.audit_agent import AuditAgent
            agent  = AuditAgent()
            report = agent.audit(result)
            err    = report.get("error")
            return report, err
        except Exception as e:
            log.warning(f"AuditAgent failed: {e}")
            return {}, str(e)

    def _run_exploit_validation(
        self,
        address:  str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Lazy-load ExploitValidator and run it. Returns findings unchanged on failure."""
        if self._validator is None:
            try:
                from detectors.bytecode_analyzer.exploit_validator import ExploitValidator
                self._validator = ExploitValidator()
            except Exception as e:
                log.warning(f"ExploitValidator init failed: {e}")
                return findings
        try:
            return self._validator.validate(address, findings)
        except Exception as e:
            log.warning(f"ExploitValidator.validate failed: {e}")
            return findings
