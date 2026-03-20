"""
analysis/bytecode_pipeline.py

Full SKANF closed-source contract analysis pipeline (LLM-free).

Pipeline stages:
  Stage 3a: CFGDeobfuscator   — resolve indirect jumps; complete CFG (Gap 1)
  Stage 3b: CFGProfiler       — obfuscation score from resolved CFG
  Stage 4:  TxnAnalyzer       — historical transaction anomaly flags (optional)
  Stage 5a: TaintAnalyzer     — static taint analysis for AM1/AM2 (Gap 2)
  Stage 5b: AMPatternDetector — heuristic AM3/AM4/AM5/AM7/AM8 pattern detection
  Stage 5c: BytecodeGNNAnalyzer — GNN inference on deobfuscated CFG graphs
  Stage 6:  RiskScorer        — 3-signal weighted risk score
  Stage 7:  ExploitValidator  — fork-EVM confirmation via Anvil (Gap 3, optional)

Usage:
    from analysis.bytecode_pipeline import BytecodePipeline
    pipeline = BytecodePipeline()
    result = pipeline.analyze_bytecode(bytecode_hex="0x608060...")
    result = pipeline.analyze_address("0x00000000003b3cc22af3ae1eac0440bcee416b40")
    print(result["risk_level"])       # CRITICAL | HIGH | MEDIUM | LOW
    print(result["am_types_found"])   # ["AM1", "AM2", "AM3"]
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
        self._detector     = AMPatternDetector()
        self._gnn          = BytecodeGNNAnalyzer()
        self._scorer       = RiskScorer()
        self._txn          = None   # lazy-loaded on first address analysis
        self._validator    = None   # lazy-loaded when validate=True

    def analyze_bytecode(self, bytecode_hex: str, address: Optional[str] = None,
                         network: str = "ethereum", validate: bool = False,
                         audit: bool = False) -> Dict[str, Any]:
        """Run the full pipeline on raw bytecode."""
        # Stage 3a: CFG deobfuscation (Gap 1)
        cfg_deob = self._deobfuscator.resolve_cfg(bytecode_hex)
        log.info(f"CFG deobfuscation: {len(cfg_deob['blocks'])} blocks, "
                 f"{len(cfg_deob['edges'])} edges, resolved={cfg_deob['resolved']}, "
                 f"approximated={cfg_deob['approximated']}")

        # Stage 3b: CFG profiling
        cfg_profile = self._profiler.profile(bytecode_hex)
        log.info(f"CFG profile: {cfg_profile['instruction_count']} instructions, "
                 f"obfuscation={cfg_profile['obfuscation_score']:.3f} ({cfg_profile['assessment']})")

        # Stage 4: Transaction analysis (optional)
        txn_score = 0.0
        txn_result: Dict[str, Any] = {}
        if address:
            txn_result = self._run_txn_analysis(address, network)
            txn_score  = txn_result.get("anomaly_score", 0.0)

        # Stage 5a: Static taint analysis for AM1/AM2 (Gap 2)
        taint_result   = self._taint.analyze(bytecode_hex)
        taint_findings = taint_result["findings"]
        log.info(f"Taint analysis: {len(taint_findings)} findings "
                 f"— types: {taint_result['am_types_found']}, "
                 f"caller_guarded={taint_result['caller_guarded']}")

        # Stage 5b: Pattern detection for AM3/AM4/AM5/AM7/AM8
        am_result   = self._detector.detect(bytecode_hex)
        am_findings = am_result["findings"]
        log.info(f"AM pattern detector: {len(am_findings)} findings "
                 f"— types: {am_result['am_types_found']}")

        all_findings = taint_findings + am_findings
        all_types    = sorted({f["type"] for f in all_findings})

        # Stage 5c: Bytecode GNN scoring
        gnn_result = self._gnn.analyze(bytecode_hex)
        gnn_score  = gnn_result["exploit_probability"]
        log.info(f"GNN: prob={gnn_score:.3f} ({gnn_result['risk_level']}) "
                 f"— {gnn_result['block_count']} blocks, {gnn_result['edge_count']} edges")

        # Stage 6: Risk scoring
        score = self._scorer.score(
            gnn_score=gnn_score, llm_findings=all_findings, txn_anomaly_score=txn_score,
        )

        # Stage 7: Fork-EVM exploit validation (Gap 3, optional)
        confirmed_exploits: List[Dict[str, Any]] = []
        if validate and address:
            validated = self._run_exploit_validation(address, all_findings)
            confirmed_exploits = [f for f in validated if f.get("confirmed")]
            if confirmed_exploits:
                log.info(f"Exploit validation: {len(confirmed_exploits)} confirmed "
                         f"({sum(f['eth_drained_wei'] for f in confirmed_exploits)} wei drained)")
                score = self._scorer.score(
                    gnn_score=gnn_score, llm_findings=validated, txn_anomaly_score=txn_score,
                )

        result = {
            "address": address, "network": network,
            "risk_score": score["risk_score"], "risk_level": score["risk_level"],
            "breakdown": score["breakdown"],
            "am_findings": all_findings, "am_types_found": all_types,
            "confirmed_exploits": confirmed_exploits,
            "cfg_deob": {
                "resolved":     cfg_deob["resolved"],
                "approximated": cfg_deob["approximated"],
                "block_count":  len(cfg_deob["blocks"]),
                "edge_count":   len(cfg_deob["edges"]),
            },
            "cfg_profile":  cfg_profile,
            "taint_result": taint_result,
            "gnn_result":   gnn_result,
            "txn_result":   txn_result,
            "error":        None,
        }

        # Stage 8: LLM Audit (optional)
        if audit:
            result["audit_report"], result["audit_error"] = self._run_audit(result)

        return result

    def analyze_address(self, address: str, network: str = "ethereum",
                        validate: bool = False, audit: bool = False) -> Dict[str, Any]:
        """Fetch bytecode from Etherscan, then run analyze_bytecode()."""
        try:
            from integrations.etherscan_client import EtherscanClient
            api_key = os.environ.get("ETHERSCAN_API_KEY", "")
            client  = EtherscanClient(api_key=api_key, network=network)
            bcode   = client.get_bytecode(address)
            bytecode_hex = bcode.get("bytecode", "0x") if isinstance(bcode, dict) else bcode
        except Exception as e:
            return {"address": address, "network": network,
                    "risk_score": 0.0, "risk_level": "UNKNOWN",
                    "error": f"bytecode fetch failed: {e}"}

        if not bytecode_hex or bytecode_hex in ("0x", ""):
            return {"address": address, "network": network,
                    "risk_score": 0.0, "risk_level": "UNKNOWN",
                    "error": "no bytecode returned (EOA or unverified contract?)"}

        result = self.analyze_bytecode(
            bytecode_hex, address=address, network=network,
            validate=validate, audit=audit,
        )
        result["txn_guided_taint"] = self._run_txn_guided_taint(
            address, network, result.get("am_findings", [])
        )
        result["context"] = self._build_context(result)
        return result

    def _run_txn_analysis(self, address: str, network: str) -> Dict[str, Any]:
        if self._txn is None:
            try:
                from integrations.etherscan_client import EtherscanClient
                from detectors.bytecode_analyzer.txn_analyzer import TxnAnalyzer
                api_key   = os.environ.get("ETHERSCAN_API_KEY", "")
                client    = EtherscanClient(api_key=api_key)
                self._txn = TxnAnalyzer(etherscan_client=client)
            except Exception as e:
                log.warning(f"TxnAnalyzer init failed: {e}")
                return {}
        try:
            return self._txn.analyze(address)
        except Exception as e:
            log.warning(f"TxnAnalyzer.analyze({address}) failed: {e}")
            return {}

    def _run_txn_guided_taint(self, address: str, network: str,
                               taint_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            from integrations.etherscan_client import EtherscanClient
            from analysis.txn_guided_taint import TxnGuidedTaintAnalyzer
            api_key  = os.environ.get("ETHERSCAN_API_KEY", "")
            client   = EtherscanClient(api_key=api_key, network=network)
            analyzer = TxnGuidedTaintAnalyzer(client)
            return analyzer.analyze(address, taint_findings)
        except Exception as e:
            log.warning(f"TxnGuidedTaint failed: {e}")
            return {}

    def _build_context(self, result: Dict[str, Any]) -> str:
        try:
            from analysis.context_builder import ContextBuilder
            return ContextBuilder(result).build()
        except Exception as e:
            log.warning(f"ContextBuilder failed: {e}")
            return ""

    def _run_audit(self, result: Dict[str, Any]) -> tuple:
        try:
            from analysis.audit_agent import AuditAgent
            agent  = AuditAgent()
            report = agent.audit(result)
            return report, report.get("error")
        except Exception as e:
            log.warning(f"AuditAgent failed: {e}")
            return {}, str(e)

    def _run_exploit_validation(self, address: str,
                                 findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
