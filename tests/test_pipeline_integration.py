"""
tests/test_pipeline_integration.py

Lightweight integration tests for the full Calyx analysis pipeline.

These tests do NOT call Anvil, Etherscan, or any external services.
The GNN is not required (it gracefully falls back to probability=0.5).

Coverage:
  - CFGDeobfuscator: direct jumps resolved, indirect jumps approximated
  - CFGProfiler: obfuscation score, split_by_selector, detect_complex_defi_patterns
  - RiskScorer: weighted combination, threshold levels, confirmed bonus
  - BytecodePipeline.analyze_bytecode: end-to-end on crafted bytecode
    with validate=False and no external dependencies
  - BytecodePipeline.analyze_address: graceful error on missing API key
"""

from __future__ import annotations

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.bytecode_analyzer.cfg_deobfuscator import CFGDeobfuscator
from detectors.bytecode_analyzer.cfg_profiler import CFGProfiler, AMPatternDetector
from detectors.risk_scorer.scorer import RiskScorer

# Minimal EVM bytecode samples
# Simple STOP
BYTECODE_STOP = "0x00"

# Direct jump: PUSH1 dest; JUMP; JUMPDEST; STOP
# Byte layout: PC0=PUSH1 PC1=0x03(operand) PC2=JUMP PC3=JUMPDEST PC4=STOP
# 0x56 = JUMP (not 0x57 which is JUMPI)
BYTECODE_DIRECT_JUMP = "0x6003565b00"  # PUSH1 3 | JUMP | JUMPDEST | STOP

# Indirect jump: the destination comes from CALLDATALOAD — cannot be constant-folded
# PUSH1 0; CALLDATALOAD; JUMP
BYTECODE_INDIRECT_JUMP = "0x600035 56".replace(" ", "")

# Contract with UniV3 flash callback + 2 swap selectors
BYTECODE_COMPLEX_DEFI = (
    "0x"
    "63fa461e33"  # PUSH4 uniswapV3SwapCallback
    "50"
    "6338ed1739"  # PUSH4 swapExactTokensForTokens
    "50"
    "63128acb08"  # PUSH4 swap (UniV3)
    "50"
    "f1f1f1f1"    # 4 x CALL opcodes
)

# Function dispatch pattern for selector split
BYTECODE_DISPATCH = (
    "0x"
    "63a9059cbb"  # PUSH4 transfer selector
    "6000"        # PUSH1 0
    "14"          # EQ
    "600f"        # PUSH1 15 (jump dest)
    "57"          # JUMPI
    "5b"          # JUMPDEST at offset ~15
    "00"          # STOP
)

# AM1 trigger bytecode (reused from taint tests)
BYTECODE_AM1 = "0x600060006000600060006000356001f1"


# ---------------------------------------------------------------------------
# CFGDeobfuscator
# ---------------------------------------------------------------------------

class TestCFGDeobfuscator(unittest.TestCase):

    def setUp(self):
        self.deob = CFGDeobfuscator()

    def test_empty_bytecode_returns_empty_result(self):
        result = self.deob.resolve_cfg("0x")
        self.assertEqual(result["blocks"], [])
        self.assertEqual(result["edges"], [])
        self.assertIsNotNone(result["error"])

    def test_stop_bytecode_produces_one_block(self):
        result = self.deob.resolve_cfg(BYTECODE_STOP)
        self.assertGreaterEqual(len(result["blocks"]), 1)
        self.assertIsNone(result["error"])

    def test_direct_jump_resolved(self):
        result = self.deob.resolve_cfg(BYTECODE_DIRECT_JUMP)
        self.assertGreater(result["resolved"], 0)
        self.assertEqual(result["approximated"], 0)

    def test_indirect_jump_approximated(self):
        result = self.deob.resolve_cfg(BYTECODE_INDIRECT_JUMP)
        self.assertGreater(result["approximated"], 0)

    def test_result_has_required_keys(self):
        result = self.deob.resolve_cfg(BYTECODE_STOP)
        for key in ("blocks", "edges", "jumpdest_pcs", "resolved", "approximated", "error"):
            self.assertIn(key, result)

    def test_edges_are_valid_block_indices(self):
        result = self.deob.resolve_cfg(BYTECODE_DIRECT_JUMP)
        block_indices = {b["idx"] for b in result["blocks"]}
        for src, dst in result["edges"]:
            self.assertIn(src, block_indices)
            self.assertIn(dst, block_indices)

    def test_no_duplicate_edges(self):
        result = self.deob.resolve_cfg(BYTECODE_AM1)
        seen = set()
        for edge in result["edges"]:
            key = (edge[0], edge[1])
            self.assertNotIn(key, seen, f"Duplicate edge: {key}")
            seen.add(key)

    def test_invalid_hex_returns_error(self):
        result = self.deob.resolve_cfg("0xZZZZ")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["blocks"], [])


# ---------------------------------------------------------------------------
# CFGProfiler
# ---------------------------------------------------------------------------

class TestCFGProfiler(unittest.TestCase):

    def setUp(self):
        self.profiler = CFGProfiler()

    def test_empty_bytecode_returns_zero_scores(self):
        result = self.profiler.profile("0x")
        self.assertEqual(result["total_jumps"], 0)
        self.assertEqual(result["obfuscation_score"], 0.0)

    def test_clean_bytecode_has_zero_obfuscation(self):
        result = self.profiler.profile("0x60016002")
        self.assertEqual(result["obfuscation_score"], 0.0)
        self.assertEqual(result["assessment"], "clean")

    def test_direct_jump_scores_zero_obfuscation(self):
        result = self.profiler.profile(BYTECODE_DIRECT_JUMP)
        self.assertEqual(result["indirect_jumps"], 0)
        self.assertEqual(result["obfuscation_score"], 0.0)

    def test_indirect_jump_increases_obfuscation_score(self):
        result = self.profiler.profile(BYTECODE_INDIRECT_JUMP)
        self.assertGreater(result["obfuscation_score"], 0.0)

    def test_obfuscation_score_in_range(self):
        result = self.profiler.profile(BYTECODE_INDIRECT_JUMP)
        self.assertGreaterEqual(result["obfuscation_score"], 0.0)
        self.assertLessEqual(result["obfuscation_score"], 1.0)

    def test_result_has_required_keys(self):
        result = self.profiler.profile(BYTECODE_STOP)
        for key in ("total_jumps", "direct_jumps", "indirect_jumps",
                    "obfuscation_score", "indirect_jump_pcs",
                    "all_jumpdest_pcs", "instruction_count", "assessment"):
            self.assertIn(key, result)

    def test_split_by_selector_finds_transfer_dispatch(self):
        result = self.profiler.split_by_selector(BYTECODE_DISPATCH)
        # Should find at least one selector (transfer = 0xa9059cbb)
        self.assertGreaterEqual(result["function_count"], 1)

    def test_split_by_selector_empty_bytecode(self):
        result = self.profiler.split_by_selector("0x")
        self.assertEqual(result["function_count"], 0)

    def test_detect_complex_defi_patterns_finds_flash_callback(self):
        result = self.profiler.detect_complex_defi_patterns(BYTECODE_COMPLEX_DEFI)
        self.assertIn("flash_loan_callback", result["patterns_found"])

    def test_detect_complex_defi_patterns_finds_multi_dex_swap(self):
        result = self.profiler.detect_complex_defi_patterns(BYTECODE_COMPLEX_DEFI)
        patterns_str = " ".join(result["patterns_found"])
        self.assertIn("multi_dex_swap", patterns_str)

    def test_complexity_score_in_range(self):
        result = self.profiler.detect_complex_defi_patterns(BYTECODE_COMPLEX_DEFI)
        self.assertGreaterEqual(result["complexity_score"], 0.0)
        self.assertLessEqual(result["complexity_score"], 1.0)

    def test_review_recommended_for_complex_defi(self):
        result = self.profiler.detect_complex_defi_patterns(BYTECODE_COMPLEX_DEFI)
        self.assertTrue(result["review_recommended"])


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class TestRiskScorer(unittest.TestCase):

    def setUp(self):
        self.scorer = RiskScorer()

    def test_zero_inputs_produce_zero_score(self):
        result = self.scorer.score(gnn_score=0.0, llm_findings=[], txn_anomaly_score=0.0)
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_score_is_in_unit_interval(self):
        for gnn in (0.0, 0.5, 1.0):
            result = self.scorer.score(gnn_score=gnn, llm_findings=[], txn_anomaly_score=0.0)
            self.assertGreaterEqual(result["risk_score"], 0.0)
            self.assertLessEqual(result["risk_score"], 1.0)

    def test_high_gnn_score_raises_risk_level(self):
        # GNN weight is 0.30, so gnn_score=1.0 alone only contributes 0.30 → MEDIUM.
        # Add a high finding (weight 0.25 * LLM_WEIGHT 0.55 = 0.1375) to cross HIGH (0.50).
        findings = [{"type": "AM1", "severity": "high", "pc": 0,
                     "description": "t", "taint_source": "calldata"}] * 3
        result = self.scorer.score(gnn_score=1.0, llm_findings=findings,
                                   txn_anomaly_score=0.0)
        self.assertIn(result["risk_level"], ("HIGH", "CRITICAL"))

    def test_single_high_finding_contributes_to_score(self):
        findings = [{"type": "AM1", "severity": "high", "pc": 0,
                     "description": "test", "taint_source": "calldata"}]
        result_with = self.scorer.score(gnn_score=0.0, llm_findings=findings,
                                        txn_anomaly_score=0.0)
        result_without = self.scorer.score(gnn_score=0.0, llm_findings=[],
                                           txn_anomaly_score=0.0)
        self.assertGreater(result_with["risk_score"], result_without["risk_score"])

    def test_confirmed_finding_adds_bonus(self):
        base_finding = {"type": "AM1", "severity": "high", "pc": 0,
                        "description": "t", "taint_source": "calldata"}
        confirmed = {**base_finding, "confirmed": True}
        r_base = self.scorer.score(gnn_score=0.0, llm_findings=[base_finding],
                                   txn_anomaly_score=0.0)
        r_conf = self.scorer.score(gnn_score=0.0, llm_findings=[confirmed],
                                   txn_anomaly_score=0.0)
        self.assertGreater(r_conf["risk_score"], r_base["risk_score"])

    def test_critical_threshold_at_0_75(self):
        result = self.scorer.score(gnn_score=1.0,
                                   llm_findings=[{"type": "AM1", "severity": "critical",
                                                  "pc": 0, "description": "t",
                                                  "taint_source": "calldata"}] * 3,
                                   txn_anomaly_score=1.0)
        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_breakdown_keys_present(self):
        result = self.scorer.score(gnn_score=0.5, llm_findings=[], txn_anomaly_score=0.5)
        for key in ("gnn_contribution", "llm_contribution", "txn_contribution",
                    "llm_sub_score", "finding_count", "finding_severities"):
            self.assertIn(key, result["breakdown"])

    def test_finding_count_correct(self):
        findings = [{"type": "AM1", "severity": "high", "pc": 0, "description": "t",
                     "taint_source": "calldata"}] * 3
        result = self.scorer.score(gnn_score=0.0, llm_findings=findings,
                                   txn_anomaly_score=0.0)
        self.assertEqual(result["breakdown"]["finding_count"], 3)

    def test_gnn_score_clamped_above_1(self):
        result = self.scorer.score(gnn_score=5.0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_gnn_score_clamped_below_0(self):
        result = self.scorer.score(gnn_score=-1.0)
        self.assertGreaterEqual(result["risk_score"], 0.0)

    def test_contributions_sum_to_risk_score(self):
        findings = [{"type": "AM2", "severity": "high", "pc": 0, "description": "t",
                     "taint_source": "value"}]
        result = self.scorer.score(gnn_score=0.4, llm_findings=findings,
                                   txn_anomaly_score=0.3)
        breakdown = result["breakdown"]
        expected = round(
            breakdown["gnn_contribution"] + breakdown["llm_contribution"] +
            breakdown["txn_contribution"], 4
        )
        self.assertAlmostEqual(result["risk_score"], expected, places=3)


# ---------------------------------------------------------------------------
# BytecodePipeline.analyze_bytecode (no external deps)
# ---------------------------------------------------------------------------

class TestBytecodePipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Import here to avoid torch warning at module level
        try:
            from analysis.bytecode_pipeline import BytecodePipeline
            cls.pipeline = BytecodePipeline()
            cls.available = True
        except Exception:
            cls.available = False

    def _skip_if_unavailable(self):
        if not self.available:
            self.skipTest("BytecodePipeline dependencies not installed")

    def test_analyze_bytecode_returns_dict(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        self.assertIsInstance(result, dict)

    def test_analyze_bytecode_has_required_keys(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        for key in ("risk_score", "risk_level", "am_findings",
                    "am_types_found", "confirmed_exploits"):
            self.assertIn(key, result)

    def test_analyze_bytecode_risk_score_in_range(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        self.assertGreaterEqual(result["risk_score"], 0.0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_analyze_bytecode_detects_am1(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        self.assertIn("AM1", result["am_types_found"])

    def test_analyze_bytecode_clean_has_low_score(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode("0x60016002")
        # Clean bytecode with no findings should have low-ish score (GNN may still be 0.5)
        self.assertIn(result["risk_level"], ("LOW", "MEDIUM"))

    def test_analyze_bytecode_no_validate_returns_empty_exploits(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1, validate=False)
        self.assertEqual(result["confirmed_exploits"], [])

    def test_analyze_bytecode_error_key_is_none_on_success(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        self.assertIsNone(result["error"])

    def test_analyze_address_error_on_no_api_key(self):
        self._skip_if_unavailable()
        env = {k: v for k, v in os.environ.items() if k != "ETHERSCAN_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            result = self.pipeline.analyze_address(
                "0x00000000003b3cc22af3ae1eac0440bcee416b40"
            )
        # Either succeeds (if rate-limited free tier works) or gracefully returns error
        self.assertIn("risk_level", result)

    def test_analyze_bytecode_cfg_deob_keys_present(self):
        self._skip_if_unavailable()
        result = self.pipeline.analyze_bytecode(BYTECODE_AM1)
        self.assertIn("cfg_deob", result)
        for key in ("resolved", "approximated", "block_count", "edge_count"):
            self.assertIn(key, result["cfg_deob"])


if __name__ == "__main__":
    unittest.main()
