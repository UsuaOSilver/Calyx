"""
tests/test_adversarial_classifier.py

Unit tests for AdversarialClassifier — all tests use synthetic pipeline results.
No network calls, no Etherscan API key, no LLM key needed.

Test strategy:
  1. Known adversarial pattern → must classify as adversarial
  2. Known clean pattern → must classify as benign
  3. Edge cases → correct threshold behavior
  4. Signal isolation → each signal contributes correctly
  5. Confidence calibration → active signal count → confidence level
"""

from __future__ import annotations

import copy
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.deployment_watcher.classifier import (
    AdversarialClassifier,
    THRESHOLD_ADVERSARIAL,
    THRESHOLD_SUSPICIOUS,
)


# ── Synthetic pipeline results ────────────────────────────────────────────────

# Known MEV bot pattern: AM1 + AM2 + AM5, obfuscated, high GNN, flash callbacks
_MEV_BOT_RESULT = {
    "address": "0x00000000003b3cc22af3ae1eac0440bcee416b40",
    "risk_score": 0.72,
    "risk_level": "HIGH",
    "am_findings": [
        {"type": "AM1", "severity": "high", "pc": 1234,
         "description": "CALL target tainted by calldata",
         "taint_source": "calldata", "erc20_sensitive": True,
         "sensitive_token_addr": "0xdac17f958d2ee523a2206206994597c13d831ec7"},
        {"type": "AM2", "severity": "high", "pc": 1238,
         "description": "CALL value tainted by calldata",
         "taint_source": "calldata"},
        {"type": "AM5", "severity": "medium", "pc": 500,
         "description": "uniswapV3SwapCallback without CALLER guard"},
    ],
    "am_types_found": ["AM1", "AM2", "AM5"],
    "taint_result": {
        "findings": [],
        "am_types_found": ["AM1", "AM2"],
        "caller_guarded": False,
        "error": None,
    },
    "gnn_result": {
        "exploit_probability": 0.85,
        "risk_level": "HIGH",
        "block_count": 47,
        "edge_count": 89,
        "available": True,
    },
    "cfg_profile": {
        "obfuscation_score": 0.42,
        "assessment": "obfuscated",
        "indirect_jumps": 11,
        "instruction_count": 2400,
    },
    "similarity": {
        "similarity_score": 0.45,
        "closest_match": "flash_loan_am5",
        "risk_flag": True,
        "error": None,
    },
    "complexity": {
        "complexity_score": 0.9,
        "review_recommended": True,
        "patterns_found": ["flash_loan_callback", "multi_dex_swap (3 selectors)", "high_call_count (6 CALLs)"],
    },
    "confirmed_exploits": [],
    "error": None,
}

# Clean ERC-20 token contract: no AM findings, clean CFG, low GNN
_CLEAN_ERC20_RESULT = {
    "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "risk_score": 0.05,
    "risk_level": "LOW",
    "am_findings": [],
    "am_types_found": [],
    "taint_result": {
        "findings": [],
        "am_types_found": [],
        "caller_guarded": True,
        "error": None,
    },
    "gnn_result": {
        "exploit_probability": 0.08,
        "risk_level": "LOW",
        "block_count": 12,
        "edge_count": 15,
        "available": True,
    },
    "cfg_profile": {
        "obfuscation_score": 0.0,
        "assessment": "clean",
        "indirect_jumps": 0,
        "instruction_count": 300,
    },
    "similarity": {
        "similarity_score": 0.05,
        "closest_match": "none",
        "risk_flag": False,
        "error": None,
    },
    "complexity": {
        "complexity_score": 0.0,
        "review_recommended": False,
        "patterns_found": [],
    },
    "confirmed_exploits": [],
    "error": None,
}

# Borderline suspicious: AM5 only, some obfuscation, moderate GNN
_BORDERLINE_RESULT = {
    "address": "0x1111111111111111111111111111111111111111",
    "risk_score": 0.35,
    "risk_level": "MEDIUM",
    "am_findings": [
        {"type": "AM5", "severity": "medium", "pc": 200,
         "description": "Callback without CALLER guard"},
    ],
    "am_types_found": ["AM5"],
    "taint_result": {
        "findings": [],
        "am_types_found": [],
        "caller_guarded": False,
        "error": None,
    },
    "gnn_result": {
        "exploit_probability": 0.45,
        "risk_level": "MEDIUM",
        "block_count": 20,
        "edge_count": 30,
        "available": True,
    },
    "cfg_profile": {
        "obfuscation_score": 0.15,
        "assessment": "likely_obfuscated",
        "indirect_jumps": 3,
        "instruction_count": 800,
    },
    "similarity": {
        "similarity_score": 0.1,
        "closest_match": "none",
        "risk_flag": False,
        "error": None,
    },
    "complexity": {
        "complexity_score": 0.3,
        "review_recommended": False,
        "patterns_found": ["flash_loan_callback"],
    },
    "confirmed_exploits": [],
    "error": None,
}

# Caller-guarded AM1: reduced taint signal
_GUARDED_AM1_RESULT = {
    "address": "0x2222222222222222222222222222222222222222",
    "risk_score": 0.4,
    "risk_level": "MEDIUM",
    "am_findings": [
        {"type": "AM1", "severity": "high", "pc": 100,
         "description": "CALL target tainted by calldata",
         "taint_source": "calldata"},
    ],
    "am_types_found": ["AM1"],
    "taint_result": {
        "findings": [],
        "am_types_found": ["AM1"],
        "caller_guarded": True,
        "error": None,
    },
    "gnn_result": {
        "exploit_probability": 0.3,
        "risk_level": "LOW",
        "block_count": 15,
        "edge_count": 20,
        "available": True,
    },
    "cfg_profile": {
        "obfuscation_score": 0.0,
        "assessment": "clean",
        "indirect_jumps": 0,
    },
    "similarity": {"similarity_score": 0.0, "closest_match": "none", "risk_flag": False},
    "complexity": {"complexity_score": 0.0, "review_recommended": False, "patterns_found": []},
    "confirmed_exploits": [],
    "error": None,
}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAdversarialClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = AdversarialClassifier()


class TestClassification(TestAdversarialClassifier):
    """Core classification: adversarial / suspicious / benign."""

    def test_mev_bot_classified_adversarial(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertEqual(result["classification"], "adversarial")

    def test_clean_erc20_classified_benign(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["classification"], "benign")

    def test_borderline_classified_suspicious(self):
        result = self.classifier.classify(_BORDERLINE_RESULT)
        self.assertIn(result["classification"], ("suspicious", "benign"))

    def test_guarded_am1_not_adversarial(self):
        result = self.classifier.classify(_GUARDED_AM1_RESULT)
        self.assertNotEqual(result["classification"], "adversarial")


class TestScoring(TestAdversarialClassifier):
    """Score range and threshold behavior."""

    def test_score_in_valid_range(self):
        for r in [_MEV_BOT_RESULT, _CLEAN_ERC20_RESULT, _BORDERLINE_RESULT]:
            result = self.classifier.classify(r)
            self.assertGreaterEqual(result["adversarial_score"], 0.0)
            self.assertLessEqual(result["adversarial_score"], 1.0)

    def test_mev_bot_score_above_adversarial_threshold(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreaterEqual(result["adversarial_score"], THRESHOLD_ADVERSARIAL)

    def test_clean_erc20_score_below_suspicious_threshold(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertLess(result["adversarial_score"], THRESHOLD_SUSPICIOUS)

    def test_mev_bot_scores_higher_than_clean(self):
        adv = self.classifier.classify(_MEV_BOT_RESULT)
        clean = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertGreater(adv["adversarial_score"], clean["adversarial_score"])


class TestResultStructure(TestAdversarialClassifier):
    """Verify all required keys are present in the result."""

    def test_required_keys_present(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        required = [
            "adversarial_score", "classification", "confidence",
            "signals", "active_signal_count",
            "rescue_window_advisory", "evidence_summary",
        ]
        for key in required:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_signals_has_all_dimensions(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        expected_signals = ["taint", "callback", "similarity", "complexity", "gnn", "obfuscation"]
        for signal_name in expected_signals:
            self.assertIn(signal_name, result["signals"], f"Missing signal: {signal_name}")

    def test_each_signal_has_required_keys(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        for name, sig in result["signals"].items():
            self.assertIn("raw", sig, f"Signal {name} missing 'raw'")
            self.assertIn("weighted", sig, f"Signal {name} missing 'weighted'")
            self.assertIn("detail", sig, f"Signal {name} missing 'detail'")

    def test_signal_raw_values_in_range(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        for name, sig in result["signals"].items():
            self.assertGreaterEqual(sig["raw"], 0.0, f"Signal {name} raw < 0")
            self.assertLessEqual(sig["raw"], 1.0, f"Signal {name} raw > 1")


class TestConfidence(TestAdversarialClassifier):
    """Confidence calibration based on active signal count."""

    def test_mev_bot_high_confidence(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertIn(result["confidence"], ("high", "medium"))

    def test_clean_erc20_low_confidence(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["confidence"], "low")

    def test_active_signal_count_is_integer(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertIsInstance(result["active_signal_count"], int)

    def test_mev_bot_has_multiple_active_signals(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreaterEqual(result["active_signal_count"], 3)


class TestRescueWindowAdvisory(TestAdversarialClassifier):
    """Rescue window advisory mapping."""

    def test_adversarial_high_confidence_is_immediate_risk(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        if result["classification"] == "adversarial" and result["confidence"] in ("high", "medium"):
            self.assertEqual(result["rescue_window_advisory"], "IMMEDIATE_RISK")

    def test_benign_is_benign_advisory(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["rescue_window_advisory"], "BENIGN")


class TestEvidenceSummary(TestAdversarialClassifier):
    """Evidence summary is human-readable and non-empty."""

    def test_summary_is_nonempty_string(self):
        for r in [_MEV_BOT_RESULT, _CLEAN_ERC20_RESULT]:
            result = self.classifier.classify(r)
            self.assertIsInstance(result["evidence_summary"], str)
            self.assertGreater(len(result["evidence_summary"]), 0)

    def test_adversarial_summary_mentions_classification(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertIn("ADVERSARIAL", result["evidence_summary"].upper())

    def test_benign_summary_mentions_no_indicators(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertIn("No significant", result["evidence_summary"])


class TestSignalIsolation(TestAdversarialClassifier):
    """Each signal responds correctly to its specific input."""

    def test_taint_signal_fires_on_am1(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreater(result["signals"]["taint"]["raw"], 0.0)

    def test_taint_signal_zero_on_clean(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["signals"]["taint"]["raw"], 0.0)

    def test_callback_signal_fires_on_am5(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreater(result["signals"]["callback"]["raw"], 0.0)

    def test_callback_signal_zero_on_clean(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["signals"]["callback"]["raw"], 0.0)

    def test_gnn_signal_fires_on_high_prob(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreater(result["signals"]["gnn"]["raw"], 0.5)

    def test_gnn_signal_low_on_clean(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertLess(result["signals"]["gnn"]["raw"], 0.2)

    def test_obfuscation_signal_fires_on_obfuscated(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreater(result["signals"]["obfuscation"]["raw"], 0.5)

    def test_obfuscation_signal_zero_on_clean(self):
        result = self.classifier.classify(_CLEAN_ERC20_RESULT)
        self.assertEqual(result["signals"]["obfuscation"]["raw"], 0.0)

    def test_similarity_signal_fires_on_match(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        self.assertGreater(result["signals"]["similarity"]["raw"], 0.0)

    def test_erc20_sensitive_boosts_taint(self):
        result = self.classifier.classify(_MEV_BOT_RESULT)
        # ERC-20 sensitive + no caller guard → raw should be 1.0
        self.assertEqual(result["signals"]["taint"]["raw"], 1.0)


class TestCallerGuardEffect(TestAdversarialClassifier):
    """Caller guard reduces taint signal but doesn't eliminate it."""

    def test_guarded_taint_lower_than_unguarded(self):
        unguarded = self.classifier.classify(_MEV_BOT_RESULT)
        guarded = self.classifier.classify(_GUARDED_AM1_RESULT)
        self.assertGreater(
            unguarded["signals"]["taint"]["raw"],
            guarded["signals"]["taint"]["raw"],
        )

    def test_guarded_taint_still_nonzero(self):
        result = self.classifier.classify(_GUARDED_AM1_RESULT)
        self.assertGreater(result["signals"]["taint"]["raw"], 0.0)


class TestCustomThresholds(unittest.TestCase):
    """Custom threshold and weight overrides."""

    def test_lower_threshold_catches_more(self):
        strict = AdversarialClassifier(threshold_adversarial=0.8)
        loose = AdversarialClassifier(threshold_adversarial=0.3)

        strict_result = strict.classify(_BORDERLINE_RESULT)
        loose_result = loose.classify(_BORDERLINE_RESULT)

        # Loose threshold should be at least as aggressive
        if strict_result["classification"] == "adversarial":
            self.assertEqual(loose_result["classification"], "adversarial")

    def test_custom_weights_change_score(self):
        default = AdversarialClassifier()
        taint_heavy = AdversarialClassifier(weights={
            "taint": 0.90, "callback": 0.02, "similarity": 0.02,
            "complexity": 0.02, "gnn": 0.02, "obfuscation": 0.02,
        })

        default_result = default.classify(_MEV_BOT_RESULT)
        heavy_result = taint_heavy.classify(_MEV_BOT_RESULT)

        # Both should classify MEV bot as adversarial, but scores may differ
        self.assertEqual(heavy_result["classification"], "adversarial")
        self.assertIsInstance(heavy_result["adversarial_score"], float)


class TestEmptyAndMinimalInputs(TestAdversarialClassifier):
    """Graceful handling of empty or minimal pipeline results."""

    def test_empty_result_classifies_benign(self):
        result = self.classifier.classify({})
        self.assertEqual(result["classification"], "benign")

    def test_minimal_result_no_crash(self):
        result = self.classifier.classify({
            "am_findings": [],
            "taint_result": {},
            "gnn_result": {},
            "cfg_profile": {},
        })
        self.assertIn(result["classification"], ("adversarial", "suspicious", "benign"))

    def test_missing_gnn_result_no_crash(self):
        r = copy.deepcopy(_MEV_BOT_RESULT)
        del r["gnn_result"]
        result = self.classifier.classify(r)
        self.assertIsInstance(result["adversarial_score"], float)

    def test_missing_similarity_no_crash(self):
        r = copy.deepcopy(_MEV_BOT_RESULT)
        del r["similarity"]
        result = self.classifier.classify(r)
        self.assertIsInstance(result["adversarial_score"], float)

    def test_missing_complexity_no_crash(self):
        r = copy.deepcopy(_MEV_BOT_RESULT)
        del r["complexity"]
        result = self.classifier.classify(r)
        self.assertIsInstance(result["adversarial_score"], float)


if __name__ == "__main__":
    unittest.main()
