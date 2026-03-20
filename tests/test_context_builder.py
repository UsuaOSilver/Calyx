"""
tests/test_context_builder.py
Tests for ContextBuilder — no network, no LLM calls.
"""
from __future__ import annotations
import sys, os, json, copy, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analysis.context_builder import ContextBuilder

_RESULT = {
    "address": "0x00000000003b3cc22af3ae1eac0440bcee416b40",
    "network": "ethereum",
    "risk_score": 0.72, "risk_level": "HIGH",
    "am_findings": [{"type": "AM1", "severity": "high", "pc": 0,
                     "description": "Calldata CALL target", "taint_source": "calldata"}],
    "am_types_found": ["AM1"], "confirmed_exploits": [],
    "breakdown": {"gnn_contribution": 0.15, "llm_contribution": 0.42,
                  "txn_contribution": 0.0, "llm_sub_score": 0.7,
                  "finding_count": 1, "finding_severities": ["high"]},
    "cfg_deob": {"resolved": 3, "approximated": 1, "block_count": 4, "edge_count": 5},
    "cfg_profile": {"total_jumps": 2, "direct_jumps": 2, "indirect_jumps": 0,
                    "obfuscation_score": 0.0, "assessment": "clean",
                    "indirect_jump_pcs": [], "all_jumpdest_pcs": [3], "instruction_count": 5},
    "taint_result": {"findings": [], "am_types_found": ["AM1"],
                     "caller_guarded": False, "error": None},
    "gnn_result": {"exploit_probability": 0.5, "risk_level": "MEDIUM",
                   "block_count": 4, "edge_count": 5},
    "txn_result": {}, "error": None,
}


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.b = ContextBuilder(_RESULT)

    def test_returns_string(self):
        self.assertIsInstance(self.b.build(), str)

    def test_is_nonempty(self):
        self.assertGreater(len(self.b.build()), 0)

    def test_contains_address(self):
        self.assertIn("0x00000000003b3cc22af3ae1eac0440bcee416b40", self.b.build())

    def test_contains_risk_level(self):
        self.assertIn("HIGH", self.b.build())

    def test_contains_risk_score(self):
        self.assertIn("0.720", self.b.build())

    def test_contains_network(self):
        self.assertIn("ethereum", self.b.build())

    def test_contains_am1(self):
        self.assertIn("AM1", self.b.build())

    def test_contains_calyx_header(self):
        self.assertIn("Calyx", self.b.build())

    def test_no_network_call(self):
        result = self.b.build()
        self.assertIsInstance(result, str)

    def test_empty_findings_still_works(self):
        r = copy.deepcopy(_RESULT)
        r["am_findings"] = []
        self.assertIsInstance(ContextBuilder(r).build(), str)


class TestBuildJson(unittest.TestCase):
    def setUp(self):
        self.b = ContextBuilder(_RESULT)

    def test_returns_dict(self):
        self.assertIsInstance(self.b.build_json(), dict)

    def test_top_level_keys(self):
        result = self.b.build_json()
        for key in ("metadata", "risk", "findings", "cfg", "taint_analysis", "gnn", "transactions"):
            self.assertIn(key, result)

    def test_metadata_address(self):
        self.assertEqual(self.b.build_json()["metadata"]["address"],
                         "0x00000000003b3cc22af3ae1eac0440bcee416b40")

    def test_metadata_network(self):
        self.assertEqual(self.b.build_json()["metadata"]["network"], "ethereum")

    def test_metadata_generated_present(self):
        self.assertIn("generated", self.b.build_json()["metadata"])

    def test_risk_score(self):
        self.assertAlmostEqual(self.b.build_json()["risk"]["score"], 0.72, places=2)

    def test_risk_level(self):
        self.assertEqual(self.b.build_json()["risk"]["level"], "HIGH")

    def test_findings_total(self):
        self.assertEqual(self.b.build_json()["findings"]["total"], 1)

    def test_findings_am_types(self):
        self.assertIn("AM1", self.b.build_json()["findings"]["am_types"])

    def test_gnn_probability(self):
        self.assertAlmostEqual(self.b.build_json()["gnn"]["exploit_probability"], 0.5, places=1)

    def test_cfg_block_count(self):
        self.assertEqual(self.b.build_json()["cfg"]["deobfuscation"]["block_count"], 4)

    def test_taint_caller_guarded_false(self):
        self.assertFalse(self.b.build_json()["taint_analysis"]["caller_guarded"])

    def test_json_serializable(self):
        json.dumps(self.b.build_json())   # must not raise

    def test_minimal_input_no_crash(self):
        result = ContextBuilder({"risk_score": 0.0, "risk_level": "LOW"}).build_json()
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
