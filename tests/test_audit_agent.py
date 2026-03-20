"""
tests/test_audit_agent.py
Tests for AuditAgent — all LLM calls are mocked.
"""
from __future__ import annotations
import sys, os, json, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analysis.audit_agent import AuditAgent

_PIPELINE_RESULT = {
    "address": "0x00000000003b3cc22af3ae1eac0440bcee416b40",
    "network": "ethereum", "risk_score": 0.72, "risk_level": "HIGH",
    "am_findings": [{"type": "AM1", "severity": "high", "pc": 0,
                     "description": "Calldata CALL target", "taint_source": "calldata"}],
    "am_types_found": ["AM1"], "confirmed_exploits": [], "breakdown": {},
    "cfg_deob": {"resolved": 3, "approximated": 1, "block_count": 4, "edge_count": 5},
    "cfg_profile": {}, "taint_result": {"findings": [], "am_types_found": ["AM1"],
                     "caller_guarded": False, "error": None},
    "gnn_result": {"exploit_probability": 0.5, "risk_level": "MEDIUM",
                   "block_count": 4, "edge_count": 5},
    "txn_result": {}, "error": None,
}

_GOOD_JSON = json.dumps({
    "verdict": "VULNERABLE",
    "vulnerability_summary": "AM1 allows calldata-controlled CALL target.",
    "findings": [{"type": "AM1", "title": "Arbitrary CALL", "description": "d",
                  "exploit_scenario": "e", "severity": "HIGH", "confidence": "HIGH",
                  "recommendation": "r"}],
    "overall_assessment": "Critical risk.",
    "triage_recommendation": "BLOCK", "audit_notes": "None.",
})

_NO_KEY_ENV = {k: v for k, v in os.environ.items()
               if k not in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                            "GROQ_API_KEY", "OPENAI_API_KEY")}


class TestAuditAgentNoKey(unittest.TestCase):
    def _agent(self):
        with patch.dict(os.environ, _NO_KEY_ENV, clear=True):
            return AuditAgent()

    def test_available_false_without_key(self):
        with patch.dict(os.environ, _NO_KEY_ENV, clear=True):
            self.assertFalse(AuditAgent.available())

    def test_audit_returns_dict(self):
        self.assertIsInstance(self._agent().audit(_PIPELINE_RESULT), dict)

    def test_audit_verdict_inconclusive(self):
        self.assertEqual(self._agent().audit(_PIPELINE_RESULT)["verdict"], "INCONCLUSIVE")

    def test_audit_error_field_set(self):
        self.assertIsNotNone(self._agent().audit(_PIPELINE_RESULT).get("error"))

    def test_error_report_required_keys(self):
        result = self._agent().audit(_PIPELINE_RESULT)
        for key in ("verdict", "vulnerability_summary", "findings",
                    "overall_assessment", "triage_recommendation",
                    "audit_notes", "provider", "model", "error"):
            self.assertIn(key, result)


class TestParseResponse(unittest.TestCase):
    def test_parse_clean_json(self):
        self.assertEqual(AuditAgent._parse_response(_GOOD_JSON)["verdict"], "VULNERABLE")

    def test_parse_json_in_markdown_fences(self):
        result = AuditAgent._parse_response(f"```json\n{_GOOD_JSON}\n```")
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_parse_json_in_plain_fences(self):
        result = AuditAgent._parse_response(f"```\n{_GOOD_JSON}\n```")
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_parse_json_with_leading_text(self):
        result = AuditAgent._parse_response(f"Here is my analysis:\n{_GOOD_JSON}")
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_parse_invalid_returns_inconclusive(self):
        result = AuditAgent._parse_response("not json at all")
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("error", result)

    def test_parse_empty_string_returns_inconclusive(self):
        self.assertEqual(AuditAgent._parse_response("")["verdict"], "INCONCLUSIVE")

    def test_parse_findings_list_preserved(self):
        result = AuditAgent._parse_response(_GOOD_JSON)
        self.assertIsInstance(result["findings"], list)
        self.assertEqual(len(result["findings"]), 1)


class TestAuditAgentMocked(unittest.TestCase):
    def _make_agent(self, api_key="test_key_123"):
        with patch.dict(os.environ, {**os.environ, "ANTHROPIC_API_KEY": api_key}):
            return AuditAgent()

    def _mock_resp(self, text):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {"content": [{"text": text}]}
        return m

    def test_audit_returns_dict(self):
        agent = self._make_agent()
        with patch("requests.post", return_value=self._mock_resp(_GOOD_JSON)):
            self.assertIsInstance(agent.audit(_PIPELINE_RESULT), dict)

    def test_audit_verdict(self):
        agent = self._make_agent()
        with patch("requests.post", return_value=self._mock_resp(_GOOD_JSON)):
            self.assertEqual(agent.audit(_PIPELINE_RESULT)["verdict"], "VULNERABLE")

    def test_audit_provider_field(self):
        agent = self._make_agent()
        with patch("requests.post", return_value=self._mock_resp(_GOOD_JSON)):
            self.assertEqual(agent.audit(_PIPELINE_RESULT).get("provider"), "anthropic")

    def test_audit_model_field_set(self):
        agent = self._make_agent()
        with patch("requests.post", return_value=self._mock_resp(_GOOD_JSON)):
            self.assertIsNotNone(agent.audit(_PIPELINE_RESULT).get("model"))

    def test_audit_exception_returns_inconclusive(self):
        agent = self._make_agent()
        with patch("requests.post", side_effect=ConnectionError("network down")):
            result = agent.audit(_PIPELINE_RESULT)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIsNotNone(result["error"])

    def test_requests_post_called_once(self):
        agent = self._make_agent()
        with patch("requests.post", return_value=self._mock_resp(_GOOD_JSON)) as mock_post:
            agent.audit(_PIPELINE_RESULT)
        mock_post.assert_called_once()

    def test_available_true_with_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test_key_123"}):
            self.assertTrue(AuditAgent.available())


if __name__ == "__main__":
    unittest.main()
