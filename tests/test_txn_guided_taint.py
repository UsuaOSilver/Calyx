"""
tests/test_txn_guided_taint.py
Tests for TxnGuidedTaintAnalyzer — all Etherscan calls are mocked.
"""
from __future__ import annotations
import sys, os, unittest
from unittest.mock import MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analysis.txn_guided_taint import TxnGuidedTaintAnalyzer

_ADDR_WORD = "0" * 24 + "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_TX_WITH_ADDR = {
    "hash": "0xaaa", "blockNumber": "19000000", "from": "0xf39fd",
    "input": "0xa9059cbb" + _ADDR_WORD + "0" * 64, "value": "0",
}
_TX_WITH_ETH = {
    "hash": "0xbbb", "blockNumber": "19000001", "from": "0xf39fd",
    "input": "0x12345678", "value": "1000000000000000000",
}
_TX_PLAIN = {
    "hash": "0xccc", "blockNumber": "19000002", "from": "0xf39fd",
    "input": "0xdeadbeef", "value": "0",
}
_AM1 = {"type": "AM1", "severity": "high", "pc": 0, "description": "t", "taint_source": "calldata"}
_AM2 = {"type": "AM2", "severity": "high", "pc": 4, "description": "t", "taint_source": "calldata"}


def _mock_client(txns, success=True):
    client = MagicMock()
    client.get_transaction_list.return_value = {
        "success": success, "transactions": txns,
        "error": None if success else "fetch failed",
    }
    return client


class TestTxnGuidedTaintAnalyzer(unittest.TestCase):
    def test_analyze_returns_dict(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN]))
        self.assertIsInstance(a.analyze("0xabc", [_AM1]), dict)

    def test_result_keys_present(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN]))
        result = a.analyze("0xabc", [])
        for key in ("hot_selectors", "am1_candidate_txns", "am2_candidate_txns",
                    "evidence_txns", "txn_count", "error"):
            self.assertIn(key, result)

    def test_error_none_on_success(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN]))
        self.assertIsNone(a.analyze("0xabc", [_AM1])["error"])

    def test_txn_count_correct(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN, _TX_WITH_ETH]))
        self.assertEqual(a.analyze("0xabc", [])["txn_count"], 2)

    def test_hot_selectors_populated(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN, _TX_WITH_ETH]))
        self.assertGreaterEqual(len(a.analyze("0xabc", [_AM1])["hot_selectors"]), 1)

    def test_hot_selector_keys(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_PLAIN]))
        result = a.analyze("0xabc", [])
        if result["hot_selectors"]:
            for key in ("selector", "count", "pct"):
                self.assertIn(key, result["hot_selectors"][0])

    def test_am1_candidate_detected(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ADDR]))
        self.assertGreater(len(a.analyze("0xabc", [_AM1])["am1_candidate_txns"]), 0)

    def test_am1_no_candidates_without_finding(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ADDR]))
        self.assertEqual(a.analyze("0xabc", [])["am1_candidate_txns"], [])

    def test_am2_candidate_detected_on_nonzero_value(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ETH]))
        self.assertGreater(len(a.analyze("0xabc", [_AM2])["am2_candidate_txns"]), 0)

    def test_am2_no_candidates_without_finding(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ETH]))
        self.assertEqual(a.analyze("0xabc", [])["am2_candidate_txns"], [])

    def test_tx_in_both_lists_promoted_to_evidence(self):
        tx_both = {**_TX_WITH_ADDR, "value": "500000000000000000", "hash": "0xddd"}
        a = TxnGuidedTaintAnalyzer(_mock_client([tx_both]))
        result = a.analyze("0xabc", [_AM1, _AM2])
        self.assertIn("0xddd", {t["hash"] for t in result["evidence_txns"]})

    def test_fetch_failure_returns_error(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([], success=False))
        result = a.analyze("0xabc", [_AM1])
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["txn_count"], 0)

    def test_empty_txn_list_returns_error(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([]))
        self.assertIsNotNone(a.analyze("0xabc", [_AM1])["error"])

    def test_candidate_summary_keys(self):
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ADDR]))
        result = a.analyze("0xabc", [_AM1])
        if result["am1_candidate_txns"]:
            for key in ("hash", "block", "from", "am_type", "eth_value_wei", "calldata_snippet"):
                self.assertIn(key, result["am1_candidate_txns"][0])

    def test_no_duplicate_hashes_in_evidence(self):
        tx_both = {**_TX_WITH_ADDR, "value": "1000", "hash": "0xeee"}
        a = TxnGuidedTaintAnalyzer(_mock_client([tx_both]))
        result = a.analyze("0xabc", [_AM1, _AM2])
        hashes = [t["hash"] for t in result["evidence_txns"]]
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_hot_selectors_sorted_desc(self):
        txns = [_TX_PLAIN] * 5 + [_TX_WITH_ADDR] * 2
        a = TxnGuidedTaintAnalyzer(_mock_client(txns))
        counts = [s["count"] for s in a.analyze("0xabc", [])["hot_selectors"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_non_am_findings_ignored(self):
        am5 = {"type": "AM5", "severity": "medium", "pc": 0, "description": "t"}
        a = TxnGuidedTaintAnalyzer(_mock_client([_TX_WITH_ETH]))
        result = a.analyze("0xabc", [am5])
        self.assertEqual(result["am1_candidate_txns"], [])
        self.assertEqual(result["am2_candidate_txns"], [])


if __name__ == "__main__":
    unittest.main()
