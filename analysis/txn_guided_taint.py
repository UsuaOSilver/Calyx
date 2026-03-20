"""
analysis/txn_guided_taint.py

Txn-Guided Taint Analysis — Hackathon P1 (SKANF author future direction #2).

Fetches historical Etherscan transactions, extracts actual calldata, and
cross-references with TaintAnalyzer findings to:
  1. Identify which function selectors have been called most (hot paths)
  2. Flag txns whose calldata contains patterns consistent with AM1/AM2
  3. Surface "evidence transactions" — real txns that may be exploitation
     attempts or provide proof-of-concept calldata for each finding

Usage:
    from analysis.txn_guided_taint import TxnGuidedTaintAnalyzer
    analyzer = TxnGuidedTaintAnalyzer(etherscan_client)
    result = analyzer.analyze(address="0x...", taint_findings=[...])
    # result["evidence_txns"]      — [{hash, selector, am_type, calldata_snippet}]
    # result["hot_selectors"]      — [{selector, count, pct}]
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_MIN_CALLDATA_BYTES = 36
_ZERO_WORD = "0" * 64


class TxnGuidedTaintAnalyzer:
    """Correlates historical on-chain transactions with static taint findings."""

    def __init__(self, etherscan_client: Any) -> None:
        self._client = etherscan_client

    def analyze(self, address: str, taint_findings: List[Dict[str, Any]],
                max_txns: int = 100) -> Dict[str, Any]:
        am_types_targeted = {f["type"] for f in taint_findings if f["type"] in ("AM1","AM2")}

        txn_result = self._client.get_transaction_list(address, limit=max_txns)
        if not txn_result.get("success"):
            return self._empty(txn_result.get("error", "txn fetch failed"))

        txns: List[Dict[str, Any]] = txn_result.get("transactions", [])
        if not txns:
            return self._empty("no transactions found")

        # Step 1: Hot path analysis
        selector_counts: Dict[str, int] = {}
        for tx in txns:
            sel = self._selector(tx.get("input", "0x"))
            if sel:
                selector_counts[sel] = selector_counts.get(sel, 0) + 1

        total = len(txns)
        hot_selectors = sorted(
            [{"selector": sel, "count": cnt, "pct": round(cnt / total * 100, 1)}
             for sel, cnt in selector_counts.items()],
            key=lambda x: x["count"], reverse=True,
        )[:10]

        # Step 2: AM1 candidate transactions
        am1_candidates: List[Dict[str, Any]] = []
        if "AM1" in am_types_targeted:
            for tx in txns:
                if self._has_address_word(tx.get("input", "0x")):
                    am1_candidates.append(self._summarize_tx(tx, "AM1"))

        # Step 3: AM2 candidate transactions
        am2_candidates: List[Dict[str, Any]] = []
        if "AM2" in am_types_targeted:
            for tx in txns:
                try:
                    eth_val = int(tx.get("value", "0"))
                except (ValueError, TypeError):
                    eth_val = 0
                if eth_val > 0:
                    am2_candidates.append(self._summarize_tx(tx, "AM2"))

        # Step 4: Build evidence list
        evidence: List[Dict[str, Any]] = []
        seen_hashes: set = set()
        am1_hashes = {t["hash"] for t in am1_candidates}

        for tx_summary in am2_candidates:
            if tx_summary["hash"] in am1_hashes and tx_summary["hash"] not in seen_hashes:
                tx_summary["am_type"] = "AM1+AM2"
                tx_summary["note"] = "Address-like calldata word AND nonzero ETH value"
                evidence.append(tx_summary)
                seen_hashes.add(tx_summary["hash"])

        for tx_summary in am1_candidates:
            if tx_summary["hash"] not in seen_hashes:
                tx_summary["note"] = "Calldata contains embedded address argument"
                evidence.append(tx_summary)
                seen_hashes.add(tx_summary["hash"])

        for tx_summary in am2_candidates:
            if tx_summary["hash"] not in seen_hashes:
                tx_summary["note"] = "Nonzero ETH value forwarded to contract"
                evidence.append(tx_summary)
                seen_hashes.add(tx_summary["hash"])

        log.info(f"TxnGuidedTaint [{address}]: {total} txns, "
                 f"{len(am1_candidates)} AM1 candidates, "
                 f"{len(am2_candidates)} AM2 candidates, "
                 f"{len(evidence)} evidence txns")

        return {
            "hot_selectors":      hot_selectors,
            "am1_candidate_txns": am1_candidates[:20],
            "am2_candidate_txns": am2_candidates[:20],
            "evidence_txns":      evidence[:20],
            "txn_count":          total,
            "error":              None,
        }

    @staticmethod
    def _selector(input_hex: str) -> Optional[str]:
        data = input_hex[2:] if input_hex.startswith("0x") else input_hex
        if len(data) >= 8:
            return "0x" + data[:8]
        return None

    @staticmethod
    def _has_address_word(input_hex: str) -> bool:
        data = input_hex[2:] if input_hex.startswith("0x") else input_hex
        if len(data) < 8 + 64:
            return False
        payload = data[8:]
        for i in range(0, len(payload) - 63, 64):
            word = payload[i: i + 64]
            if len(word) < 64:
                break
            if word[:24] == "0" * 24 and word[24:] != "0" * 40:
                return True
        return False

    @staticmethod
    def _summarize_tx(tx: Dict[str, Any], am_type: str) -> Dict[str, Any]:
        inp = tx.get("input", "0x")
        snippet = inp[:66] + ("..." if len(inp) > 66 else "")
        try:
            eth_val_wei = int(tx.get("value", "0"))
        except (ValueError, TypeError):
            eth_val_wei = 0
        return {
            "hash": tx.get("hash", ""), "block": tx.get("blockNumber", ""),
            "from": tx.get("from", ""), "am_type": am_type,
            "eth_value_wei": eth_val_wei, "calldata_snippet": snippet,
        }

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {
            "hot_selectors": [], "am1_candidate_txns": [], "am2_candidate_txns": [],
            "evidence_txns": [], "txn_count": 0, "error": error,
        }
