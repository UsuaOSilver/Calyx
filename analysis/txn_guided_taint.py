"""
analysis/txn_guided_taint.py

Txn-Guided Taint Analysis — Hackathon P1 (SKANF author future direction #2).

SKANF's 2nd core innovation: "prioritize symbolic exploration based on real-world
execution traces."  We adapt this idea for our static pipeline: fetch historical
Etherscan transactions, extract actual calldata, and cross-reference with
TaintAnalyzer findings to:

  1. Identify which function selectors have been called most (hot paths)
  2. Flag individual transactions whose calldata contains patterns consistent
     with AM1 (externally-supplied address) or AM2 (externally-supplied ETH value)
  3. Surface "evidence transactions" — real txns that may be exploitation attempts
     or that provide concrete proof-of-concept calldata for each finding

Output is added to the BytecodePipeline result as `txn_guided_taint`.

Usage:
    from analysis.txn_guided_taint import TxnGuidedTaintAnalyzer

    analyzer = TxnGuidedTaintAnalyzer(etherscan_client)
    result = analyzer.analyze(
        address="0x...",
        taint_findings=[...],   # from TaintAnalyzer
        max_txns=100,
    )
    # result["evidence_txns"]      — [{hash, selector, am_type, calldata_snippet}]
    # result["hot_selectors"]      — [{selector, count, pct}]
    # result["am1_candidate_txns"] — txns with 32-byte-aligned address in calldata
    # result["am2_candidate_txns"] — txns with nonzero ETH value + calldata
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Minimum calldata length to be interesting (selector + at least 1 word = 36 bytes → 72 hex chars)
_MIN_CALLDATA_BYTES = 36
# An address word: 12 zero bytes + 20 address bytes = 32 bytes.
# A value of 0 for address fields would be 32 zero bytes.
_ZERO_WORD = "0" * 64
# Large-value threshold: more than 0.001 ETH (in wei, as hex digit count)
_NONZERO_ETH_THRESHOLD = 1  # any tx.value > 0 is interesting for AM2


class TxnGuidedTaintAnalyzer:
    """
    Correlates historical on-chain transactions with static taint findings.

    Identifies real transactions that corroborate AM1/AM2 vulnerability findings,
    providing concrete evidence of exploitation risk with actual calldata.
    """

    def __init__(self, etherscan_client: Any) -> None:
        """
        Args:
            etherscan_client: An EtherscanClient instance (from integrations/).
        """
        self._client = etherscan_client

    def analyze(
        self,
        address: str,
        taint_findings: List[Dict[str, Any]],
        max_txns: int = 100,
    ) -> Dict[str, Any]:
        """
        Fetch transactions and correlate with taint findings.

        Args:
            address:        Contract address to analyze.
            taint_findings: AM1/AM2 findings from TaintAnalyzer.
            max_txns:       Number of recent transactions to fetch.

        Returns:
            {
                "hot_selectors":      List[dict] — most-called function selectors
                "am1_candidate_txns": List[dict] — txns with address-like calldata args
                "am2_candidate_txns": List[dict] — txns with nonzero ETH value
                "evidence_txns":      List[dict] — txns corroborating specific findings
                "txn_count":          int
                "error":              Optional[str]
            }
        """
        am_types_targeted = {f["type"] for f in taint_findings if f["type"] in ("AM1", "AM2")}

        txn_result = self._client.get_transaction_list(address, limit=max_txns)
        if not txn_result.get("success"):
            return self._empty(txn_result.get("error", "txn fetch failed"))

        txns: List[Dict[str, Any]] = txn_result.get("transactions", [])
        if not txns:
            return self._empty("no transactions found")

        # ── Step 1: Hot path analysis (function selectors) ────────────────────
        selector_counts: Dict[str, int] = {}
        for tx in txns:
            inp = tx.get("input", "0x")
            sel = self._selector(inp)
            if sel:
                selector_counts[sel] = selector_counts.get(sel, 0) + 1

        total = len(txns)
        hot_selectors = sorted(
            [
                {
                    "selector": sel,
                    "count": cnt,
                    "pct": round(cnt / total * 100, 1),
                }
                for sel, cnt in selector_counts.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        # ── Step 2: AM1 candidate transactions ────────────────────────────────
        # AM1: calldata contains an embedded address (32-byte word where top 12 bytes
        # are 0x000...000 and bottom 20 bytes look like an address).
        am1_candidates: List[Dict[str, Any]] = []
        if "AM1" in am_types_targeted:
            for tx in txns:
                inp = tx.get("input", "0x")
                if self._has_address_word(inp):
                    am1_candidates.append(self._summarize_tx(tx, "AM1"))

        # ── Step 3: AM2 candidate transactions ────────────────────────────────
        # AM2: transaction sent nonzero ETH value to this contract
        am2_candidates: List[Dict[str, Any]] = []
        if "AM2" in am_types_targeted:
            for tx in txns:
                try:
                    eth_val = int(tx.get("value", "0"))
                except (ValueError, TypeError):
                    eth_val = 0
                if eth_val > 0:
                    am2_candidates.append(self._summarize_tx(tx, "AM2"))

        # ── Step 4: Build evidence list ───────────────────────────────────────
        evidence: List[Dict[str, Any]] = []
        seen_hashes: set = set()

        # Prioritize AM1 candidates that also sent value (highest suspicion)
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

        # Limit evidence list to top 20 most recent
        evidence = evidence[:20]

        log.info(
            f"TxnGuidedTaint [{address}]: {total} txns, "
            f"{len(am1_candidates)} AM1 candidates, "
            f"{len(am2_candidates)} AM2 candidates, "
            f"{len(evidence)} evidence txns"
        )

        return {
            "hot_selectors":      hot_selectors,
            "am1_candidate_txns": am1_candidates[:20],
            "am2_candidate_txns": am2_candidates[:20],
            "evidence_txns":      evidence,
            "txn_count":          total,
            "error":              None,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _selector(input_hex: str) -> Optional[str]:
        """Extract 4-byte function selector from calldata hex, or None."""
        data = input_hex[2:] if input_hex.startswith("0x") else input_hex
        if len(data) >= 8:
            return "0x" + data[:8]
        return None

    @staticmethod
    def _has_address_word(input_hex: str) -> bool:
        """
        Return True if calldata contains at least one 32-byte-aligned word that
        looks like an ABI-encoded address (top 12 bytes zero, bottom 20 bytes nonzero).
        """
        data = input_hex[2:] if input_hex.startswith("0x") else input_hex
        if len(data) < 8 + 64:  # need selector + at least one word
            return False
        # Skip selector (8 hex chars), then scan 32-byte (64 hex char) words
        payload = data[8:]
        for i in range(0, len(payload) - 63, 64):
            word = payload[i: i + 64]
            if len(word) < 64:
                break
            # Top 12 bytes (24 hex chars) must be zero
            if word[:24] == "0" * 24:
                # Bottom 20 bytes (40 hex chars) must be nonzero
                if word[24:] != "0" * 40:
                    return True
        return False

    @staticmethod
    def _summarize_tx(tx: Dict[str, Any], am_type: str) -> Dict[str, Any]:
        """Build a compact evidence record for a transaction."""
        inp = tx.get("input", "0x")
        snippet = inp[:66] + ("..." if len(inp) > 66 else "")
        try:
            eth_val_wei = int(tx.get("value", "0"))
        except (ValueError, TypeError):
            eth_val_wei = 0
        return {
            "hash":            tx.get("hash", ""),
            "block":           tx.get("blockNumber", ""),
            "from":            tx.get("from", ""),
            "am_type":         am_type,
            "eth_value_wei":   eth_val_wei,
            "calldata_snippet": snippet,
        }

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {
            "hot_selectors":      [],
            "am1_candidate_txns": [],
            "am2_candidate_txns": [],
            "evidence_txns":      [],
            "txn_count":          0,
            "error":              error,
        }
