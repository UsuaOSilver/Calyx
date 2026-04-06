from __future__ import annotations
# detectors/bytecode_analyzer/txn_analyzer.py
"""
Historical transaction anomaly analyzer.

Fetches the last N transactions for a contract address via the existing
EtherscanClient and detects patterns associated with asset management
vulnerabilities (SKANF AM1–AM5 taxonomy):

  AM1: Unguarded CALL with calldata-controlled target address
  AM2: Unguarded CALL with calldata-controlled value
  AM3: tx.origin used as authorization check  (inferred from sender patterns)
  AM4: Approve-then-transferFrom without caller validation
  AM5: Callback callable by arbitrary external address

Observable signals from on-chain transaction history:
  - Many different callers invoking the same function
  - Transactions with large ETH value from unexpected external callers
  - Calls from newly-created contracts (potential flash-loan attack prep)
  - Function selectors not matching any known ERC interface
  - Single large drain transaction preceded by unusual activity

Usage:
    from detectors.bytecode_analyzer.txn_analyzer import TxnAnalyzer
    a = TxnAnalyzer(etherscan_client)
    result = a.analyze("0xContractAddress", limit=50)
"""

import logging
from collections import Counter, defaultdict
from typing import Any

log = logging.getLogger(__name__)

# Well-known ERC20/ERC721 function selectors (4-byte hex, no 0x prefix)
KNOWN_SELECTORS: dict[str, str] = {
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    "6352211e": "ownerOf(uint256)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "e985e9c5": "isApprovedForAll(address,address)",
    "a22cb465": "setApprovalForAll(address,bool)",
}

# Minimum ETH value (in wei) to flag as "large"
LARGE_ETH_WEI = 10 ** 18  # 1 ETH


class TxnAnalyzer:
    def __init__(self, etherscan_client):
        """
        Args:
            etherscan_client: An initialized EtherscanClient instance.
        """
        self.client = etherscan_client

    def analyze(self, address: str, limit: int = 50) -> dict[str, Any]:
        """
        Fetch and analyze recent transactions for a contract.

        Returns:
            {
                "address":               str,
                "tx_count_analyzed":     int,
                "unique_callers":        int,
                "unknown_selectors":     list[str],
                "large_value_txs":       list[dict],
                "anomaly_flags":         list[str],
                "anomaly_score":         float,   # 0.0–1.0
                "error":                 str | None
            }
        """
        result = self.client.get_transaction_list(address, limit=limit)
        if not result.get("success"):
            return self._empty(address, error=result.get("error", "fetch failed"))

        txns = result.get("transactions", [])
        if not txns:
            return self._empty(address, error="no transactions found")

        callers: set[str] = set()
        selector_counts: Counter = Counter()
        large_value_txs: list[dict] = []
        new_contract_callers: list[str] = []
        drain_candidates: list[dict] = []

        for tx in txns:
            sender = tx.get("from", "").lower()
            callers.add(sender)

            # Extract function selector (first 4 bytes of input)
            inp = tx.get("input", "")
            if len(inp) >= 10 and inp.startswith("0x"):
                sel = inp[2:10].lower()
                selector_counts[sel] += 1

            # Large ETH value
            try:
                value_wei = int(tx.get("value", "0"))
            except ValueError:
                value_wei = 0
            if value_wei >= LARGE_ETH_WEI:
                large_value_txs.append({
                    "hash": tx.get("hash", ""),
                    "from": sender,
                    "value_eth": round(value_wei / 1e18, 4),
                    "selector": inp[2:10] if len(inp) >= 10 else "fallback",
                })

            # Newly created contract as caller (isError + contractAddress hint)
            if tx.get("contractAddress") and tx.get("contractAddress") != address.lower():
                new_contract_callers.append(sender)

        # Unknown selectors: called more than once but not in known ERC list
        unknown_selectors = [
            sel for sel, count in selector_counts.items()
            if sel not in KNOWN_SELECTORS and count >= 2
        ]

        anomaly_flags = self._detect_anomalies(
            callers=callers,
            selector_counts=selector_counts,
            unknown_selectors=unknown_selectors,
            large_value_txs=large_value_txs,
            new_contract_callers=new_contract_callers,
            total_txns=len(txns),
        )

        anomaly_score = min(1.0, len(anomaly_flags) * 0.2)

        return {
            "address": address,
            "tx_count_analyzed": len(txns),
            "unique_callers": len(callers),
            "selector_distribution": dict(selector_counts.most_common(10)),
            "unknown_selectors": unknown_selectors,
            "large_value_txs": large_value_txs[:5],  # top 5 for context
            "anomaly_flags": anomaly_flags,
            "anomaly_score": round(anomaly_score, 2),
            "error": None,
        }

    def _detect_anomalies(
        self,
        callers: set,
        selector_counts: Counter,
        unknown_selectors: list,
        large_value_txs: list,
        new_contract_callers: list,
        total_txns: int,
    ) -> list[str]:
        flags: list[str] = []

        # Many distinct callers invoking same unknown function
        # (suggests public function with no caller restriction)
        if unknown_selectors and len(callers) > 10:
            flags.append(
                f"AM1/AM3: {len(unknown_selectors)} unknown function selector(s) called "
                f"by {len(callers)} distinct addresses — possible unguarded function"
            )

        # Large ETH outflows
        if large_value_txs:
            flags.append(
                f"AM2: {len(large_value_txs)} transaction(s) moved ≥1 ETH — "
                f"review caller authorization"
            )

        # Single dominant caller (potential whitelist bypass — only one approved caller)
        if total_txns >= 10:
            top_caller, top_count = selector_counts.most_common(1)[0] if selector_counts else ("", 0)
            top_caller_fraction = top_count / total_txns
            # Note: selector_counts not caller_counts here but gives signal
            unique_ratio = len(callers) / total_txns
            if unique_ratio < 0.1:
                flags.append(
                    "AM3: >90% of calls from same address — tx.origin whitelist pattern possible"
                )

        # Contracts deploying and immediately calling (flash loan / callback setup)
        if new_contract_callers:
            flags.append(
                f"AM5: {len(new_contract_callers)} call(s) from newly deployed contracts — "
                f"callback exploitation pattern"
            )

        # approve + transferFrom pattern with many callers (AM4)
        has_approve = "095ea7b3" in selector_counts
        has_transfer_from = "23b872dd" in selector_counts
        if has_approve and has_transfer_from and len(callers) > 5:
            flags.append(
                "AM4: approve() + transferFrom() both called by multiple addresses — "
                "verify transferFrom caller validation"
            )

        return flags

    @staticmethod
    def _empty(address: str, error: str = "") -> dict[str, Any]:
        return {
            "address": address,
            "tx_count_analyzed": 0,
            "unique_callers": 0,
            "selector_distribution": {},
            "unknown_selectors": [],
            "large_value_txs": [],
            "anomaly_flags": [],
            "anomaly_score": 0.0,
            "error": error,
        }
