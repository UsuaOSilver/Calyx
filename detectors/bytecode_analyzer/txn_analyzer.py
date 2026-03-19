# detectors/bytecode_analyzer/txn_analyzer.py
"""
Historical transaction anomaly analyzer.

Fetches the last N transactions for a contract address via EtherscanClient
and detects patterns associated with SKANF AM1-AM5 vulnerabilities.

Usage:
    from detectors.bytecode_analyzer.txn_analyzer import TxnAnalyzer
    a = TxnAnalyzer(etherscan_client)
    result = a.analyze("0xContractAddress", limit=50)
"""

import logging
from collections import Counter
from typing import Any

log = logging.getLogger(__name__)

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

LARGE_ETH_WEI = 10 ** 18


class TxnAnalyzer:
    def __init__(self, etherscan_client):
        self.client = etherscan_client

    def analyze(self, address: str, limit: int = 50) -> dict[str, Any]:
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

        for tx in txns:
            sender = tx.get("from", "").lower()
            callers.add(sender)

            inp = tx.get("input", "")
            if len(inp) >= 10 and inp.startswith("0x"):
                sel = inp[2:10].lower()
                selector_counts[sel] += 1

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

            if tx.get("contractAddress") and tx.get("contractAddress") != address.lower():
                new_contract_callers.append(sender)

        unknown_selectors = [
            sel for sel, count in selector_counts.items()
            if sel not in KNOWN_SELECTORS and count >= 2
        ]

        anomaly_flags = self._detect_anomalies(
            callers=callers, selector_counts=selector_counts,
            unknown_selectors=unknown_selectors, large_value_txs=large_value_txs,
            new_contract_callers=new_contract_callers, total_txns=len(txns),
        )

        anomaly_score = min(1.0, len(anomaly_flags) * 0.2)

        return {
            "address": address,
            "tx_count_analyzed": len(txns),
            "unique_callers": len(callers),
            "selector_distribution": dict(selector_counts.most_common(10)),
            "unknown_selectors": unknown_selectors,
            "large_value_txs": large_value_txs[:5],
            "anomaly_flags": anomaly_flags,
            "anomaly_score": round(anomaly_score, 2),
            "error": None,
        }

    def _detect_anomalies(self, callers, selector_counts, unknown_selectors,
                          large_value_txs, new_contract_callers, total_txns) -> list[str]:
        flags: list[str] = []

        if unknown_selectors and len(callers) > 10:
            flags.append(
                f"AM1/AM3: {len(unknown_selectors)} unknown function selector(s) called "
                f"by {len(callers)} distinct addresses — possible unguarded function"
            )
        if large_value_txs:
            flags.append(
                f"AM2: {len(large_value_txs)} transaction(s) moved >=1 ETH — "
                f"review caller authorization"
            )
        if total_txns >= 10:
            unique_ratio = len(callers) / total_txns
            if unique_ratio < 0.1:
                flags.append(
                    "AM3: >90% of calls from same address — tx.origin whitelist pattern possible"
                )
        if new_contract_callers:
            flags.append(
                f"AM5: {len(new_contract_callers)} call(s) from newly deployed contracts — "
                f"callback exploitation pattern"
            )
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
            "address": address, "tx_count_analyzed": 0, "unique_callers": 0,
            "selector_distribution": {}, "unknown_selectors": [],
            "large_value_txs": [], "anomaly_flags": [],
            "anomaly_score": 0.0, "error": error,
        }
