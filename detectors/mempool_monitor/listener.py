"""
detectors/mempool_monitor/listener.py

Async WebSocket listener for Ethereum mempool transactions.

Connects via eth_subscribe("newPendingTransactions"), fetches full tx details,
and calls on_tx() for any transaction matching the triage filter:

  Focused mode (default):
    - tx.to in SKANF SENSITIVE_ADDRESSES_ETH (50 DeFi token addresses), OR
    - tx.input selector in ERC-20 transfer/approve/transferFrom
    AND tx.input != "0x"  AND  tx.value >= min_value_wei

  Broad mode (--all-contracts):
    - Any tx with non-empty calldata AND tx.value >= min_value_wei

Usage:
    import asyncio
    from detectors.mempool_monitor.listener import MempoolListener

    async def handle(tx):
        print(tx["hash"], tx["to"])

    listener = MempoolListener(ws_url="wss://...", on_tx=handle)
    asyncio.run(listener.run())
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Dict, Optional

try:
    import websockets
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

from detectors.bytecode_analyzer.skanf_sensitive import is_sensitive_call

log = logging.getLogger(__name__)

_SUBSCRIBE_MSG = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "eth_subscribe",
    "params": ["newPendingTransactions"],
})


class MempoolListener:
    """
    Async WebSocket listener that triages Ethereum pending transactions
    and fires on_tx() for those matching SKANF sensitivity criteria.

    Reconnects automatically on disconnect.

    Args:
        ws_url:        WebSocket RPC URL
                       (e.g. wss://eth-mainnet.g.alchemy.com/v2/KEY).
        on_tx:         Async or sync callable invoked with full tx dict.
        min_value_wei: Minimum transaction value filter (default 0).
        broad_mode:    If True, triage ALL contract calls, not only
                       SKANF target addresses.
        max_inflight:  Max concurrent eth_getTransactionByHash requests.
    """

    def __init__(
        self,
        ws_url: str,
        on_tx: Callable[[Dict[str, Any]], Any],
        min_value_wei: int = 0,
        broad_mode: bool = False,
        max_inflight: int = 20,
    ) -> None:
        if not _WS_AVAILABLE:
            raise ImportError(
                "websockets is required for MempoolListener. "
                "Install it with: pip install 'websockets>=12.0'"
            )
        self.ws_url        = ws_url
        self.on_tx         = on_tx
        self.min_value_wei = min_value_wei
        self.broad_mode    = broad_mode
        self._sem          = asyncio.Semaphore(max_inflight)
        self._stats: Dict[str, int] = {
            "received":   0,
            "fetched":    0,
            "triaged_in": 0,
            "errors":     0,
        }

    async def run(self) -> None:
        """Stream pending transactions, reconnecting automatically on failure."""
        while True:
            try:
                await self._stream()
            except Exception as exc:
                log.warning(f"WebSocket disconnected ({exc}), reconnecting in 5s...")
                await asyncio.sleep(5)

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    async def _stream(self) -> None:
        log.info(f"Connecting to mempool WebSocket: {self.ws_url}")
        async with websockets.connect(self.ws_url, ping_interval=20) as ws:
            await ws.send(_SUBSCRIBE_MSG)
            ack    = json.loads(await ws.recv())
            sub_id = ack.get("result")
            log.info(f"Subscribed to newPendingTransactions (id={sub_id})")
            async for raw in ws:
                msg     = json.loads(raw)
                tx_hash = msg.get("params", {}).get("result")
                if not tx_hash:
                    continue
                self._stats["received"] += 1
                asyncio.create_task(self._handle_hash(ws, tx_hash))

    async def _handle_hash(self, ws: Any, tx_hash: str) -> None:
        async with self._sem:
            tx = await self._fetch_tx(ws, tx_hash)
            if tx is None:
                return
            self._stats["fetched"] += 1
            if not self._triage(tx):
                return
            self._stats["triaged_in"] += 1
            try:
                result = self.on_tx(tx)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                log.error(f"on_tx error for {tx_hash}: {exc}")
                self._stats["errors"] += 1

    async def _fetch_tx(self, ws: Any, tx_hash: str) -> Optional[Dict[str, Any]]:
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash],
        })
        try:
            await ws.send(req)
            resp = json.loads(await ws.recv())
            return resp.get("result")
        except Exception as exc:
            log.debug(f"Fetch failed for {tx_hash}: {exc}")
            self._stats["errors"] += 1
            return None

    def _triage(self, tx: Dict[str, Any]) -> bool:
        calldata  = tx.get("input") or tx.get("data") or "0x"
        value_hex = tx.get("value") or "0x0"
        if not calldata or calldata == "0x":
            return False
        try:
            value_wei = int(value_hex, 16)
        except (ValueError, TypeError):
            value_wei = 0
        if value_wei < self.min_value_wei:
            return False
        if self.broad_mode:
            return True
        to_addr  = (tx.get("to") or "").lower()
        selector = calldata[2:10] if len(calldata) >= 10 else ""
        return is_sensitive_call(to_addr, selector)
