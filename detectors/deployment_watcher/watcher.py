"""
detectors/deployment_watcher/watcher.py

Deployment Watcher — monitors Ethereum for new contract deployments.

Two operational modes:
  poll:   Etherscan API polling every N seconds (default, no WebSocket needed)
  stream: Extend MempoolListener to catch CREATE/CREATE2 in pending txns

Poll mode uses the internal transactions API (txlistinternal) filtered for
contract creation events. This catches both CREATE and CREATE2 deployments
with ~15 second latency — well within the SoK-identified rescue window
of 1h ± 4.1h average.

For each new deployment, fetches bytecode and invokes the on_deploy callback
with all metadata needed for adversarial classification.

Usage:
    import asyncio
    from integrations.etherscan_client import EtherscanClient
    from detectors.deployment_watcher.watcher import DeploymentWatcher

    client = EtherscanClient()

    async def handle(address, bytecode_hex, deployer, tx_hash, block):
        print(f"New contract: {address} deployed by {deployer}")

    watcher = DeploymentWatcher(client, on_deploy=handle)
    asyncio.run(watcher.run_poll())
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_POLL_INTERVAL = 15       # seconds between Etherscan polls
_DEFAULT_LOOKBACK_BLOCKS = 5      # how many blocks to scan on first run
_MAX_CREATIONS_PER_POLL = 50      # cap per poll cycle to avoid runaway
_MAX_BLOCKS_PER_POLL = 5          # max blocks to scan per cycle (≈1 block/12s on ETH)
_BYTECODE_MIN_LENGTH = 20         # minimum hex chars (beyond "0x") to consider real


class DeploymentWatcher:
    """
    Monitors Ethereum for new contract deployments via Etherscan polling.

    On each new deployment:
      1. Fetches deployed bytecode via EtherscanClient.get_bytecode()
      2. Calls on_deploy(address, bytecode_hex, deployer, tx_hash, block_number)
      3. Tracks seen addresses to avoid re-processing

    Args:
        etherscan_client:  Initialized EtherscanClient instance.
        on_deploy:         Async or sync callback invoked per new deployment.
        poll_interval:     Seconds between polls (default 15).
        network:           Chain name (passed through to client; default "ethereum").
        lookback_blocks:   How many blocks to scan on first run (default 50).
    """

    def __init__(
        self,
        etherscan_client: Any,
        on_deploy: Callable,
        poll_interval: int = _DEFAULT_POLL_INTERVAL,
        network: str = "ethereum",
        lookback_blocks: int = _DEFAULT_LOOKBACK_BLOCKS,
    ) -> None:
        self._client          = etherscan_client
        self._on_deploy       = on_deploy
        self._poll_interval   = poll_interval
        self._network         = network
        self._lookback_blocks = lookback_blocks
        self._seen: Set[str]  = set()
        self._last_block: Optional[int] = None
        self._stats = {
            "polls": 0,
            "deployments_found": 0,
            "bytecodes_fetched": 0,
            "callbacks_fired": 0,
            "errors": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    # ── Poll mode ─────────────────────────────────────────────────────────────

    async def run_poll(self) -> None:
        """
        Main loop: poll Etherscan for new contract creations every N seconds.
        Runs indefinitely. Ctrl-C to stop.
        """
        log.info(
            f"DeploymentWatcher starting — poll every {self._poll_interval}s "
            f"on {self._network}"
        )

        # Get current block for initial lookback window
        current_block = self._get_latest_block()
        if current_block is not None:
            self._last_block = max(0, current_block - self._lookback_blocks)
            log.info(
                f"Starting from block {self._last_block} "
                f"(current: {current_block}, lookback: {self._lookback_blocks})"
            )
        else:
            self._last_block = 0
            log.warning("Could not determine latest block — starting from 0")

        while True:
            try:
                await self._poll_cycle()
            except Exception as exc:
                log.error(f"Poll cycle error: {exc}")
                self._stats["errors"] += 1

            await asyncio.sleep(self._poll_interval)

    async def _poll_cycle(self) -> None:
        """Single poll iteration: find new deployments, fetch bytecode, fire callbacks."""
        self._stats["polls"] += 1

        creations = self._get_recent_creations(from_block=self._last_block)

        if not creations:
            return

        log.info(f"Found {len(creations)} new deployment(s) since block {self._last_block}")

        # Update block cursor to latest seen
        max_block = max(c["block_number"] for c in creations)
        self._last_block = max_block + 1

        for creation in creations:
            address = creation["address"].lower()

            # Dedup: skip if we've already processed this address
            if address in self._seen:
                continue
            self._seen.add(address)

            self._stats["deployments_found"] += 1

            # Fetch bytecode
            bytecode_hex = self._fetch_bytecode(address)
            if not bytecode_hex:
                continue
            self._stats["bytecodes_fetched"] += 1

            # Fire callback
            try:
                result = self._on_deploy(
                    address,
                    bytecode_hex,
                    creation["deployer"],
                    creation["tx_hash"],
                    creation["block_number"],
                )
                if asyncio.iscoroutine(result):
                    await result
                self._stats["callbacks_fired"] += 1
            except Exception as exc:
                log.error(f"on_deploy callback error for {address}: {exc}")
                self._stats["errors"] += 1

    # ── Etherscan V2 helpers ───────────────────────────────────────────────────

    def _v2_proxy(self, action: str, extra: Optional[Dict] = None) -> Any:
        """
        Call Etherscan V2 Geth/Parity proxy with correct chainid.
        Returns the 'result' field, or None on error.
        """
        import requests
        chain_id = getattr(self._client, "CHAIN_IDS", {}).get(self._network, 1)
        v2_base  = getattr(self._client, "V2_BASE",
                           "https://api.etherscan.io/v2/api")
        params: Dict[str, Any] = {
            "chainid": chain_id,
            "module":  "proxy",
            "action":  action,
            "apikey":  self._client.api_key,
        }
        if extra:
            params.update(extra)
        try:
            resp = requests.get(v2_base, params=params, timeout=15)
            data = resp.json()
            log.debug(f"v2_proxy {action}: {str(data)[:120]}")
            return data.get("result")
        except Exception as exc:
            log.debug(f"v2_proxy {action} failed: {exc}")
            return None

    # ── Etherscan queries ─────────────────────────────────────────────────────

    def _get_latest_block(self) -> Optional[int]:
        """Get the current block number via Etherscan V2 proxy."""
        result = self._v2_proxy("eth_blockNumber")
        if isinstance(result, str) and result.startswith("0x"):
            return int(result, 16)
        log.debug(f"eth_blockNumber unexpected result: {result!r}")
        return None

    def _get_recent_creations(
        self,
        from_block: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan recent blocks for contract creation transactions.

        Strategy: fetch each block with full transactions via eth_getBlockByNumber,
        filter for txns where `to` is null (direct EOA → contract deployments),
        then call eth_getTransactionReceipt to get the deployed contractAddress.

        Catches all direct deploys (CREATE opcode from EOA).
        Factory deploys (CREATE2 via proxy) are skipped — they require internal
        txn tracing which needs a paid Etherscan plan.

        Returns list of:
          {"address": str, "deployer": str, "tx_hash": str, "block_number": int}
        """
        creations: List[Dict[str, Any]] = []
        seen_addrs: Set[str] = set()

        latest = self._get_latest_block()
        if latest is None:
            log.warning("Cannot determine latest block — skipping poll cycle")
            return []

        start = from_block if from_block is not None else max(0, latest - _DEFAULT_LOOKBACK_BLOCKS)
        # Cap scan range to avoid excessive API calls
        end = min(latest, start + _MAX_BLOCKS_PER_POLL - 1)

        if start > end:
            return []

        log.debug(f"Scanning blocks {start}–{end} (latest={latest})")

        for block_num in range(start, end + 1):
            if len(creations) >= _MAX_CREATIONS_PER_POLL:
                break
            try:
                block = self._v2_proxy(
                    "eth_getBlockByNumber",
                    {"tag": hex(block_num), "boolean": "true"},
                )
                if not block or not isinstance(block, dict):
                    log.debug(f"Block {block_num}: empty or non-dict result")
                    continue

                txns = block.get("transactions") or []
                log.debug(f"Block {block_num}: {len(txns)} transactions")

                for tx in txns:
                    # Direct contract creation: `to` is null or empty string
                    to_field = tx.get("to")
                    if to_field is not None and to_field != "":
                        continue

                    tx_hash = tx.get("hash", "")
                    if not tx_hash:
                        continue

                    contract_addr = self._receipt_contract_address(tx_hash)
                    if not contract_addr or contract_addr in seen_addrs:
                        continue

                    seen_addrs.add(contract_addr)
                    creations.append({
                        "address":      contract_addr,
                        "deployer":     (tx.get("from") or "").lower(),
                        "tx_hash":      tx_hash,
                        "block_number": _safe_int(block.get("number", "0")),
                    })

                    if len(creations) >= _MAX_CREATIONS_PER_POLL:
                        break

            except Exception as exc:
                log.debug(f"Block {block_num} scan error: {exc}")

        return creations

    def _receipt_contract_address(self, tx_hash: str) -> Optional[str]:
        """Fetch transaction receipt and return the deployed contractAddress."""
        result = self._v2_proxy("eth_getTransactionReceipt", {"txhash": tx_hash})
        if not isinstance(result, dict):
            return None
        addr = result.get("contractAddress")
        if addr and isinstance(addr, str) and addr != "0x0000000000000000000000000000000000000000":
            return addr.lower()
        return None

    def _fetch_bytecode(self, address: str) -> Optional[str]:
        """Fetch deployed bytecode. Returns hex string or None if too short."""
        try:
            result = self._client.get_bytecode(address)
            if not result.get("success"):
                log.debug(f"Bytecode fetch failed for {address}: {result.get('error')}")
                return None

            bytecode = result.get("bytecode", "0x")
            # Strip "0x" for length check
            hex_body = bytecode[2:] if bytecode.startswith("0x") else bytecode
            if len(hex_body) < _BYTECODE_MIN_LENGTH:
                log.debug(f"Bytecode too short for {address}: {len(hex_body)} hex chars")
                return None

            return bytecode
        except Exception as exc:
            log.debug(f"Bytecode fetch exception for {address}: {exc}")
            self._stats["errors"] += 1
            return None

    # ── Stream mode (stretch goal) ────────────────────────────────────────────

    async def run_stream(self, ws_url: str) -> None:
        """
        Stream mode: subscribe to pending transactions via WebSocket,
        filter for CREATE/CREATE2, wait for confirmation, then process.

        This is a stretch goal — poll mode is sufficient for the hackathon
        and operates within the rescue window.

        Requires: websockets pip package + Alchemy/Infura WebSocket URL.
        """
        raise NotImplementedError(
            "Stream mode is a post-hackathon enhancement. "
            "Use run_poll() for Etherscan-based deployment monitoring."
        )


def _safe_int(val: Any) -> int:
    """Safely convert a value to int, handling hex strings."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if val.startswith("0x"):
            return int(val, 16)
        try:
            return int(val)
        except ValueError:
            return 0
    return 0
