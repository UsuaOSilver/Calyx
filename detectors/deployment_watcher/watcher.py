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
_DEFAULT_LOOKBACK_BLOCKS = 50     # how many blocks to scan on first run
_MAX_CREATIONS_PER_POLL = 50      # cap per poll cycle to avoid runaway
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

    # ── Etherscan queries ─────────────────────────────────────────────────────

    def _get_recent_creations(
        self,
        from_block: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Etherscan for recent contract creation transactions.

        Uses two approaches:
        1. Internal transactions (txlistinternal) with type=create
           — catches CREATE/CREATE2 from factory contracts
        2. Normal transactions (txlist) where to="" (direct deployments)

        Returns list of:
          {"address": str, "deployer": str, "tx_hash": str, "block_number": int}
        """
        creations: List[Dict[str, Any]] = []
        seen_addrs: Set[str] = set()

        start_block = from_block or 0

        # ── Approach 1: internal txns (catches factory deploys) ──────────
        try:
            params = {
                "module": "account",
                "action": "txlistinternal",
                "startblock": start_block,
                "endblock": 99999999,
                "page": 1,
                "offset": _MAX_CREATIONS_PER_POLL,
                "sort": "desc",
                "apikey": self._client.api_key,
            }
            import requests
            resp = requests.get(self._client.base_url, params=params, timeout=15)
            data = resp.json()

            if data.get("status") == "1" and data.get("result"):
                for tx in data["result"]:
                    # Internal create transactions have type "create" or "create2"
                    # and a non-empty contractAddress field
                    tx_type = tx.get("type", "").lower()
                    contract_addr = tx.get("contractAddress", "").lower()

                    if tx_type in ("create", "create2") and contract_addr:
                        if contract_addr not in seen_addrs:
                            seen_addrs.add(contract_addr)
                            creations.append({
                                "address": contract_addr,
                                "deployer": tx.get("from", "").lower(),
                                "tx_hash": tx.get("hash", ""),
                                "block_number": _safe_int(tx.get("blockNumber", "0")),
                            })
        except Exception as exc:
            log.debug(f"Internal txlist query failed: {exc}")

        # ── Approach 2: normal txns where to="" (direct EOA deploys) ─────
        # This is less reliable for high-volume monitoring but catches
        # the common case of a deployer EOA creating a contract directly.
        # Skipped if we already found creations from internal txns,
        # since most factory deploys are the interesting ones.
        if not creations:
            try:
                # Use a broader query — look for transactions to null address
                # This requires knowing the deployer address, which we don't have
                # in a general monitoring context. For now, we rely on approach 1.
                # A future enhancement would subscribe to block events directly.
                pass
            except Exception:
                pass

        return creations[:_MAX_CREATIONS_PER_POLL]

    def _get_latest_block(self) -> Optional[int]:
        """Get the current block number from Etherscan."""
        try:
            import requests
            params = {
                "module": "proxy",
                "action": "eth_blockNumber",
                "apikey": self._client.api_key,
            }
            resp = requests.get(self._client.base_url, params=params, timeout=10)
            data = resp.json()
            result = data.get("result", "0x0")
            if isinstance(result, str) and result.startswith("0x"):
                return int(result, 16)
            return None
        except Exception as exc:
            log.debug(f"eth_blockNumber query failed: {exc}")
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
