"""
detectors/mempool_monitor/contract_cache.py

Thread-safe LRU cache for BytecodePipeline contract analysis results.

Avoids re-running the expensive 8-stage pipeline for the same contract
address within the TTL window.  Pipeline calls run in a ThreadPoolExecutor
so they never block the asyncio event loop.

Concurrent requests for the same address coalesce into a single pipeline run.

Usage:
    from analysis.bytecode_pipeline import BytecodePipeline
    from detectors.mempool_monitor.contract_cache import ContractAnalysisCache

    pipeline = BytecodePipeline()
    cache    = ContractAnalysisCache(ttl=3600, maxsize=500)
    result   = await cache.get_or_analyze("0x...", pipeline)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)


class ContractAnalysisCache:
    """
    LRU cache wrapping BytecodePipeline.analyze_address().

    Args:
        ttl:     Cache entry lifetime in seconds (default 3600 = 1 hour).
        maxsize: Maximum number of cached addresses (default 500).
        workers: ThreadPoolExecutor pool size for pipeline calls (default 4).
        audit:   Pass audit=True to BytecodePipeline (requires LLM key).
    """

    def __init__(
        self,
        ttl:     int  = 3600,
        maxsize: int  = 500,
        workers: int  = 4,
        audit:   bool = False,
    ) -> None:
        self._ttl      = ttl
        self._maxsize  = maxsize
        self._audit    = audit
        self._cache:   OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="calyx-pipeline",
        )
        self._locks: Dict[str, asyncio.Lock] = {}

    async def get_or_analyze(
        self,
        address:  str,
        pipeline: Any,
        network:  str = "ethereum",
    ) -> Dict[str, Any]:
        """Return cached result for address, or run the pipeline and cache it."""
        addr   = address.lower()
        cached = self._get(addr)
        if cached is not None:
            return cached
        if addr not in self._locks:
            self._locks[addr] = asyncio.Lock()
        async with self._locks[addr]:
            cached = self._get(addr)
            if cached is not None:
                return cached
            log.info(f"Cache miss -- running pipeline for {addr}")
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: pipeline.analyze_address(
                    addr, network=network, audit=self._audit
                ),
            )
            self._set(addr, result)
            return result

    def get_cached(self, address: str) -> Optional[Dict[str, Any]]:
        return self._get(address.lower())

    @property
    def size(self) -> int:
        return len(self._cache)

    def clear(self) -> None:
        self._cache.clear()

    def _get(self, addr: str) -> Optional[Dict[str, Any]]:
        entry = self._cache.get(addr)
        if entry is None:
            return None
        if time.monotonic() - entry["_cached_at"] > self._ttl:
            del self._cache[addr]
            return None
        self._cache.move_to_end(addr)
        return entry["result"]

    def _set(self, addr: str, result: Dict[str, Any]) -> None:
        if addr in self._cache:
            self._cache.move_to_end(addr)
        self._cache[addr] = {"result": result, "_cached_at": time.monotonic()}
        while len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)
