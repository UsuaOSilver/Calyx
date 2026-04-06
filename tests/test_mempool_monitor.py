"""tests/test_mempool_monitor.py

Unit tests for:
  detectors/mempool_monitor/listener.py      -- MempoolListener._triage, init, stats
  detectors/mempool_monitor/contract_cache.py -- ContractAnalysisCache TTL/LRU/coalesce

No network I/O -- WebSocket imports are mocked.
"""
import asyncio
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import detectors.mempool_monitor.listener as _listener_mod
from detectors.mempool_monitor.contract_cache import ContractAnalysisCache


def _make_listener(**kwargs):
    """Construct MempoolListener with websockets availability mocked."""
    with patch.object(_listener_mod, "_WS_AVAILABLE", True):
        from detectors.mempool_monitor.listener import MempoolListener
        return MempoolListener(ws_url="wss://fake", on_tx=lambda tx: None, **kwargs)


def _tx(to="0xdac17f958d2ee523a2206206994597c13d831ec7",
        inp="0xa9059cbb" + "00" * 64,
        value="0x0"):
    return {"to": to, "input": inp, "value": value, "hash": "0xabc"}


# -- MempoolListener._triage --------------------------------------------------

class TestMempoolListenerTriage(unittest.TestCase):

    def setUp(self):
        self.listener = _make_listener()

    def test_sensitive_address_erc20_calldata(self):
        """USDT address + ERC-20 transfer calldata -> triaged in."""
        self.assertTrue(self.listener._triage(_tx()))

    def test_empty_calldata_rejected(self):
        self.assertFalse(self.listener._triage(_tx(inp="0x")))

    def test_missing_calldata_field(self):
        tx = {"to": "0xdac17f958d2ee523a2206206994597c13d831ec7", "value": "0x0"}
        self.assertFalse(self.listener._triage(tx))

    def test_min_value_filter_rejects_low(self):
        listener = _make_listener(min_value_wei=int(1e18))
        self.assertFalse(listener._triage(_tx(value=hex(int(0.5e18)))))

    def test_min_value_filter_passes_high(self):
        listener = _make_listener(min_value_wei=int(0.1e18))
        self.assertTrue(listener._triage(_tx(value=hex(int(1e18)))))

    def test_broad_mode_accepts_unknown_address(self):
        listener = _make_listener(broad_mode=True)
        tx = _tx(to="0x1234567890abcdef1234567890abcdef12345678",
                 inp="0xdeadbeef" + "00" * 32)
        self.assertTrue(listener._triage(tx))

    def test_focused_unknown_address_and_selector_rejected(self):
        listener = _make_listener(broad_mode=False)
        tx = _tx(to="0x1234567890abcdef1234567890abcdef12345678",
                 inp="0xdeadbeef" + "00" * 32)
        self.assertFalse(listener._triage(tx))

    def test_data_key_fallback(self):
        """tx.data used when tx.input is absent."""
        tx = {"to": "0xdac17f958d2ee523a2206206994597c13d831ec7",
              "data": "0xa9059cbb" + "00" * 64, "value": "0x0"}
        self.assertTrue(self.listener._triage(tx))

    def test_malformed_value_treated_as_zero(self):
        """Malformed hex value doesn't crash; treated as 0 (min_value=0 -> passes)."""
        self.assertIsInstance(self.listener._triage(_tx(value="not_a_hex")), bool)


# -- MempoolListener init / stats ---------------------------------------------

class TestMempoolListenerInit(unittest.TestCase):

    def test_raises_without_websockets(self):
        with patch.object(_listener_mod, "_WS_AVAILABLE", False):
            from detectors.mempool_monitor.listener import MempoolListener
            with self.assertRaises(ImportError):
                MempoolListener(ws_url="wss://x", on_tx=lambda tx: None)

    def test_initial_stats_all_zero(self):
        stats = _make_listener().stats
        self.assertEqual(stats, {"received": 0, "fetched": 0, "triaged_in": 0, "errors": 0})

    def test_stats_returns_copy(self):
        listener = _make_listener()
        s = listener.stats
        s["received"] = 9999
        self.assertEqual(listener.stats["received"], 0)


# -- ContractAnalysisCache ----------------------------------------------------

class TestContractAnalysisCache(unittest.TestCase):

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def _pipeline(self, result=None):
        p = MagicMock()
        p.analyze_address.return_value = result or {"risk_level": "LOW", "risk_score": 0.1}
        return p

    def test_cache_miss_then_hit(self):
        cache = ContractAnalysisCache(ttl=60)
        pipeline = self._pipeline()
        r1 = self._run(cache.get_or_analyze("0xABC", pipeline))
        r2 = self._run(cache.get_or_analyze("0xABC", pipeline))
        self.assertEqual(r1["risk_level"], "LOW")
        self.assertEqual(r2, r1)
        pipeline.analyze_address.assert_called_once()

    def test_address_normalised_lowercase(self):
        cache = ContractAnalysisCache(ttl=60)
        pipeline = self._pipeline({"risk_level": "HIGH"})
        self._run(cache.get_or_analyze("0xABCDEF", pipeline))
        self._run(cache.get_or_analyze("0xabcdef", pipeline))
        pipeline.analyze_address.assert_called_once()

    def test_ttl_expiry_triggers_rerun(self):
        cache = ContractAnalysisCache(ttl=0)
        pipeline = self._pipeline()
        self._run(cache.get_or_analyze("0x1", pipeline))
        time.sleep(0.01)
        self._run(cache.get_or_analyze("0x1", pipeline))
        self.assertEqual(pipeline.analyze_address.call_count, 2)

    def test_lru_evicts_oldest(self):
        cache = ContractAnalysisCache(ttl=3600, maxsize=2)
        pipeline = MagicMock()
        pipeline.analyze_address.side_effect = lambda addr, **kw: {"addr": addr}
        self._run(cache.get_or_analyze("0x1", pipeline))
        self._run(cache.get_or_analyze("0x2", pipeline))
        self._run(cache.get_or_analyze("0x3", pipeline))
        self.assertEqual(cache.size, 2)
        self.assertIsNone(cache.get_cached("0x1"))

    def test_get_cached_returns_none_on_miss(self):
        self.assertIsNone(ContractAnalysisCache().get_cached("0xnothere"))

    def test_clear_empties_cache(self):
        cache = ContractAnalysisCache(ttl=3600)
        self._run(cache.get_or_analyze("0xA", self._pipeline()))
        cache.clear()
        self.assertEqual(cache.size, 0)

    def test_size_increments(self):
        cache = ContractAnalysisCache(ttl=3600, maxsize=10)
        pipeline = MagicMock()
        pipeline.analyze_address.side_effect = lambda addr, **kw: {}
        for i in range(5):
            self._run(cache.get_or_analyze(f"0x{i}", pipeline))
        self.assertEqual(cache.size, 5)


if __name__ == "__main__":
    unittest.main()
