"""
tests/test_deployment_watcher.py

Unit tests for DeploymentWatcher — all Etherscan calls are mocked.
No API key, no network access needed.
"""

from __future__ import annotations

import asyncio
import sys
import os
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.deployment_watcher.watcher import DeploymentWatcher, _safe_int


# ── Mock helpers ──────────────────────────────────────────────────────────────

def _mock_client(bytecode="0x" + "60806040" * 50):
    """Create a mock EtherscanClient."""
    client = MagicMock()
    client.api_key = "test_key"
    client.base_url = "https://api.etherscan.io/api"
    client.get_bytecode.return_value = {
        "success": True,
        "bytecode": bytecode,
        "is_contract": True,
        "error": None,
    }
    return client


def _mock_internal_txns_response(creations):
    """Build a mock requests.get response for txlistinternal."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "1",
        "result": [
            {
                "type": c.get("type", "create"),
                "contractAddress": c["address"],
                "from": c.get("deployer", "0xdeployer"),
                "hash": c.get("tx_hash", "0xhash123"),
                "blockNumber": str(c.get("block_number", 19000000)),
            }
            for c in creations
        ],
    }
    return mock_resp


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSafeInt(unittest.TestCase):
    def test_int_passthrough(self):
        self.assertEqual(_safe_int(42), 42)

    def test_decimal_string(self):
        self.assertEqual(_safe_int("19000000"), 19000000)

    def test_hex_string(self):
        self.assertEqual(_safe_int("0x1234"), 0x1234)

    def test_invalid_string(self):
        self.assertEqual(_safe_int("not_a_number"), 0)

    def test_none(self):
        self.assertEqual(_safe_int(None), 0)


class TestDeploymentWatcherInit(unittest.TestCase):
    def test_creates_with_defaults(self):
        w = DeploymentWatcher(_mock_client(), on_deploy=lambda *a: None)
        self.assertIsNotNone(w)

    def test_initial_stats_all_zero(self):
        w = DeploymentWatcher(_mock_client(), on_deploy=lambda *a: None)
        stats = w.stats
        self.assertEqual(stats["polls"], 0)
        self.assertEqual(stats["deployments_found"], 0)
        self.assertEqual(stats["errors"], 0)

    def test_stats_returns_copy(self):
        w = DeploymentWatcher(_mock_client(), on_deploy=lambda *a: None)
        s = w.stats
        s["polls"] = 9999
        self.assertEqual(w.stats["polls"], 0)


class TestGetRecentCreations(unittest.TestCase):
    def test_finds_create_transactions(self):
        client = _mock_client()
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnewcontract1", "type": "create", "block_number": 19000100},
            {"address": "0xnewcontract2", "type": "create2", "block_number": 19000101},
        ])

        with patch("requests.get", return_value=mock_resp):
            creations = w._get_recent_creations(from_block=19000000)

        self.assertEqual(len(creations), 2)
        self.assertEqual(creations[0]["address"], "0xnewcontract1")
        self.assertEqual(creations[1]["address"], "0xnewcontract2")

    def test_ignores_non_create_transactions(self):
        client = _mock_client()
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnewcontract1", "type": "create", "block_number": 19000100},
            {"address": "0xnotacreate", "type": "call", "block_number": 19000102},
        ])

        with patch("requests.get", return_value=mock_resp):
            creations = w._get_recent_creations(from_block=19000000)

        self.assertEqual(len(creations), 1)

    def test_returns_empty_on_api_error(self):
        client = _mock_client()
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "0", "result": None}

        with patch("requests.get", return_value=mock_resp):
            creations = w._get_recent_creations(from_block=19000000)

        self.assertEqual(len(creations), 0)

    def test_deduplicates_same_address(self):
        client = _mock_client()
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        mock_resp = _mock_internal_txns_response([
            {"address": "0xsame", "type": "create", "block_number": 19000100},
            {"address": "0xsame", "type": "create", "block_number": 19000101},
        ])

        with patch("requests.get", return_value=mock_resp):
            creations = w._get_recent_creations(from_block=19000000)

        self.assertEqual(len(creations), 1)


class TestFetchBytecode(unittest.TestCase):
    def test_returns_bytecode_for_contract(self):
        client = _mock_client(bytecode="0x" + "aa" * 100)
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        result = w._fetch_bytecode("0xtest")
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("0x"))

    def test_returns_none_for_short_bytecode(self):
        client = _mock_client(bytecode="0x6080")  # too short
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        result = w._fetch_bytecode("0xtest")
        self.assertIsNone(result)

    def test_returns_none_on_fetch_failure(self):
        client = _mock_client()
        client.get_bytecode.return_value = {"success": False, "error": "not found"}
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)

        result = w._fetch_bytecode("0xtest")
        self.assertIsNone(result)


class TestPollCycle(unittest.TestCase):
    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_callback_fired_for_new_deployment(self):
        client = _mock_client()
        callback_calls = []

        def on_deploy(address, bytecode, deployer, tx_hash, block):
            callback_calls.append(address)

        w = DeploymentWatcher(client, on_deploy=on_deploy)
        w._last_block = 19000000

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnew1", "type": "create", "block_number": 19000100},
        ])

        with patch("requests.get", return_value=mock_resp):
            self._run(w._poll_cycle())

        self.assertEqual(len(callback_calls), 1)
        self.assertEqual(callback_calls[0], "0xnew1")

    def test_same_address_not_processed_twice(self):
        client = _mock_client()
        callback_calls = []

        def on_deploy(address, bytecode, deployer, tx_hash, block):
            callback_calls.append(address)

        w = DeploymentWatcher(client, on_deploy=on_deploy)
        w._last_block = 19000000

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnew1", "type": "create", "block_number": 19000100},
        ])

        with patch("requests.get", return_value=mock_resp):
            self._run(w._poll_cycle())
            self._run(w._poll_cycle())  # same data again

        # Should only be called once due to dedup
        self.assertEqual(len(callback_calls), 1)

    def test_poll_increments_stats(self):
        client = _mock_client()
        w = DeploymentWatcher(client, on_deploy=lambda *a: None)
        w._last_block = 19000000

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnew1", "type": "create", "block_number": 19000100},
        ])

        with patch("requests.get", return_value=mock_resp):
            self._run(w._poll_cycle())

        self.assertEqual(w.stats["polls"], 1)
        self.assertEqual(w.stats["deployments_found"], 1)
        self.assertEqual(w.stats["callbacks_fired"], 1)

    def test_async_callback_works(self):
        client = _mock_client()
        callback_calls = []

        async def on_deploy(address, bytecode, deployer, tx_hash, block):
            callback_calls.append(address)

        w = DeploymentWatcher(client, on_deploy=on_deploy)
        w._last_block = 19000000

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnew1", "type": "create", "block_number": 19000100},
        ])

        with patch("requests.get", return_value=mock_resp):
            self._run(w._poll_cycle())

        self.assertEqual(len(callback_calls), 1)

    def test_callback_error_increments_error_stat(self):
        client = _mock_client()

        def on_deploy(address, bytecode, deployer, tx_hash, block):
            raise ValueError("callback crashed")

        w = DeploymentWatcher(client, on_deploy=on_deploy)
        w._last_block = 19000000

        mock_resp = _mock_internal_txns_response([
            {"address": "0xnew1", "type": "create", "block_number": 19000100},
        ])

        with patch("requests.get", return_value=mock_resp):
            self._run(w._poll_cycle())

        self.assertEqual(w.stats["errors"], 1)


class TestStreamMode(unittest.TestCase):
    def test_stream_raises_not_implemented(self):
        w = DeploymentWatcher(_mock_client(), on_deploy=lambda *a: None)
        with self.assertRaises(NotImplementedError):
            asyncio.get_event_loop().run_until_complete(
                w.run_stream("wss://fake")
            )


if __name__ == "__main__":
    unittest.main()
