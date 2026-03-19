"""
tests/test_integration_real.py

Real-API integration tests for the Calyx pipeline.

These tests hit live external services (Etherscan free tier, Alchemy RPC).
They are gated on environment variables and auto-skipped when the keys are
not present (see conftest.py):

    ETHERSCAN_API_KEY   — required for all @pytest.mark.integration tests
    ETHEREUM_RPC_URL    — required for @pytest.mark.requires_anvil tests

LLM calls (AuditAgent) remain mocked even here — they cost money and are
non-deterministic; the real-API tests focus on the deterministic pipeline.

Reference contracts
-------------------
  known_mev_bot : 0x00000000003b3cc22af3ae1eac0440bcee416b40
      A well-studied MEV sandwich bot with documented AM1/AM2/AM5 patterns.
      Bytecode is public; Etherscan returns it via eth_getCode.

  known_clean   : 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48  (USDC)
      Canonical, audited ERC-20 — no exploit patterns expected.
"""

from __future__ import annotations

import os
import sys
import time
import unittest

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from integrations.etherscan_client import EtherscanClient

MEV_BOT   = "0x00000000003b3cc22af3ae1eac0440bcee416b40"
USDC_ADDR = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client() -> EtherscanClient:
    return EtherscanClient(api_key=os.environ.get("ETHERSCAN_API_KEY", ""))


def _pipeline():
    from analysis.bytecode_pipeline import BytecodePipeline
    return BytecodePipeline()


# ---------------------------------------------------------------------------
# EtherscanClient — live bytecode fetch
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestEtherscanClientLive(unittest.TestCase):
    """Tests that call the real Etherscan API."""

    @classmethod
    def setUpClass(cls):
        cls.client = _client()

    def _throttle(self):
        """Free tier: 5 req/s; add a short pause between tests."""
        time.sleep(0.25)

    def test_get_bytecode_mev_bot_returns_nonempty(self):
        self._throttle()
        result = self.client.get_bytecode(MEV_BOT)
        self.assertTrue(result["success"], msg=result.get("error"))
        self.assertTrue(result["is_contract"])
        self.assertGreater(len(result["bytecode"]), 2)

    def test_get_bytecode_mev_bot_starts_with_0x(self):
        self._throttle()
        result = self.client.get_bytecode(MEV_BOT)
        self.assertTrue(result["bytecode"].startswith("0x"))

    def test_get_bytecode_mev_bot_is_valid_hex(self):
        self._throttle()
        result = self.client.get_bytecode(MEV_BOT)
        raw = result["bytecode"][2:]
        bytes.fromhex(raw)   # raises ValueError if not valid hex

    def test_get_bytecode_usdc_is_contract(self):
        self._throttle()
        result = self.client.get_bytecode(USDC_ADDR)
        self.assertTrue(result["success"], msg=result.get("error"))
        self.assertTrue(result["is_contract"])

    def test_get_bytecode_eoa_returns_0x(self):
        """An EOA address has no bytecode."""
        self._throttle()
        eoa = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"   # vitalik.eth
        result = self.client.get_bytecode(eoa)
        # Graceful: success may be True but bytecode should be 0x / is_contract=False
        self.assertFalse(result.get("is_contract", True),
                         "EOA must not be flagged as contract")

    def test_get_transaction_list_mev_bot(self):
        self._throttle()
        result = self.client.get_transaction_list(MEV_BOT, limit=10)
        self.assertTrue(result["success"], msg=result.get("error"))
        self.assertLessEqual(len(result["transactions"]), 10)

    def test_transaction_list_has_expected_fields(self):
        self._throttle()
        result = self.client.get_transaction_list(MEV_BOT, limit=5)
        if result["success"] and result["transactions"]:
            tx = result["transactions"][0]
            for field in ("hash", "from", "to", "value", "blockNumber"):
                self.assertIn(field, tx, f"Missing field: {field}")

    def test_get_contract_info_returns_balance(self):
        self._throttle()
        result = self.client.get_contract_info(MEV_BOT)
        self.assertTrue(result["success"], msg=result.get("error"))
        # balance is a string wei amount
        int(result["balance"])   # must be parseable as integer

    def test_case_insensitive_address_normalization(self):
        """Upper-case address should produce same bytecode as lower-case."""
        self._throttle()
        r_lower = self.client.get_bytecode(MEV_BOT.lower())
        self._throttle()
        r_upper = self.client.get_bytecode(MEV_BOT.upper())
        self.assertEqual(r_lower["bytecode"].lower(), r_upper["bytecode"].lower())

    def test_get_bytecode_result_keys_present(self):
        self._throttle()
        result = self.client.get_bytecode(MEV_BOT)
        for key in ("success", "bytecode", "is_contract", "error"):
            self.assertIn(key, result, f"Missing key: {key}")


# ---------------------------------------------------------------------------
# BytecodePipeline.analyze_address — live end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestPipelineLiveAddress(unittest.TestCase):
    """End-to-end analyze_address() against real contracts."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.pipeline = _pipeline()
            cls.available = True
        except Exception:
            cls.available = False

    def _skip(self):
        if not self.available:
            self.skipTest("BytecodePipeline dependencies not installed")

    def _throttle(self):
        time.sleep(0.5)   # be gentle with free-tier Etherscan

    def test_analyze_address_mev_bot_returns_dict(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertIsInstance(result, dict)

    def test_analyze_address_mev_bot_has_required_keys(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        for key in ("risk_score", "risk_level", "am_findings",
                    "am_types_found", "confirmed_exploits", "error"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_analyze_address_mev_bot_risk_score_in_range(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertGreaterEqual(result["risk_score"], 0.0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_analyze_address_mev_bot_not_low_risk(self):
        """Known MEV bot must be rated at least MEDIUM."""
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertNotEqual(result["risk_level"], "LOW",
                            msg=f"Unexpected LOW risk for MEV bot: {result}")

    def test_analyze_address_mev_bot_no_error(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertIsNone(result.get("error"),
                          msg=f"Unexpected error: {result.get('error')}")

    def test_analyze_address_mev_bot_cfg_deob_keys(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertIn("cfg_deob", result)
        for key in ("resolved", "approximated", "block_count", "edge_count"):
            self.assertIn(key, result["cfg_deob"])

    def test_analyze_address_mev_bot_has_blocks(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertGreater(result["cfg_deob"]["block_count"], 0,
                           "Expected at least one CFG block for MEV bot")

    def test_analyze_address_mev_bot_detects_am_type(self):
        """MEV bot bytecode should trigger at least one AM pattern."""
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(MEV_BOT)
        self.assertGreater(len(result["am_types_found"]), 0,
                           msg=f"No AM types detected for known MEV bot: {result}")

    def test_analyze_address_usdc_returns_result(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(USDC_ADDR)
        self.assertIsInstance(result, dict)
        self.assertIn("risk_level", result)

    def test_analyze_address_usdc_no_error(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(USDC_ADDR)
        self.assertIsNone(result.get("error"),
                          msg=f"Unexpected error for USDC: {result.get('error')}")

    def test_analyze_address_usdc_risk_score_in_range(self):
        self._skip()
        self._throttle()
        result = self.pipeline.analyze_address(USDC_ADDR)
        score = result.get("risk_score", -1)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_analyze_address_invalid_returns_graceful_error(self):
        """A non-existent / EOA address must return a graceful error dict."""
        self._skip()
        # Not throttling — this call likely returns immediately (0x bytecode)
        result = self.pipeline.analyze_address(
            "0x0000000000000000000000000000000000000001"  # precompile
        )
        # Must return a dict with risk_level key (never raise an exception)
        self.assertIsInstance(result, dict)
        self.assertIn("risk_level", result)

    def test_analyze_address_no_api_key_returns_graceful_error(self):
        """Missing API key must not crash — just return a dict with an error."""
        self._skip()
        import unittest.mock as mock
        env_without_key = {k: v for k, v in os.environ.items()
                           if k != "ETHERSCAN_API_KEY"}
        with mock.patch.dict(os.environ, env_without_key, clear=True):
            result = self.pipeline.analyze_address(MEV_BOT)
        self.assertIsInstance(result, dict)
        self.assertIn("risk_level", result)


# ---------------------------------------------------------------------------
# EtherscanClient — bytecode pipeline using fetched hex (no address lookup)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestPipelineLiveBytecode(unittest.TestCase):
    """Fetch bytecode manually, then run analyze_bytecode() — no address path."""

    @classmethod
    def setUpClass(cls):
        cls.client = _client()
        try:
            cls.pipeline = _pipeline()
            cls.pipeline_available = True
        except Exception:
            cls.pipeline_available = False

        # Pre-fetch once; share across all tests in this class
        r = cls.client.get_bytecode(MEV_BOT)
        cls.mev_bytecode = r["bytecode"] if r["success"] else None

    def _skip_pipeline(self):
        if not self.pipeline_available:
            self.skipTest("BytecodePipeline dependencies not installed")

    def test_fetched_bytecode_is_nonempty(self):
        self.assertIsNotNone(self.mev_bytecode, "Bytecode fetch failed")
        self.assertGreater(len(self.mev_bytecode), 2)

    def test_analyze_fetched_bytecode_returns_dict(self):
        self._skip_pipeline()
        if not self.mev_bytecode:
            self.skipTest("No bytecode available")
        result = self.pipeline.analyze_bytecode(self.mev_bytecode)
        self.assertIsInstance(result, dict)

    def test_analyze_fetched_bytecode_risk_score_in_range(self):
        self._skip_pipeline()
        if not self.mev_bytecode:
            self.skipTest("No bytecode available")
        result = self.pipeline.analyze_bytecode(self.mev_bytecode)
        self.assertGreaterEqual(result["risk_score"], 0.0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_analyze_fetched_bytecode_not_low_risk(self):
        """MEV bot bytecode should not be rated LOW even without address context."""
        self._skip_pipeline()
        if not self.mev_bytecode:
            self.skipTest("No bytecode available")
        result = self.pipeline.analyze_bytecode(self.mev_bytecode)
        self.assertNotEqual(result["risk_level"], "LOW",
                            msg=f"Unexpected LOW risk for MEV bot bytecode: {result}")

    def test_analyze_fetched_bytecode_has_cfg_blocks(self):
        self._skip_pipeline()
        if not self.mev_bytecode:
            self.skipTest("No bytecode available")
        result = self.pipeline.analyze_bytecode(self.mev_bytecode)
        self.assertGreater(result["cfg_deob"]["block_count"], 0)

    def test_analyze_fetched_bytecode_finds_am_pattern(self):
        self._skip_pipeline()
        if not self.mev_bytecode:
            self.skipTest("No bytecode available")
        result = self.pipeline.analyze_bytecode(self.mev_bytecode)
        self.assertGreater(len(result["am_types_found"]), 0,
                           "Expected AM patterns in MEV bot bytecode")


if __name__ == "__main__":
    unittest.main()
