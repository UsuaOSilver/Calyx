"""
tests/test_skanf_sensitive.py

Tests for SKANF sensitive-address/signature constants and calldata helpers.

Coverage:
  - ERC-20 selector constants are correct 4-byte ABI hashes
  - is_sensitive_call() — address matching on ETH/BSC, selector matching
  - erc20_calldata() — transfer, approve, transferFrom payload structure
  - Address normalization (case-insensitive, with/without 0x prefix)
"""

from __future__ import annotations

import hashlib
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.bytecode_analyzer.skanf_sensitive import (
    ERC20_APPROVE,
    ERC20_TRANSFER,
    ERC20_TRANSFER_FROM,
    SENSITIVE_ADDRESSES_ALL,
    SENSITIVE_ADDRESSES_BSC,
    SENSITIVE_ADDRESSES_ETH,
    SENSITIVE_SIGNATURES,
    erc20_calldata,
    is_sensitive_call,
)

_WORD = 32
_MAX_UINT256 = 2**256 - 1
_ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


# ---------------------------------------------------------------------------
# Selector constants
# ---------------------------------------------------------------------------

class TestSelectorConstants(unittest.TestCase):

    def _keccak4(self, sig: str) -> str:
        """Compute the first 4 bytes of keccak256 of an ABI function signature."""
        from Crypto.Hash import keccak as pycryptokeccak
        try:
            k = pycryptokeccak.new(digest_bits=256)
            k.update(sig.encode())
            return k.hexdigest()[:8]
        except ImportError:
            # Fall back to sha3_256 for structure check only (not real keccak)
            return None

    def test_transfer_selector_is_4_bytes(self):
        self.assertEqual(len(ERC20_TRANSFER), 8)

    def test_approve_selector_is_4_bytes(self):
        self.assertEqual(len(ERC20_APPROVE), 8)

    def test_transfer_from_selector_is_4_bytes(self):
        self.assertEqual(len(ERC20_TRANSFER_FROM), 8)

    def test_selectors_are_lowercase_hex(self):
        for sel in (ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM):
            self.assertEqual(sel, sel.lower())
            # Must be valid hex
            bytes.fromhex(sel)

    def test_transfer_selector_known_value(self):
        self.assertEqual(ERC20_TRANSFER, "a9059cbb")

    def test_approve_selector_known_value(self):
        self.assertEqual(ERC20_APPROVE, "095ea7b3")

    def test_transfer_from_selector_known_value(self):
        self.assertEqual(ERC20_TRANSFER_FROM, "23b872dd")

    def test_selectors_all_distinct(self):
        sels = [ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM]
        self.assertEqual(len(sels), len(set(sels)))

    def test_sensitive_signatures_contains_selectors_with_and_without_prefix(self):
        for sel in (ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM):
            self.assertIn(sel, SENSITIVE_SIGNATURES)
            self.assertIn("0x" + sel, SENSITIVE_SIGNATURES)


# ---------------------------------------------------------------------------
# Address sets
# ---------------------------------------------------------------------------

class TestAddressSets(unittest.TestCase):

    def test_eth_addresses_are_lowercase(self):
        for addr in SENSITIVE_ADDRESSES_ETH:
            self.assertEqual(addr, addr.lower(), f"Not lowercase: {addr}")

    def test_bsc_addresses_are_lowercase(self):
        for addr in SENSITIVE_ADDRESSES_BSC:
            self.assertEqual(addr, addr.lower(), f"Not lowercase: {addr}")

    def test_all_addresses_have_0x_prefix(self):
        for addr in SENSITIVE_ADDRESSES_ALL:
            self.assertTrue(addr.startswith("0x"), f"Missing 0x prefix: {addr}")

    def test_all_set_is_union_of_eth_and_bsc(self):
        self.assertEqual(SENSITIVE_ADDRESSES_ALL, SENSITIVE_ADDRESSES_ETH | SENSITIVE_ADDRESSES_BSC)

    def test_usdt_eth_present(self):
        self.assertIn("0xdac17f958d2ee523a2206206994597c13d831ec7", SENSITIVE_ADDRESSES_ETH)

    def test_weth_eth_present(self):
        self.assertIn("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", SENSITIVE_ADDRESSES_ETH)

    def test_wbnb_bsc_present(self):
        self.assertIn("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", SENSITIVE_ADDRESSES_BSC)

    def test_minimum_address_counts(self):
        self.assertGreaterEqual(len(SENSITIVE_ADDRESSES_ETH), 40)
        self.assertGreaterEqual(len(SENSITIVE_ADDRESSES_BSC), 40)

    def test_no_duplicate_within_eth(self):
        # SENSITIVE_ADDRESSES_ETH is a frozenset — no duplicates possible, but validate construction
        self.assertIsInstance(SENSITIVE_ADDRESSES_ETH, frozenset)

    def test_addresses_are_valid_length(self):
        """All addresses must be exactly 42 chars (0x + 40 hex digits)."""
        for addr in SENSITIVE_ADDRESSES_ALL:
            self.assertEqual(len(addr), 42, f"Invalid length for {addr}")


# ---------------------------------------------------------------------------
# is_sensitive_call
# ---------------------------------------------------------------------------

class TestIsSensitiveCall(unittest.TestCase):

    def test_known_eth_address_returns_true(self):
        usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        self.assertTrue(is_sensitive_call(usdt, network="ethereum"))

    def test_known_eth_address_lowercase_returns_true(self):
        usdt_lower = "0xdac17f958d2ee523a2206206994597c13d831ec7"
        self.assertTrue(is_sensitive_call(usdt_lower, network="ethereum"))

    def test_known_eth_address_not_in_bsc_set(self):
        usdt_eth = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        self.assertFalse(is_sensitive_call(usdt_eth, network="bsc"))

    def test_known_bsc_address_returns_true_on_bsc(self):
        wbnb = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
        self.assertTrue(is_sensitive_call(wbnb, network="bsc"))

    def test_network_all_matches_both_chains(self):
        usdt_eth = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        wbnb_bsc = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
        self.assertTrue(is_sensitive_call(usdt_eth, network="all"))
        self.assertTrue(is_sensitive_call(wbnb_bsc, network="all"))

    def test_unknown_address_returns_false(self):
        unknown = "0x1234567890123456789012345678901234567890"
        self.assertFalse(is_sensitive_call(unknown))

    def test_erc20_transfer_selector_returns_true(self):
        self.assertTrue(is_sensitive_call(None, function_selector=ERC20_TRANSFER))

    def test_erc20_approve_selector_returns_true(self):
        self.assertTrue(is_sensitive_call(None, function_selector=ERC20_APPROVE))

    def test_erc20_transfer_from_selector_returns_true(self):
        self.assertTrue(is_sensitive_call(None, function_selector=ERC20_TRANSFER_FROM))

    def test_selector_with_0x_prefix_returns_true(self):
        self.assertTrue(is_sensitive_call(None, function_selector="0x" + ERC20_TRANSFER))

    def test_unknown_selector_returns_false(self):
        self.assertFalse(is_sensitive_call(None, function_selector="deadbeef"))

    def test_no_args_returns_false(self):
        self.assertFalse(is_sensitive_call(None))
        self.assertFalse(is_sensitive_call(None, function_selector=None))

    def test_address_without_0x_prefix_still_matches(self):
        """Addresses submitted without 0x should still be recognized."""
        usdt_no_prefix = "dAC17F958D2ee523a2206206994597C13D831ec7"
        # The function adds 0x if missing
        self.assertTrue(is_sensitive_call(usdt_no_prefix, network="ethereum"))

    def test_case_insensitive_address_matching(self):
        usdt_upper = "0xDAC17F958D2EE523A2206206994597C13D831EC7"
        self.assertTrue(is_sensitive_call(usdt_upper, network="ethereum"))

    def test_selector_case_insensitive(self):
        self.assertTrue(is_sensitive_call(None, function_selector=ERC20_TRANSFER.upper()))


# ---------------------------------------------------------------------------
# erc20_calldata
# ---------------------------------------------------------------------------

class TestErc20Calldata(unittest.TestCase):

    def test_transfer_payload_length(self):
        # selector(4) + attacker_padded(32) + max_uint256(32) = 68 bytes
        data = erc20_calldata(ERC20_TRANSFER, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(len(raw), 68)

    def test_transfer_selector_prefix(self):
        data = erc20_calldata(ERC20_TRANSFER, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(raw[:4], bytes.fromhex(ERC20_TRANSFER))

    def test_transfer_attacker_address_in_slot1(self):
        data = erc20_calldata(ERC20_TRANSFER, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        addr_int = int(_ATTACKER, 16)
        expected = addr_int.to_bytes(32, "big")
        self.assertEqual(raw[4:36], expected)

    def test_transfer_max_uint256_in_slot2(self):
        data = erc20_calldata(ERC20_TRANSFER, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(int.from_bytes(raw[36:68], "big"), _MAX_UINT256)

    def test_approve_payload_same_structure_as_transfer(self):
        data = erc20_calldata(ERC20_APPROVE, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(len(raw), 68)
        self.assertEqual(raw[:4], bytes.fromhex(ERC20_APPROVE))
        self.assertEqual(int.from_bytes(raw[36:68], "big"), _MAX_UINT256)

    def test_transfer_from_payload_length(self):
        # selector(4) + zero(32) + attacker(32) + max_uint256(32) = 100 bytes
        data = erc20_calldata(ERC20_TRANSFER_FROM, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(len(raw), 100)

    def test_transfer_from_selector_prefix(self):
        data = erc20_calldata(ERC20_TRANSFER_FROM, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(raw[:4], bytes.fromhex(ERC20_TRANSFER_FROM))

    def test_transfer_from_zero_slot(self):
        data = erc20_calldata(ERC20_TRANSFER_FROM, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(raw[4:36], bytes(32))

    def test_transfer_from_attacker_in_slot2(self):
        data = erc20_calldata(ERC20_TRANSFER_FROM, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        addr_int = int(_ATTACKER, 16)
        expected = addr_int.to_bytes(32, "big")
        self.assertEqual(raw[36:68], expected)

    def test_transfer_from_max_uint256_in_slot3(self):
        data = erc20_calldata(ERC20_TRANSFER_FROM, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(int.from_bytes(raw[68:100], "big"), _MAX_UINT256)

    def test_selector_with_0x_prefix_works(self):
        data = erc20_calldata("0x" + ERC20_TRANSFER, _ATTACKER)
        raw = bytes.fromhex(data[2:])
        self.assertEqual(raw[:4], bytes.fromhex(ERC20_TRANSFER))

    def test_output_is_0x_prefixed_hex(self):
        data = erc20_calldata(ERC20_TRANSFER, _ATTACKER)
        self.assertTrue(data.startswith("0x"))
        bytes.fromhex(data[2:])  # must not raise

    def test_address_leading_zeros_handled(self):
        """Very small addresses must still be padded to 32 bytes."""
        small_addr = "0x0000000000000000000000000000000000000001"
        data = erc20_calldata(ERC20_TRANSFER, small_addr)
        raw = bytes.fromhex(data[2:])
        expected = (1).to_bytes(32, "big")
        self.assertEqual(raw[4:36], expected)


if __name__ == "__main__":
    unittest.main()
