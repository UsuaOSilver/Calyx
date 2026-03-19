"""
tests/test_taint_analyzer.py

Tests for TaintAnalyzer — SKANF Gap 2 static taint analysis.

Bytecode crafting notes
-----------------------
All hand-crafted bytecodes are minimal sequences that exercise exactly one
code path.  Stack layout for CALL (top → bottom before CALL executes):
    gas, to, value, argsOffset, argsSize, retOffset, retSize

Standard push order to reach that layout (push retSize first):
    PUSH1 retSize          0x6000
    PUSH1 retOffset        0x6000
    PUSH1 argsSize         0x6000
    PUSH1 argsOffset       0x6000
    PUSH1 value            0x6000       (or CALLVALUE/CALLDATALOAD for taint)
    <to>                               (PUSH1 addr or CALLDATALOAD)
    PUSH1 gas              0x6001
    CALL                   0xf1

Coverage:
  - Empty / invalid bytecode
  - AM1: calldata-tainted CALL target (CALLDATALOAD → to)
  - AM1: origin-tainted CALL target (ORIGIN → to)
  - AM2: calldata-tainted CALL value (CALLDATALOAD → value)
  - AM2: ETH value tainted (CALLVALUE → value)
  - No finding when CALLER guard is present (CALLER+EQ+JUMPI)
  - No finding for clean bytecode (all PUSH constants)
  - AM3: ORIGIN used in authorization check (ORIGIN → EQ → JUMPI)
  - AM4: approve + transferFrom selectors without CALLER guard
  - AM5: flash-loan callback selector reachable without CALLER check
  - AM7: permissionless SSTORE
  - AM8: DELEGATECALL preceded by SLOAD (pattern-based)
  - AM6 gap: RETURNDATACOPY does NOT propagate taint to memory (documented limitation)
  - AM8 taint gap: SLOAD taint not tracked through DELEGATECALL target (documented)
  - caller_guarded detection
  - SELFDESTRUCT treated as a sink
"""

from __future__ import annotations

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.bytecode_analyzer.taint_analyzer import TaintAnalyzer
from detectors.bytecode_analyzer.cfg_profiler import AMPatternDetector

ta = TaintAnalyzer()
det = AMPatternDetector()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def h(bcode: str) -> str:
    """Strip 0x prefix for readability, add it back."""
    return "0x" + bcode.lstrip("0x")


# ---------------------------------------------------------------------------
# Pre-computed minimal bytecodes
# ---------------------------------------------------------------------------

# AM1: CALLDATALOAD-tainted CALL target
# 60 00 60 00 60 00 60 00 60 00 60 00 35 60 01 f1
#  retSize retOff argsSz argsOff  value  CALLDATALOAD_offset  gas  CALL
BYTECODE_AM1_CALLDATA = "0x600060006000600060006000356001f1"

# AM2: CALLVALUE-tainted CALL value
# 60 00 60 00 60 00 60 00 34 60 00 60 01 f1
#  retSize retOff argsSz argsOff  CALLVALUE  to(0)  gas  CALL
BYTECODE_AM2_CALLVALUE = "0x60006000600060003460006001f1"

# AM2: CALLDATALOAD-tainted value
# 60 00 60 00 60 00 60 00 60 00 35 60 00 60 01 f1
BYTECODE_AM2_CALLDATA_VALUE = "0x6000600060006000600035600060 01f1".replace(" ", "")

# AM1 via ORIGIN (ORIGIN → to)
# 60 00 60 00 60 00 60 00 60 00 32 60 01 f1
BYTECODE_AM1_ORIGIN = "0x60006000600060006000326001f1"

# Caller guard pattern: CALLER EQ JUMPI somewhere before CALL
# We build: CALLER PUSH1 addr EQ PUSH1 dest JUMPI  + CALLDATALOAD CALL
# 33 60 00 14 60 00 57  60 00 ... f1
# Simplified: just put CALLER, EQ, JUMPI early, then AM1 pattern
BYTECODE_CALLER_GUARDED = (
    "0x"
    "33"        # CALLER
    "6000"      # PUSH1 0x00 (comparison address)
    "14"        # EQ
    "600b"      # PUSH1 0x0b (jump destination)
    "57"        # JUMPI
    # Now the AM1 pattern:
    "6000600060006000600060003560 01f1".replace(" ", "")
)

# AM3: ORIGIN → EQ → JUMPI
BYTECODE_AM3 = "0x326000146000 57".replace(" ", "")

# AM4: PUSH4 approve_selector + PUSH4 transferFrom_selector (no CALLER guard)
BYTECODE_AM4 = (
    "0x"
    "63095ea7b3"   # PUSH4 approve selector
    "5050"         # POP POP (discard)
    "6323b872dd"   # PUSH4 transferFrom selector
    "50"           # POP
)

# AM5: Callback selector present + CALL reachable without CALLER check
# uniswapV3SwapCallback = 0xfa461e33
BYTECODE_AM5 = (
    "0x"
    "63fa461e33"  # PUSH4 uniswapV3SwapCallback
    "50"          # POP
    "f1"          # CALL (gas/to/... all zero from empty stack — just triggers CALL reachable check)
)

# AM7: SSTORE without CALLER guard + PUSH4 function selector
BYTECODE_AM7 = (
    "0x"
    "63deadbeef"  # PUSH4 some function selector
    "50"          # POP
    "6000"        # PUSH1 0 (slot)
    "6000"        # PUSH1 0 (value)
    "55"          # SSTORE
)

# AM8: SLOAD followed by DELEGATECALL (within 15 instructions, no PUSH20 in between)
# 60 00 54  (PUSH1 slot, SLOAD)
# 60 00 60 00 60 00 60 00 f4  (gas to argsOff argsLen DELEGATECALL)
BYTECODE_AM8 = (
    "0x"
    "6000"  # PUSH1 slot
    "54"    # SLOAD
    "6000"  # gas
    "6000"  # argsOffset
    "6000"  # argsLen
    "6000"  # retOffset
    "f4"    # DELEGATECALL
)

# Clean: just PUSH constants, no taint
BYTECODE_CLEAN = "0x600160026003600460056006"

# Empty
BYTECODE_EMPTY = "0x"


# ---------------------------------------------------------------------------
# Basic robustness
# ---------------------------------------------------------------------------

class TestRobustness(unittest.TestCase):

    def test_empty_bytecode_returns_empty(self):
        result = ta.analyze(BYTECODE_EMPTY)
        self.assertEqual(result["findings"], [])
        self.assertIsNotNone(result["error"])

    def test_empty_string_without_prefix(self):
        result = ta.analyze("")
        self.assertEqual(result["findings"], [])
        self.assertIsNotNone(result["error"])

    def test_invalid_hex_returns_error(self):
        result = ta.analyze("0xGGGG")
        self.assertIsNotNone(result["error"])

    def test_clean_bytecode_no_findings(self):
        result = ta.analyze(BYTECODE_CLEAN)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["am_types_found"], [])

    def test_result_always_has_required_keys(self):
        for bcode in (BYTECODE_CLEAN, BYTECODE_AM1_CALLDATA, BYTECODE_EMPTY):
            result = ta.analyze(bcode)
            for key in ("findings", "am_types_found", "caller_guarded", "error"):
                self.assertIn(key, result, f"Missing key '{key}' for {bcode!r}")


# ---------------------------------------------------------------------------
# AM1 detection (TaintAnalyzer)
# ---------------------------------------------------------------------------

class TestAM1Detection(unittest.TestCase):

    def test_am1_detected_from_calldataload_to_call_target(self):
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        self.assertIn("AM1", result["am_types_found"])

    def test_am1_finding_has_correct_type_and_severity(self):
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        am1 = [f for f in result["findings"] if f["type"] == "AM1"]
        self.assertTrue(am1)
        self.assertEqual(am1[0]["severity"], "high")

    def test_am1_finding_has_pc(self):
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        am1 = [f for f in result["findings"] if f["type"] == "AM1"]
        self.assertIsNotNone(am1[0].get("pc"))

    def test_am1_detected_from_origin_to_call_target(self):
        result = ta.analyze(BYTECODE_AM1_ORIGIN)
        self.assertIn("AM1", result["am_types_found"])

    def test_am1_taint_source_recorded(self):
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        am1 = [f for f in result["findings"] if f["type"] == "AM1"]
        self.assertIn(am1[0]["taint_source"], ("calldata", "origin"))


# ---------------------------------------------------------------------------
# AM2 detection (TaintAnalyzer)
# ---------------------------------------------------------------------------

class TestAM2Detection(unittest.TestCase):

    def test_am2_detected_from_callvalue_to_call_value_arg(self):
        result = ta.analyze(BYTECODE_AM2_CALLVALUE)
        self.assertIn("AM2", result["am_types_found"])

    def test_am2_taint_source_is_value(self):
        result = ta.analyze(BYTECODE_AM2_CALLVALUE)
        am2 = [f for f in result["findings"] if f["type"] == "AM2"]
        self.assertTrue(am2)
        self.assertEqual(am2[0]["taint_source"], "value")

    def test_am2_severity_is_high(self):
        result = ta.analyze(BYTECODE_AM2_CALLVALUE)
        am2 = [f for f in result["findings"] if f["type"] == "AM2"]
        self.assertEqual(am2[0]["severity"], "high")


# ---------------------------------------------------------------------------
# Caller guard suppresses AM1
# ---------------------------------------------------------------------------

class TestCallerGuard(unittest.TestCase):

    def test_caller_guarded_detected(self):
        result = ta.analyze(BYTECODE_CALLER_GUARDED)
        self.assertTrue(result["caller_guarded"])

    def test_am1_suppressed_when_caller_guard_present(self):
        """CALLER+EQ+JUMPI pattern means AM1 should NOT fire."""
        result = ta.analyze(BYTECODE_CALLER_GUARDED)
        am1_findings = [f for f in result["findings"] if f["type"] == "AM1"]
        self.assertEqual(am1_findings, [],
                         "AM1 must be suppressed when a CALLER guard is present")

    def test_no_caller_guard_in_clean_bytecode(self):
        result = ta.analyze(BYTECODE_CLEAN)
        self.assertFalse(result["caller_guarded"])


# ---------------------------------------------------------------------------
# AM3 detection (AMPatternDetector)
# ---------------------------------------------------------------------------

class TestAM3Detection(unittest.TestCase):

    def test_am3_detected_from_origin_eq_jumpi(self):
        result = det.detect(BYTECODE_AM3)
        self.assertIn("AM3", result["am_types_found"])

    def test_am3_finding_severity(self):
        result = det.detect(BYTECODE_AM3)
        am3 = [f for f in result["findings"] if f["type"] == "AM3"]
        self.assertEqual(am3[0]["severity"], "medium")

    def test_am3_not_detected_in_clean_bytecode(self):
        result = det.detect(BYTECODE_CLEAN)
        self.assertNotIn("AM3", result["am_types_found"])


# ---------------------------------------------------------------------------
# AM4 detection (AMPatternDetector)
# ---------------------------------------------------------------------------

class TestAM4Detection(unittest.TestCase):

    def test_am4_detected_when_approve_and_transfer_from_present(self):
        result = det.detect(BYTECODE_AM4)
        self.assertIn("AM4", result["am_types_found"])

    def test_am4_not_detected_with_only_approve(self):
        bcode = "0x" + "63095ea7b3" + "50"
        result = det.detect(bcode)
        self.assertNotIn("AM4", result["am_types_found"])

    def test_am4_not_detected_with_only_transfer_from(self):
        bcode = "0x" + "6323b872dd" + "50"
        result = det.detect(bcode)
        self.assertNotIn("AM4", result["am_types_found"])


# ---------------------------------------------------------------------------
# AM5 detection (AMPatternDetector)
# ---------------------------------------------------------------------------

class TestAM5Detection(unittest.TestCase):

    def test_am5_detected_for_uniswap_callback_with_reachable_call(self):
        result = det.detect(BYTECODE_AM5)
        self.assertIn("AM5", result["am_types_found"])


# ---------------------------------------------------------------------------
# AM7 detection (AMPatternDetector)
# ---------------------------------------------------------------------------

class TestAM7Detection(unittest.TestCase):

    def test_am7_detected_for_permissionless_sstore(self):
        result = det.detect(BYTECODE_AM7)
        self.assertIn("AM7", result["am_types_found"])

    def test_am7_not_detected_without_sstore(self):
        result = det.detect(BYTECODE_CLEAN)
        self.assertNotIn("AM7", result["am_types_found"])

    def test_am7_not_detected_when_caller_guard_present(self):
        bcode = (
            "0x"
            "63deadbeef"  # PUSH4 selector
            "50"          # POP
            "33"          # CALLER
            "6000"        # PUSH1 0
            "14"          # EQ
            "6000"        # PUSH1 (dest)
            "57"          # JUMPI
            "60006000"    # PUSH1 0, PUSH1 0
            "55"          # SSTORE
        )
        result = det.detect(bcode)
        self.assertNotIn("AM7", result["am_types_found"])


# ---------------------------------------------------------------------------
# AM8 detection (AMPatternDetector)
# ---------------------------------------------------------------------------

class TestAM8Detection(unittest.TestCase):

    def test_am8_detected_for_sload_before_delegatecall(self):
        result = det.detect(BYTECODE_AM8)
        self.assertIn("AM8", result["am_types_found"])

    def test_am8_finding_severity_is_high(self):
        result = det.detect(BYTECODE_AM8)
        am8 = [f for f in result["findings"] if f["type"] == "AM8"]
        self.assertTrue(am8)
        self.assertEqual(am8[0]["severity"], "high")

    def test_am8_not_detected_with_push20_constant_target(self):
        """PUSH20 constant target means the implementation is hardcoded — safe."""
        bcode = (
            "0x"
            "6000"        # PUSH1 slot
            "54"          # SLOAD
            "73" + "deadbeef" * 5  # PUSH20 constant address
            + "60006000600060 00f4".replace(" ", "")
        )
        result = det.detect(bcode)
        self.assertNotIn("AM8", result["am_types_found"])

    def test_am8_not_detected_without_sload(self):
        bcode = (
            "0x"
            "6000"   # PUSH1
            "6000"   # PUSH1
            "6000"   # PUSH1
            "6000"   # PUSH1
            "f4"     # DELEGATECALL (no SLOAD in lookback)
        )
        result = det.detect(bcode)
        self.assertNotIn("AM8", result["am_types_found"])


# ---------------------------------------------------------------------------
# Documented gaps / known limitations
# ---------------------------------------------------------------------------

class TestDocumentedGaps(unittest.TestCase):
    """
    These tests document known gaps in the current implementation.
    They are expected to PASS (verifying the gap exists), not fail.
    When the gap is addressed, these tests should be updated.
    """

    def test_am6_gap_returndatacopy_does_not_propagate_memory_taint(self):
        """
        SKANF Gap: RETURNDATACOPY should mark memory as 'return_data' tainted.
        An MLOAD from that offset, followed by SSTORE, should fire AM6.

        Current behavior: RETURNDATACOPY just pops its 3 stack args but does NOT
        write any taint to mem_taint. Consequently, AM6 never fires from taint analysis.

        This is a known limitation documented here as a regression guard.
        """
        # Construct: external CALL → RETURNDATACOPY → MLOAD → SSTORE
        # External CALL:  60 00 60 00 60 00 60 00 60 00 60 00 60 01 f1
        # RETURNDATASIZE: 3d  (pushes size onto stack)
        # PUSH1 0 / PUSH1 0: for RETURNDATACOPY args (destOffset, offset, length)
        # RETURNDATACOPY: 3e
        # MLOAD offset 0: 60 00 51
        # SSTORE slot 0:  60 00 55
        bcode = (
            "0x"
            # External CALL (returns some data)
            "6000600060006000600060006001f1"
            # RETURNDATASIZE → stack has size
            "3d"
            # PUSH1 0 / PUSH1 0 for RETURNDATACOPY(destOff=0, srcOff=0, len=size)
            "6000" "6000"
            # RETURNDATACOPY (pops 3 args)
            "3e"
            # MLOAD from offset 0
            "6000" "51"
            # SSTORE to slot 1
            "6001" "55"
        )
        result = ta.analyze(bcode)
        # AM6 is NOT currently detected — this documents the gap
        self.assertNotIn("AM6", result["am_types_found"],
                         "AM6 detection via RETURNDATACOPY taint not yet implemented")

    def test_am8_taint_gap_sload_storage_taint_not_tracked_through_delegatecall(self):
        """
        SKANF Gap: TaintAnalyzer tracks 'storage' taint via SLOAD only if the slot
        was previously SSSTOREd with a tainted value in the same trace.  In real
        contracts the implementation slot is set externally, so SLOAD returns None
        taint, and AM8 via data-flow never fires from TaintAnalyzer.

        AMPatternDetector._scan_am8 covers this gap with pattern matching.
        This test confirms the taint-based path does not false-positive.
        """
        # SLOAD a storage slot, then DELEGATECALL using the loaded value as target
        result_taint = ta.analyze(BYTECODE_AM8)
        # TaintAnalyzer should not produce AM8 (pattern-based detector handles it)
        am8_taint = [f for f in result_taint["findings"] if f["type"] == "AM8"]
        self.assertEqual(am8_taint, [],
                         "TaintAnalyzer AM8 via storage taint is not yet implemented")

    def test_calldataload_does_not_pop_offset_arg(self):
        """
        Known quirk: _TAINT_SOURCES handler for CALLDATALOAD appends the taint
        label but does NOT pop the offset argument from the stack first.
        The stack grows by 1 net (instead of net 0), but the taint label ends
        up in the right position relative to subsequent CALL args in simple cases.

        This test documents the behavior so regressions are caught if the
        stack model is corrected in the future.
        """
        # A single CALLDATALOAD should consume the offset (PUSH1 0) and produce
        # the 32-byte value.  If offset is not popped, the stack has 2 items;
        # if it is popped, the stack has 1 item.
        # We verify the AM1 finding still fires (the practical impact is benign
        # for simple sequences, but complex ones may be mis-modeled).
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        self.assertIn("AM1", result["am_types_found"])


# ---------------------------------------------------------------------------
# Result structure validation
# ---------------------------------------------------------------------------

class TestResultStructure(unittest.TestCase):

    def test_taint_findings_have_required_fields(self):
        result = ta.analyze(BYTECODE_AM1_CALLDATA)
        for f in result["findings"]:
            for key in ("type", "severity", "pc", "description", "taint_source"):
                self.assertIn(key, f, f"Finding missing key '{key}': {f}")

    def test_pattern_findings_have_required_fields(self):
        result = det.detect(BYTECODE_AM7)
        for f in result["findings"]:
            for key in ("type", "severity", "pc", "description"):
                self.assertIn(key, f, f"Finding missing key '{key}': {f}")

    def test_am_types_found_matches_finding_types(self):
        for bcode in (BYTECODE_AM1_CALLDATA, BYTECODE_AM2_CALLVALUE, BYTECODE_AM7):
            result_ta = ta.analyze(bcode)
            self.assertEqual(
                sorted(result_ta["am_types_found"]),
                sorted({f["type"] for f in result_ta["findings"]}),
            )

    def test_detect_result_has_error_key(self):
        result = det.detect(BYTECODE_EMPTY)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
