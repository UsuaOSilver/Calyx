"""
detectors/bytecode_analyzer/taint_analyzer.py

Static taint analysis for EVM bytecode — Full SKANF Gap 2.

Replaces the sliding-window heuristic in AMPatternDetector for AM1/AM2.
Performs a single linear pass over the disassembled instruction stream,
maintaining a simulated EVM stack where each slot is tagged with its
taint origin (or None for clean constants).

Taint sources (values the attacker controls or that are externally derived):
  CALLDATALOAD / CALLDATASIZE  → tagged "calldata"
  CALLVALUE                    → tagged "value"
  ORIGIN                       → tagged "origin"
  CALLER                       → tagged "caller"
  RETURNDATACOPY               → marks memory as "return_data" (external call output)
  SLOAD                        → tagged "storage" (always; value comes from contract state)

Taint propagates through arithmetic, bitwise, stack-manipulation, and
memory/storage ops.  Sinks:
  - CALL to argument is calldata/origin-tainted + no CALLER guard → AM1
  - CALL value argument is calldata/value-tainted                 → AM2
  - SSTORE of "return_data"-tainted value                         → AM6
  - DELEGATECALL to "storage"-tainted target                      → AM8

AM6: Price oracle manipulation (SoK DeFi Attacks arXiv:2208.13035).
  External CALL return value → RETURNDATACOPY (marks memory "return_data")
  → MLOAD (reads tainted memory) → SSTORE (writes oracle slot). Attacker
  manipulates the external price source before this call to corrupt the oracle.

AM8 (taint-based): DELEGATECALL where target address is "storage"-derived.
  Complements the pattern-based AM8 in AMPatternDetector with actual data-flow
  confirmation that the to-argument comes from SLOAD.

Sanitizer detection:  a CALLER+EQ+JUMPI sequence anywhere in the bytecode
marks the entire function as guarded, suppressing AM1 findings only.

AM3/AM4/AM5/AM7 are NOT detected here — pattern matching only, in AMPatternDetector.

Usage:
    from detectors.bytecode_analyzer.taint_analyzer import TaintAnalyzer

    ta = TaintAnalyzer()
    result = ta.analyze(bytecode_hex)

    # result["findings"]       — [{type, severity, pc, description, taint_source}]
    # result["am_types_found"] — e.g. ["AM1", "AM2", "AM6", "AM8"]  (deduplicated)
    # result["caller_guarded"] — True if a CALLER+EQ guard was detected
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from pyevmasm import disassemble_all, Instruction

from detectors.bytecode_analyzer.skanf_sensitive import (
    SENSITIVE_ADDRESSES_ETH,
    SENSITIVE_SIGNATURES,
)

# ── Taint source opcodes ───────────────────────────────────────────────────────

_TAINT_SOURCES: Dict[str, str] = {
    "CALLDATALOAD":  "calldata",
    "CALLDATASIZE":  "calldata",
    "CALLVALUE":     "value",
    "ORIGIN":        "origin",
    "CALLER":        "caller",
}

# ── Propagating opcodes ────────────────────────────────────────────────────────
# Output is tainted if any input is tainted.

_BINARY_PROPAGATE: Set[str] = {
    # arithmetic
    "ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD",
    "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND",
    # bitwise
    "AND", "OR", "XOR",
    # comparison
    "LT", "GT", "SLT", "SGT", "EQ",
    # shifts
    "SHL", "SHR", "SAR",
    # byte extraction
    "BYTE",
}

_UNARY_PROPAGATE: Set[str] = {"NOT", "ISZERO"}

# ── Call sinks and their stack-position layout ─────────────────────────────────
# EVM stack at CALL:         [gas, to, value, argsOff, argsLen, retOff, retLen] top→
# EVM stack at DELEGATECALL: [gas, to, argsOff, argsLen, retOff, retLen]
# Position 0 = top of stack (last pushed).

_CALL_SINKS: Dict[str, Dict[str, int]] = {
    "CALL":         {"to": 1, "value": 2},
    "CALLCODE":     {"to": 1, "value": 2},
    "DELEGATECALL": {"to": 1},
    "STATICCALL":   {"to": 1},
    "SELFDESTRUCT": {"to": 0},
}

# Number of stack items each call opcode consumes
_CALL_POP_COUNT: Dict[str, int] = {
    "CALL":         7,
    "CALLCODE":     7,
    "DELEGATECALL": 6,
    "STATICCALL":   6,
    "SELFDESTRUCT": 1,
}

# PUSH1–PUSH32: opcodes 0x60–0x7f
_PUSH_OPCODES: set = set(range(0x60, 0x80))


class TaintAnalyzer:
    """
    Single-pass linear taint analysis over EVM bytecode.

    Detects AM1 (unguarded call target) and AM2 (unguarded ETH value drain)
    using actual data-flow tracking instead of proximity heuristics.
    """

    def analyze(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Run taint analysis on raw EVM bytecode.

        Args:
            bytecode_hex: Hex string with or without 0x prefix.

        Returns:
            {
                "findings":       List[dict]   — AM1/AM2 findings with taint_source
                "am_types_found": List[str]    — deduplicated finding types
                "caller_guarded": bool         — CALLER+EQ guard detected in bytecode
                "error":          Optional[str]
            }
        """
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        hex_str = hex_str.strip()
        if not hex_str:
            return self._empty("empty bytecode")

        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as exc:
            return self._empty(f"disassemble failed: {exc}")

        caller_guarded = self._detect_caller_guard(instructions)
        findings = self._simulate(instructions, caller_guarded)
        am_types = sorted({f["type"] for f in findings})

        return {
            "findings":       findings,
            "am_types_found": am_types,
            "caller_guarded": caller_guarded,
            "error":          None,
        }

    # ── Sanitizer pre-scan ─────────────────────────────────────────────────────

    @staticmethod
    def _detect_caller_guard(instructions: List[Instruction]) -> bool:
        """
        Return True if a CALLER+EQ+JUMPI sequence appears anywhere in the
        bytecode within a 5-instruction window.  This heuristic detects the
        common access-control pattern: require(msg.sender == owner).
        """
        names = [i.name for i in instructions]
        for idx, name in enumerate(names):
            if name == "CALLER":
                window = names[idx: idx + 5]
                if "EQ" in window and "JUMPI" in window:
                    return True
        return False

    # ── Stack simulation ───────────────────────────────────────────────────────

    def _simulate(
        self,
        instructions: List[Instruction],
        caller_guarded: bool,
    ) -> List[Dict[str, Any]]:
        """
        Walk instructions linearly (no branching — single-pass approximation).

        Stack model: List[Optional[str]]
          None      — clean (not tainted, or unknown)
          "calldata"— tainted by CALLDATALOAD / CALLDATASIZE
          "value"   — tainted by CALLVALUE
          "origin"  — tainted by ORIGIN
          "caller"  — tainted by CALLER

        Memory/storage taint uses dict keyed on the slot value (None for
        unknown-offset stores/loads, which are treated as untainted reads).
        """
        stack: List[Optional[str]] = []
        # Parallel stack tracking raw constant values (int for PUSH, None otherwise)
        stack_val: List[Optional[int]] = []
        mem_taint:  Dict[Optional[int], Optional[str]] = {}
        stor_taint: Dict[Optional[int], Optional[str]] = {}
        findings: List[Dict[str, Any]] = []

        for instr in instructions:
            name = instr.name

            # ── Taint sources ──────────────────────────────────────────────────
            if name in _TAINT_SOURCES:
                stack.append(_TAINT_SOURCES[name])
                stack_val.append(None)

            # ── Clean constants ────────────────────────────────────────────────
            elif instr.opcode in _PUSH_OPCODES:
                stack.append(None)
                # Track the raw integer value for sensitive-address detection
                try:
                    stack_val.append(int(instr.operand))
                except Exception:
                    stack_val.append(None)

            # ── Stack manipulation ─────────────────────────────────────────────
            elif name.startswith("DUP") and name[3:].isdigit():
                n = int(name[3:])
                val = stack[-n] if len(stack) >= n else None
                stack.append(val)
                vv = stack_val[-n] if len(stack_val) >= n else None
                stack_val.append(vv)

            elif name.startswith("SWAP") and name[4:].isdigit():
                n = int(name[4:])
                if len(stack) > n:
                    stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]
                if len(stack_val) > n:
                    stack_val[-1], stack_val[-(n + 1)] = stack_val[-(n + 1)], stack_val[-1]

            elif name == "POP":
                if stack:
                    stack.pop()
                if stack_val:
                    stack_val.pop()

            # ── Binary propagation ─────────────────────────────────────────────
            elif name in _BINARY_PROPAGATE:
                b = stack.pop() if stack else None
                a = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                # Propagate: output is tainted if either input is tainted
                tainted = a if a is not None else b
                stack.append(tainted)
                stack_val.append(None)

            # ── Unary propagation ──────────────────────────────────────────────
            elif name in _UNARY_PROPAGATE:
                a = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack.append(a)
                stack_val.append(None)

            # ── Memory ────────────────────────────────────────────────────────
            elif name == "MSTORE":
                offset = stack.pop() if stack else None
                value  = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                key = offset if isinstance(offset, int) else None
                mem_taint[key] = value

            elif name in ("MSTORE8",):
                stack.pop() if stack else None   # offset
                stack.pop() if stack else None   # value
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None

            elif name == "MLOAD":
                offset = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                key = offset if isinstance(offset, int) else None
                stack.append(mem_taint.get(key))
                stack_val.append(None)

            elif name == "MSIZE":
                stack.append(None)
                stack_val.append(None)

            # ── Storage ───────────────────────────────────────────────────────
            elif name == "SSTORE":
                slot  = stack.pop() if stack else None
                value = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                key = slot if isinstance(slot, int) else None
                stor_taint[key] = value
                # AM6: price oracle manipulation — storage written from external call output
                if value == "return_data":
                    findings.append(self._finding(
                        am_type="AM6",
                        severity="high",
                        pc=instr.pc,
                        description=(
                            f"SSTORE at PC {instr.pc}: storage slot written with value derived "
                            f"from external call return data (RETURNDATACOPY path) — "
                            f"potential price oracle manipulation (SoK DeFi Attacks AM6)"
                        ),
                        taint_source="return_data",
                    ))

            elif name == "SLOAD":
                slot = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                key  = slot if isinstance(slot, int) else None
                existing = stor_taint.get(key)
                # Always tag SLOAD result as "storage" — enables AM8 detection.
                # Explicit propagated taint (e.g., "calldata") takes priority.
                stack.append(existing if existing is not None else "storage")
                stack_val.append(None)

            # ── Call sinks ────────────────────────────────────────────────────
            elif name in _CALL_SINKS:
                sink_def = _CALL_SINKS[name]

                def _peek(pos: int) -> Optional[str]:
                    """Peek at stack[-(pos+1)] without consuming."""
                    return stack[-(pos + 1)] if len(stack) > pos else None

                def _peek_val(pos: int) -> Optional[int]:
                    """Peek raw integer value at stack[-(pos+1)]."""
                    return stack_val[-(pos + 1)] if len(stack_val) > pos else None

                # Check if the static CALL target (to) is a SKANF-sensitive address
                static_to_val = _peek_val(sink_def.get("to", 1))
                erc20_sensitive = False
                sensitive_token_addr: Optional[str] = None
                if static_to_val is not None:
                    candidate = hex(static_to_val)
                    if candidate in SENSITIVE_ADDRESSES_ETH:
                        erc20_sensitive = True
                        sensitive_token_addr = candidate

                # AM1: tainted call target address
                if "to" in sink_def:
                    to_taint = _peek(sink_def["to"])
                    if to_taint in ("calldata", "origin") and not caller_guarded:
                        findings.append(self._finding(
                            am_type="AM1",
                            severity="high",
                            pc=instr.pc,
                            description=(
                                f"CALL at PC {instr.pc}: target address is tainted by "
                                f"'{to_taint}' with no CALLER+EQ guard — "
                                f"caller controls where funds flow"
                            ),
                            taint_source=to_taint,
                            erc20_sensitive=erc20_sensitive,
                            sensitive_token_addr=sensitive_token_addr,
                        ))

                # AM2: tainted ETH value forwarded
                if "value" in sink_def:
                    val_taint = _peek(sink_def["value"])
                    if val_taint in ("calldata", "value"):
                        findings.append(self._finding(
                            am_type="AM2",
                            severity="high",
                            pc=instr.pc,
                            description=(
                                f"CALL at PC {instr.pc}: ETH value argument is tainted by "
                                f"'{val_taint}' — caller can drain ETH via controlled value"
                            ),
                            taint_source=val_taint,
                            erc20_sensitive=erc20_sensitive,
                            sensitive_token_addr=sensitive_token_addr,
                        ))

                # AM8 (taint-confirmed): DELEGATECALL to storage-derived target
                if name == "DELEGATECALL" and "to" in sink_def:
                    to_taint = _peek(sink_def["to"])
                    if to_taint == "storage":
                        findings.append(self._finding(
                            am_type="AM8",
                            severity="high",
                            pc=instr.pc,
                            description=(
                                f"DELEGATECALL at PC {instr.pc}: target address is "
                                f"storage-derived (data-flow confirmed via SLOAD) — "
                                f"implementation slot may be overwritable (SoK AM8)"
                            ),
                            taint_source="storage",
                        ))

                # Consume call arguments
                n_pop = min(_CALL_POP_COUNT.get(name, 4), len(stack))
                for _ in range(n_pop):
                    stack.pop()
                for _ in range(min(n_pop, len(stack_val))):
                    stack_val.pop()

                # CALL/CALLCODE/DELEGATECALL/STATICCALL push a success flag
                if name != "SELFDESTRUCT":
                    stack.append(None)
                    stack_val.append(None)

            # ── Halts (don't clear stack — linear pass continues) ──────────────
            elif name in ("STOP", "RETURN", "REVERT", "INVALID"):
                pass

            # ── SHA3 (hash of memory range → unknown, but propagate taint) ────
            elif name == "SHA3":
                _off = stack.pop() if stack else None
                _len = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                # Conservative: treat hash of tainted data as tainted
                tainted = _off if _off is not None else _len
                stack.append(tainted)
                stack_val.append(None)

            # ── Environment ops that push clean values ─────────────────────────
            elif name in (
                "ADDRESS", "BALANCE", "EXTCODESIZE", "EXTCODEHASH",
                "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER",
                "DIFFICULTY", "GASLIMIT", "CHAINID", "SELFBALANCE",
                "BASEFEE", "GAS", "PC", "RETURNDATASIZE",
                "GASPRICE", "CODESIZE",
            ):
                stack.append(None)
                stack_val.append(None)

            elif name == "RETURNDATACOPY":
                # (destOffset, offset, size) → copies external call result to memory
                # Taint the destination memory region as "return_data" (AM6 source)
                dest_t  = stack.pop() if stack else None
                _off    = stack.pop() if stack else None
                _sz     = stack.pop() if stack else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                stack_val.pop() if stack_val else None
                # Mark destination (use None key for unknown offset — conservative)
                dest_key = dest_t if isinstance(dest_t, int) else None
                mem_taint[dest_key] = "return_data"

            elif name in ("CALLDATACOPY", "CODECOPY", "EXTCODECOPY"):
                # These copy to memory; pop their args (no stack output)
                n_args = 3 if name != "EXTCODECOPY" else 4
                for _ in range(min(n_args, len(stack))):
                    stack.pop()
                for _ in range(min(n_args, len(stack_val))):
                    stack_val.pop()

            # ── CREATE / CREATE2 ───────────────────────────────────────────────
            elif name in ("CREATE", "CREATE2"):
                n_args = 3 if name == "CREATE" else 4
                for _ in range(min(n_args, len(stack))):
                    stack.pop()
                for _ in range(min(n_args, len(stack_val))):
                    stack_val.pop()
                stack.append(None)  # new contract address (clean)
                stack_val.append(None)

            # ── LOG0–LOG4 ──────────────────────────────────────────────────────
            elif name.startswith("LOG") and name[3:].isdigit():
                n_topics = int(name[3:])
                for _ in range(min(2 + n_topics, len(stack))):
                    stack.pop()
                for _ in range(min(2 + n_topics, len(stack_val))):
                    stack_val.pop()

            # ── Everything else: unknown — push one unknown value ──────────────
            else:
                stack.append(None)
                stack_val.append(None)

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _finding(
        am_type: str,
        severity: str,
        pc: int,
        description: str,
        taint_source: Optional[str],
        erc20_sensitive: bool = False,
        sensitive_token_addr: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "type":                 am_type,
            "severity":             severity,
            "pc":                   pc,
            "description":          description,
            "taint_source":         taint_source,
            # SKANF sensitivity: True when the CALL target is a known DeFi token
            "erc20_sensitive":      erc20_sensitive,
            "sensitive_token_addr": sensitive_token_addr,
        }

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {
            "findings":       [],
            "am_types_found": [],
            "caller_guarded": False,
            "error":          error,
        }
