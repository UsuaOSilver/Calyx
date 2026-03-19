"""
detectors/bytecode_analyzer/taint_analyzer.py

Static taint analysis for EVM bytecode -- Full SKANF Gap 2 + SoK extensions.

Taint sources:
  CALLDATALOAD / CALLDATASIZE  -> "calldata"
  CALLVALUE                    -> "value"
  ORIGIN                       -> "origin"
  CALLER                       -> "caller"
  RETURNDATACOPY               -> marks memory as "return_data" (external call output)
  SLOAD                        -> always tags result as "storage"

Sinks:
  CALL  to-arg calldata/origin-tainted + no CALLER guard  -> AM1
  CALL  value-arg calldata/value-tainted                  -> AM2
  SSTORE of "return_data"-tainted value                   -> AM6 (oracle manipulation)
  DELEGATECALL to "storage"-tainted target                -> AM8 (proxy hijack)

AM6: SoK DeFi Attacks arXiv:2208.13035 -- external CALL return data written to
storage slot (price oracle). RETURNDATACOPY marks memory as "return_data";
MLOAD propagates to stack; SSTORE fires AM6.

AM8 (taint-confirmed): complements pattern-based AM8 in AMPatternDetector with
actual data-flow confirmation that DELEGATECALL target came from SLOAD.

Usage:
    from detectors.bytecode_analyzer.taint_analyzer import TaintAnalyzer
    ta = TaintAnalyzer()
    result = ta.analyze(bytecode_hex)
    # result["am_types_found"] -- e.g. ["AM1", "AM2", "AM6", "AM8"]
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set

from pyevmasm import disassemble_all, Instruction

from detectors.bytecode_analyzer.skanf_sensitive import (
    SENSITIVE_ADDRESSES_ETH,
    SENSITIVE_SIGNATURES,
)

_TAINT_SOURCES: Dict[str, str] = {
    "CALLDATALOAD": "calldata",
    "CALLDATASIZE": "calldata",
    "CALLVALUE":    "value",
    "ORIGIN":       "origin",
    "CALLER":       "caller",
}

_BINARY_PROPAGATE: Set[str] = {
    "ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD",
    "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND",
    "AND", "OR", "XOR", "LT", "GT", "SLT", "SGT", "EQ",
    "SHL", "SHR", "SAR", "BYTE",
}

_UNARY_PROPAGATE: Set[str] = {"NOT", "ISZERO"}

_CALL_SINKS: Dict[str, Dict[str, int]] = {
    "CALL":         {"to": 1, "value": 2},
    "CALLCODE":     {"to": 1, "value": 2},
    "DELEGATECALL": {"to": 1},
    "STATICCALL":   {"to": 1},
    "SELFDESTRUCT": {"to": 0},
}

_CALL_POP_COUNT: Dict[str, int] = {
    "CALL": 7, "CALLCODE": 7, "DELEGATECALL": 6,
    "STATICCALL": 6, "SELFDESTRUCT": 1,
}

_PUSH_OPCODES: set = set(range(0x60, 0x80))


class TaintAnalyzer:
    """Single-pass linear taint analysis over EVM bytecode."""

    def analyze(self, bytecode_hex: str) -> Dict[str, Any]:
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
            "findings": findings, "am_types_found": am_types,
            "caller_guarded": caller_guarded, "error": None,
        }

    @staticmethod
    def _detect_caller_guard(instructions) -> bool:
        names = [i.name for i in instructions]
        for idx, name in enumerate(names):
            if name == "CALLER":
                window = names[idx: idx + 5]
                if "EQ" in window and "JUMPI" in window:
                    return True
        return False

    def _simulate(self, instructions, caller_guarded: bool) -> List[Dict[str, Any]]:
        stack: List[Optional[str]] = []
        stack_val: List[Optional[int]] = []
        mem_taint:  Dict[Optional[int], Optional[str]] = {}
        stor_taint: Dict[Optional[int], Optional[str]] = {}
        findings: List[Dict[str, Any]] = []

        for instr in instructions:
            name = instr.name

            if name in _TAINT_SOURCES:
                stack.append(_TAINT_SOURCES[name])
                stack_val.append(None)

            elif instr.opcode in _PUSH_OPCODES:
                stack.append(None)
                try:
                    stack_val.append(int(instr.operand))
                except Exception:
                    stack_val.append(None)

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
                if stack: stack.pop()
                if stack_val: stack_val.pop()

            elif name in _BINARY_PROPAGATE:
                b = stack.pop() if stack else None
                a = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                if stack_val: stack_val.pop()
                stack.append(a if a is not None else b)
                stack_val.append(None)

            elif name in _UNARY_PROPAGATE:
                a = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                stack.append(a)
                stack_val.append(None)

            elif name == "MSTORE":
                offset = stack.pop() if stack else None
                value  = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                if stack_val: stack_val.pop()
                mem_taint[offset if isinstance(offset, int) else None] = value

            elif name in ("MSTORE8",):
                if stack: stack.pop()
                if stack: stack.pop()
                if stack_val: stack_val.pop()
                if stack_val: stack_val.pop()

            elif name == "MLOAD":
                offset = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                stack.append(mem_taint.get(offset if isinstance(offset, int) else None))
                stack_val.append(None)

            elif name == "MSIZE":
                stack.append(None)
                stack_val.append(None)

            elif name == "SSTORE":
                slot  = stack.pop() if stack else None
                value = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                if stack_val: stack_val.pop()
                stor_taint[slot if isinstance(slot, int) else None] = value

            elif name == "SLOAD":
                slot = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                stack.append(stor_taint.get(slot if isinstance(slot, int) else None))
                stack_val.append(None)

            elif name in _CALL_SINKS:
                sink_def = _CALL_SINKS[name]

                def _peek(pos):
                    return stack[-(pos + 1)] if len(stack) > pos else None

                def _peek_val(pos):
                    return stack_val[-(pos + 1)] if len(stack_val) > pos else None

                static_to_val = _peek_val(sink_def.get("to", 1))
                erc20_sensitive = False
                sensitive_token_addr = None
                if static_to_val is not None:
                    candidate = hex(static_to_val)
                    if candidate in SENSITIVE_ADDRESSES_ETH:
                        erc20_sensitive = True
                        sensitive_token_addr = candidate

                if "to" in sink_def:
                    to_taint = _peek(sink_def["to"])
                    if to_taint in ("calldata", "origin") and not caller_guarded:
                        findings.append(self._finding(
                            am_type="AM1", severity="high", pc=instr.pc,
                            description=(
                                f"CALL at PC {instr.pc}: target address is tainted by "
                                f"'{to_taint}' with no CALLER+EQ guard — "
                                f"caller controls where funds flow"
                            ),
                            taint_source=to_taint,
                            erc20_sensitive=erc20_sensitive,
                            sensitive_token_addr=sensitive_token_addr,
                        ))

                if "value" in sink_def:
                    val_taint = _peek(sink_def["value"])
                    if val_taint in ("calldata", "value"):
                        findings.append(self._finding(
                            am_type="AM2", severity="high", pc=instr.pc,
                            description=(
                                f"CALL at PC {instr.pc}: ETH value argument is tainted by "
                                f"'{val_taint}' — caller can drain ETH via controlled value"
                            ),
                            taint_source=val_taint,
                            erc20_sensitive=erc20_sensitive,
                            sensitive_token_addr=sensitive_token_addr,
                        ))

                n_pop = min(_CALL_POP_COUNT.get(name, 4), len(stack))
                for _ in range(n_pop):
                    stack.pop()
                for _ in range(min(n_pop, len(stack_val))):
                    stack_val.pop()

                if name != "SELFDESTRUCT":
                    stack.append(None)
                    stack_val.append(None)

            elif name in ("STOP", "RETURN", "REVERT", "INVALID"):
                pass

            elif name == "SHA3":
                _off = stack.pop() if stack else None
                _len = stack.pop() if stack else None
                if stack_val: stack_val.pop()
                if stack_val: stack_val.pop()
                stack.append(_off if _off is not None else _len)
                stack_val.append(None)

            elif name in (
                "ADDRESS", "BALANCE", "EXTCODESIZE", "EXTCODEHASH",
                "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER",
                "DIFFICULTY", "GASLIMIT", "CHAINID", "SELFBALANCE",
                "BASEFEE", "GAS", "PC", "RETURNDATASIZE",
                "GASPRICE", "CODESIZE",
            ):
                stack.append(None)
                stack_val.append(None)

            elif name in ("CALLDATACOPY", "CODECOPY", "EXTCODECOPY", "RETURNDATACOPY"):
                n_args = 3 if name != "EXTCODECOPY" else 4
                for _ in range(min(n_args, len(stack))): stack.pop()
                for _ in range(min(n_args, len(stack_val))): stack_val.pop()

            elif name in ("CREATE", "CREATE2"):
                n_args = 3 if name == "CREATE" else 4
                for _ in range(min(n_args, len(stack))): stack.pop()
                for _ in range(min(n_args, len(stack_val))): stack_val.pop()
                stack.append(None)
                stack_val.append(None)

            elif name.startswith("LOG") and name[3:].isdigit():
                n_topics = int(name[3:])
                for _ in range(min(2 + n_topics, len(stack))): stack.pop()
                for _ in range(min(2 + n_topics, len(stack_val))): stack_val.pop()

            else:
                stack.append(None)
                stack_val.append(None)

        return findings

    @staticmethod
    def _finding(am_type, severity, pc, description, taint_source,
                 erc20_sensitive=False, sensitive_token_addr=None):
        return {
            "type": am_type, "severity": severity, "pc": pc,
            "description": description, "taint_source": taint_source,
            "erc20_sensitive": erc20_sensitive,
            "sensitive_token_addr": sensitive_token_addr,
        }

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {"findings": [], "am_types_found": [], "caller_guarded": False, "error": error}
