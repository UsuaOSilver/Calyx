# detectors/bytecode_analyzer/cfg_profiler.py
"""
Control-flow obfuscation profiler + AM vulnerability pattern detector for EVM bytecode.

CFGProfiler:
    Detects indirect JUMP/JUMPI instructions (runtime-computed destinations) —
    the core obfuscation technique analyzed in SKANF (IC3/Yale, arXiv:2504.13398).

AMPatternDetector:
    Heuristic opcode-sequence scanner for SKANF AM3/AM4/AM5 vulnerability patterns.
    Uses sliding-window analysis — no symbolic execution or taint tracking.

    AM3: tx.origin used as authorization check (ORIGIN -> EQ -> JUMPI)
    AM4: approve() + transferFrom() selectors present without CALLER guard
    AM5: Known flash-loan/swap callback selector reachable without CALLER check

    NOTE: AM1 and AM2 are now detected by TaintAnalyzer (taint_analyzer.py).
    AMPatternDetector.detect() no longer includes AM1/AM2 findings.

Usage:
    from detectors.bytecode_analyzer.cfg_profiler import CFGProfiler, AMPatternDetector

    profiler = CFGProfiler()
    profile  = profiler.profile(bytecode_hex)

    detector = AMPatternDetector()
    findings = detector.detect(bytecode_hex)
"""

from __future__ import annotations

from pyevmasm import disassemble_all, Instruction
from typing import Any, Dict, List, Optional, Tuple

PUSH_OPCODES = set(range(0x60, 0x80))
CALL_OPCODES = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}
_SEL_APPROVE        = 0x095ea7b3
_SEL_TRANSFER_FROM  = 0x23b872dd

CALLBACK_SELECTORS = {
    0xfa461e33: "uniswapV3SwapCallback",
    0x10d1e85c: "uniswapV2Call",
    0x920f5c84: "executeOperation",
    0xd9d98ce4: "executeOperation",
    0x23e30c8b: "onFlashLoan",
    0x4ec7d75d: "pancakeCall",
}

_CALL_WINDOW = 20
_CALLBACK_WINDOW = 50


def _preceding_instruction(instructions: List[Instruction], idx: int) -> Optional[Instruction]:
    if idx > 0:
        return instructions[idx - 1]
    return None


class CFGProfiler:
    """
    Disassembles EVM bytecode and classifies every JUMP/JUMPI as
    direct (destination is a preceding PUSH constant) or indirect
    (destination depends on runtime state).
    """

    def profile(self, bytecode_hex: str) -> Dict[str, Any]:
        hex_str = bytecode_hex.lstrip("0x").strip() if bytecode_hex.startswith("0x") else bytecode_hex.strip()
        if not hex_str:
            return self._empty_result("empty bytecode")
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._empty_result(f"disassemble failed: {e}")

        total_jumps = 0
        direct_jumps = 0
        indirect_jump_pcs: List[Dict] = []
        jumpdest_pcs: List[int] = []

        for i, instr in enumerate(instructions):
            op = instr.name
            if op == "JUMPDEST":
                jumpdest_pcs.append(instr.pc)
            elif op in ("JUMP", "JUMPI"):
                total_jumps += 1
                prev = _preceding_instruction(instructions, i)
                if prev is not None and prev.opcode in PUSH_OPCODES:
                    direct_jumps += 1
                else:
                    indirect_jump_pcs.append({"pc": instr.pc, "opcode": op})

        indirect = len(indirect_jump_pcs)
        score = indirect / total_jumps if total_jumps > 0 else 0.0

        if score == 0.0:
            assessment = "clean"
        elif score < 0.3:
            assessment = "likely_obfuscated"
        else:
            assessment = "obfuscated"

        return {
            "total_jumps": total_jumps,
            "direct_jumps": direct_jumps,
            "indirect_jumps": indirect,
            "obfuscation_score": round(score, 4),
            "indirect_jump_pcs": indirect_jump_pcs,
            "all_jumpdest_pcs": jumpdest_pcs,
            "instruction_count": len(instructions),
            "assessment": assessment,
            "error": None,
        }

    @staticmethod
    def _empty_result(error: str) -> Dict[str, Any]:
        return {
            "total_jumps": 0, "direct_jumps": 0, "indirect_jumps": 0,
            "obfuscation_score": 0.0, "indirect_jump_pcs": [],
            "all_jumpdest_pcs": [], "instruction_count": 0,
            "assessment": "unknown", "error": error,
        }


class AMPatternDetector:
    """
    Heuristic scanner for SKANF AM3/AM4/AM5 vulnerability patterns.
    Uses sliding-window analysis — no symbolic execution or taint tracking.
    """

    def detect(self, bytecode_hex: str) -> Dict[str, Any]:
        hex_str = bytecode_hex.lstrip("0x").strip() if bytecode_hex.startswith("0x") else bytecode_hex.strip()
        if not hex_str:
            return self._empty("empty bytecode")
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._empty(f"disassemble failed: {e}")

        findings: List[Dict] = []
        findings.extend(self._scan_am3(instructions))
        findings.extend(self._scan_am4(instructions))
        findings.extend(self._scan_am5(instructions))

        am_types = sorted({f["type"] for f in findings})
        return {"findings": findings, "am_types_found": am_types, "error": None}

    def _scan_am3(self, instructions: List[Instruction]) -> List[Dict]:
        findings = []
        names = [instr.name for instr in instructions]
        window = 5
        for i, name in enumerate(names):
            if name != "ORIGIN":
                continue
            lookahead = names[i: i + window]
            if "EQ" in lookahead and "JUMPI" in lookahead:
                pc = instructions[i].pc
                findings.append({
                    "type": "AM3", "severity": "medium", "pc": pc,
                    "description": (
                        f"ORIGIN at PC {pc} followed by EQ+JUMPI within {window} instructions — "
                        f"tx.origin used as authorization check (spoofable via contract relay)"
                    ),
                })
        return findings

    def _scan_am4(self, instructions: List[Instruction]) -> List[Dict]:
        findings = []
        has_approve = False
        has_transfer_from = False
        has_caller_eq = False
        names = [instr.name for instr in instructions]
        for i, instr in enumerate(instructions):
            if instr.name == "PUSH4":
                sel = instr.operand
                if sel == _SEL_APPROVE:
                    has_approve = True
                elif sel == _SEL_TRANSFER_FROM:
                    has_transfer_from = True
            if instr.name == "CALLER":
                lookahead = names[i: i + 3]
                if "EQ" in lookahead:
                    has_caller_eq = True

        if has_approve and has_transfer_from and not has_caller_eq:
            findings.append({
                "type": "AM4", "severity": "low", "pc": 0,
                "description": (
                    "approve() and transferFrom() selectors both present; "
                    "no CALLER+EQ guard detected in bytecode — "
                    "confirm whether transferFrom validates msg.sender"
                ),
            })
        return findings

    def _scan_am5(self, instructions: List[Instruction]) -> List[Dict]:
        findings = []
        names   = [instr.name   for instr in instructions]
        jumpdest_idx: Dict[int, int] = {}
        for i, instr in enumerate(instructions):
            if instr.name == "JUMPDEST":
                jumpdest_idx[instr.pc] = i

        for i, instr in enumerate(instructions):
            if instr.name != "PUSH4":
                continue
            sel = instr.operand
            if sel not in CALLBACK_SELECTORS:
                continue
            callback_name = CALLBACK_SELECTORS[sel]
            lookahead_instrs = instructions[i: i + 6]
            lookahead_names  = [x.name for x in lookahead_instrs]

            jumpi_target_pc = None
            if "JUMPI" in lookahead_names:
                jumpi_idx_local = lookahead_names.index("JUMPI")
                push_before = lookahead_instrs[jumpi_idx_local - 1] if jumpi_idx_local > 0 else None
                if push_before and push_before.name in [f"PUSH{n}" for n in range(1, 33)]:
                    jumpi_target_pc = push_before.operand

            start_idx = jumpdest_idx.get(jumpi_target_pc)
            if start_idx is None:
                start_idx = i + 1

            body = instructions[start_idx: start_idx + _CALLBACK_WINDOW]
            body_names = [x.name for x in body]

            has_call = any(n in CALL_OPCODES for n in body_names)
            if not has_call:
                continue

            caller_eq_before_call = False
            for j, bname in enumerate(body_names):
                if bname in CALL_OPCODES:
                    break
                if bname == "CALLER" and "EQ" in body_names[j: j + 3]:
                    caller_eq_before_call = True
                    break

            if not caller_eq_before_call:
                findings.append({
                    "type": "AM5", "severity": "medium", "pc": instr.pc,
                    "description": (
                        f"Callback selector {hex(sel)} ({callback_name}) at PC {instr.pc} — "
                        f"CALL reachable within {_CALLBACK_WINDOW} instructions of dispatch "
                        f"without CALLER+EQ guard; arbitrary callers may trigger the callback"
                    ),
                })
        return findings

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {"findings": [], "am_types_found": [], "error": error}
