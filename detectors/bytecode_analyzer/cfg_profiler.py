# detectors/bytecode_analyzer/cfg_profiler.py
"""
Control-flow obfuscation profiler + AM vulnerability pattern detector for EVM bytecode.

CFGProfiler:
    Detects indirect JUMP/JUMPI instructions (runtime-computed destinations) -
    the core obfuscation technique analyzed in SKANF (IC3/Yale, arXiv:2504.13398).

    Also provides:
    - split_by_selector(): partition bytecode by 4-byte function selectors (T2,
      arXiv:2506.19624 -- enables per-function vulnerability attribution)
    - detect_complex_defi_patterns(): multi-hop flash loan + swap sequence detection
      (T4 -- flags contracts needing human review)

AMPatternDetector:
    Heuristic opcode-sequence scanner for SKANF AM3-AM8 vulnerability patterns.
    Uses sliding-window analysis -- no symbolic execution or taint tracking.

    AM3: tx.origin used as authorization check (ORIGIN -> EQ -> JUMPI)
    AM4: approve() + transferFrom() selectors present without CALLER guard
    AM5: Known flash-loan/swap callback selector reachable without CALLER check
    AM7: Public function selector dispatches to SSTORE without any CALLER guard
         (SoK DeFi Attacks arXiv:2208.13035 -- permissionless/camouflage pattern)
    AM8: DELEGATECALL preceded by SLOAD without constant PUSH20 target
         (proxy implementation slot controllable via storage -- SoK AM8)

    NOTE: AM1, AM2 detected by TaintAnalyzer (data-flow tracking).
          AM6 detected by TaintAnalyzer (oracle taint: RETURNDATACOPY -> SSTORE).
          AMPatternDetector.detect() covers AM3/AM4/AM5/AM7/AM8.

Usage:
    from detectors.bytecode_analyzer.cfg_profiler import CFGProfiler, AMPatternDetector

    profiler = CFGProfiler()
    profile  = profiler.profile(bytecode_hex)
    funcs    = profiler.split_by_selector(bytecode_hex)
    hard     = profiler.detect_complex_defi_patterns(bytecode_hex)

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
            "obfuscation_score": 0.0, "indirect_jump_pcs": [], "all_jumpdest_pcs": [],
            "instruction_count": 0, "assessment": "unknown", "error": error,
        }

    def split_by_selector(self, bytecode_hex: str) -> Dict[str, Any]:
        """Partition bytecode by 4-byte function selectors (T2 -- arXiv:2506.19624)."""
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str:
            return {"functions": {}, "function_count": 0, "error": "empty bytecode"}
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return {"functions": {}, "function_count": 0, "error": str(e)}

        functions: Dict[str, Dict] = {}
        push_names = {f"PUSH{n}" for n in range(1, 33)}

        for i, instr in enumerate(instructions):
            if instr.name != "PUSH4":
                continue
            sel_hex = hex(instr.operand)
            lookahead = instructions[i: i + 8]
            la_names = [x.name for x in lookahead]
            if "EQ" not in la_names or "JUMPI" not in la_names:
                continue
            jumpi_local = la_names.index("JUMPI")
            entry_pc = None
            for j in range(jumpi_local - 1, 0, -1):
                if lookahead[j].name in push_names:
                    try:
                        entry_pc = int(lookahead[j].operand)
                    except Exception:
                        pass
                    break
            if entry_pc is None:
                continue
            functions[sel_hex] = {"selector": sel_hex, "dispatch_pc": instr.pc, "entry_pc": entry_pc}

        return {"functions": functions, "function_count": len(functions), "error": None}

    def detect_complex_defi_patterns(self, bytecode_hex: str) -> Dict[str, Any]:
        """Detect multi-hop flash loan + swap sequences (T4 -- arXiv:2506.19624)."""
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str:
            return self._empty_complex("empty bytecode")
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._empty_complex(str(e))

        _DEX_SWAP_SELECTORS = {
            0x38ed1739: "swapExactTokensForTokens (UniV2)",
            0x7ff36ab5: "swapExactETHForTokens (UniV2)",
            0x128acb08: "swap (UniV3)",
            0x022c0d9f: "swap (UniV2 pool)",
            0xd0e30db0: "deposit (WETH)",
            0x2e1a7d4d: "withdraw (WETH)",
        }

        has_flash_callback = False
        swap_selector_count = 0
        call_count = 0
        patterns_found: List[str] = []

        for instr in instructions:
            if instr.name == "PUSH4":
                if instr.operand in CALLBACK_SELECTORS:
                    has_flash_callback = True
                if instr.operand in _DEX_SWAP_SELECTORS:
                    swap_selector_count += 1
            if instr.name == "CALL":
                call_count += 1

        if has_flash_callback:
            patterns_found.append("flash_loan_callback")
        if swap_selector_count >= 2:
            patterns_found.append(f"multi_dex_swap ({swap_selector_count} selectors)")
        if call_count >= 4:
            patterns_found.append(f"high_call_count ({call_count} CALLs)")

        score = min(1.0, (
            (0.4 if has_flash_callback else 0.0) +
            (0.3 if swap_selector_count >= 2 else 0.0) +
            (0.2 if call_count >= 4 else 0.0) +
            (0.1 if swap_selector_count >= 3 else 0.0)
        ))

        return {
            "complexity_score":   round(score, 3),
            "review_recommended": has_flash_callback and (swap_selector_count >= 1 or call_count >= 3),
            "patterns_found":     patterns_found,
            "detail":             f"flash_callback={'yes' if has_flash_callback else 'no'}, dex_selectors={swap_selector_count}, total_calls={call_count}",
            "error":              None,
        }

    @staticmethod
    def _empty_complex(error: str) -> Dict[str, Any]:
        return {"complexity_score": 0.0, "review_recommended": False, "patterns_found": [], "detail": "", "error": error}


class AMPatternDetector:
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
        findings.extend(self._scan_am7(instructions))
        findings.extend(self._scan_am8(instructions))

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
                findings.append({"type": "AM3", "severity": "medium", "pc": pc,
                    "description": f"ORIGIN at PC {pc} followed by EQ+JUMPI within {window} instructions -- tx.origin used as authorization check (spoofable via contract relay)"})
        return findings

    def _scan_am4(self, instructions: List[Instruction]) -> List[Dict]:
        has_approve = has_transfer_from = has_caller_eq = False
        names = [instr.name for instr in instructions]
        for i, instr in enumerate(instructions):
            if instr.name == "PUSH4":
                if instr.operand == _SEL_APPROVE:
                    has_approve = True
                elif instr.operand == _SEL_TRANSFER_FROM:
                    has_transfer_from = True
            if instr.name == "CALLER" and "EQ" in names[i: i + 3]:
                has_caller_eq = True
        if has_approve and has_transfer_from and not has_caller_eq:
            return [{"type": "AM4", "severity": "low", "pc": 0,
                "description": "approve() and transferFrom() selectors both present; no CALLER+EQ guard detected -- confirm whether transferFrom validates msg.sender"}]
        return []

    def _scan_am5(self, instructions: List[Instruction]) -> List[Dict]:
        findings = []
        names = [instr.name for instr in instructions]
        jumpdest_idx: Dict[int, int] = {}
        for i, instr in enumerate(instructions):
            if instr.name == "JUMPDEST":
                jumpdest_idx[instr.pc] = i

        for i, instr in enumerate(instructions):
            if instr.name != "PUSH4" or instr.operand not in CALLBACK_SELECTORS:
                continue
            callback_name = CALLBACK_SELECTORS[instr.operand]
            lookahead_instrs = instructions[i: i + 6]
            lookahead_names  = [x.name for x in lookahead_instrs]
            jumpi_target_pc = None
            if "JUMPI" in lookahead_names:
                ji = lookahead_names.index("JUMPI")
                pb = lookahead_instrs[ji - 1] if ji > 0 else None
                if pb and pb.name in [f"PUSH{n}" for n in range(1, 33)]:
                    jumpi_target_pc = pb.operand
            start_idx = jumpdest_idx.get(jumpi_target_pc, i + 1)
            body = instructions[start_idx: start_idx + _CALLBACK_WINDOW]
            body_names = [x.name for x in body]
            if not any(n in CALL_OPCODES for n in body_names):
                continue
            caller_eq = False
            for j, bname in enumerate(body_names):
                if bname in CALL_OPCODES:
                    break
                if bname == "CALLER" and "EQ" in body_names[j: j + 3]:
                    caller_eq = True
                    break
            if not caller_eq:
                findings.append({"type": "AM5", "severity": "medium", "pc": instr.pc,
                    "description": f"Callback selector {hex(instr.operand)} ({callback_name}) at PC {instr.pc} -- CALL reachable without CALLER+EQ guard; arbitrary callers may trigger the callback"})
        return findings

    def _scan_am7(self, instructions: List[Instruction]) -> List[Dict]:
        """AM7: permissionless SSTORE -- SoK DeFi Attacks camouflage pattern (arXiv:2208.13035)."""
        names = [i.name for i in instructions]
        if "SSTORE" not in names:
            return []
        push4_count = sum(1 for instr in instructions
            if instr.name == "PUSH4"
            and instr.operand not in (_SEL_APPROVE, _SEL_TRANSFER_FROM)
            and instr.operand not in CALLBACK_SELECTORS)
        if push4_count == 0:
            return []
        for i, name in enumerate(names):
            if name == "CALLER" and "EQ" in names[i: i + 5]:
                return []
        return [{"type": "AM7", "severity": "medium", "pc": 0,
            "description": f"{push4_count} public function selector(s) dispatch to code with SSTORE but no CALLER+EQ access control -- state modification may be permissionless (SoK camouflage/proxy pattern)"}]

    def _scan_am8(self, instructions: List[Instruction]) -> List[Dict]:
        """AM8: DELEGATECALL to storage-derived target -- proxy upgrade attack (SoK arXiv:2208.13035)."""
        findings = []
        names = [i.name for i in instructions]
        for i, instr in enumerate(instructions):
            if instr.name != "DELEGATECALL":
                continue
            lookback = names[max(0, i - 15): i]
            if "SLOAD" not in lookback or "PUSH20" in lookback:
                continue
            findings.append({"type": "AM8", "severity": "high", "pc": instr.pc,
                "description": f"DELEGATECALL at PC {instr.pc} preceded by SLOAD (within 15 instructions) without constant PUSH20 target -- implementation slot may be controllable via storage write (proxy upgrade attack, SoK AM8)"})
        return findings

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {"findings": [], "am_types_found": [], "error": error}
