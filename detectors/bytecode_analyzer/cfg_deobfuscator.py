"""
detectors/bytecode_analyzer/cfg_deobfuscator.py

CFG deobfuscator for EVM bytecode — Full SKANF Gap 1.

Two strategies:
1. Constant-fold resolution — simulate push/arithmetic stack within basic block
2. Conservative over-approximation — connect to ALL valid JUMPDEST addresses
   (mirrors SKANF branch table injection)

Usage:
    from detectors.bytecode_analyzer.cfg_deobfuscator import CFGDeobfuscator
    result = CFGDeobfuscator().resolve_cfg(bytecode_hex)
    # result["blocks"], result["edges"], result["resolved"], result["approximated"]
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from pyevmasm import disassemble_all, Instruction

_PUSH_OPCODES: set = set(range(0x60, 0x80))
_TERMINATORS = {"JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}
_FOLDABLE_BINARY = {"ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR", "SHL", "SHR"}


class CFGDeobfuscator:
    """Produces a complete CFG from EVM bytecode by resolving indirect jumps."""

    def resolve_cfg(self, bytecode_hex: str) -> Dict[str, Any]:
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        hex_str = hex_str.strip()
        if not hex_str:
            return self._empty("empty bytecode")
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as exc:
            return self._empty(f"disassemble failed: {exc}")

        jumpdest_pcs: List[int] = [i.pc for i in instructions if i.name == "JUMPDEST"]
        blocks = self._build_blocks(instructions)
        pc_to_block: Dict[int, int] = {b["start_pc"]: b["idx"] for b in blocks}

        raw_edges: List[Tuple[int, int]] = []
        resolved = 0
        approximated = 0

        for i, block in enumerate(blocks):
            if not block["opcodes"]:
                continue
            term = block["opcodes"][-1]
            next_idx = i + 1 if i + 1 < len(blocks) else None

            if term.name not in ("JUMP", "JUMPI"):
                if term.name not in {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}:
                    if next_idx is not None:
                        raw_edges.append((block["idx"], next_idx))
                continue

            target_pc = self._fold_target(block["opcodes"])
            if target_pc is not None:
                resolved += 1
                dst = pc_to_block.get(target_pc)
                if dst is not None:
                    raw_edges.append((block["idx"], dst))
            else:
                approximated += 1
                for jpc in jumpdest_pcs:
                    dst = pc_to_block.get(jpc)
                    if dst is not None:
                        raw_edges.append((block["idx"], dst))

            if term.name == "JUMPI" and next_idx is not None:
                raw_edges.append((block["idx"], next_idx))

        seen: set = set()
        edges: List[List[int]] = []
        for s, d in raw_edges:
            if (s, d) not in seen:
                seen.add((s, d))
                edges.append([s, d])

        return {
            "blocks": blocks, "edges": edges, "jumpdest_pcs": jumpdest_pcs,
            "resolved": resolved, "approximated": approximated, "error": None,
        }

    def _build_blocks(self, instructions):
        blocks, current, idx = [], [], 0
        for instr in instructions:
            if instr.name == "JUMPDEST" and current:
                blocks.append(self._make_block(idx, current))
                idx += 1
                current = []
            current.append(instr)
            if instr.name in _TERMINATORS:
                blocks.append(self._make_block(idx, current))
                idx += 1
                current = []
        if current:
            blocks.append(self._make_block(idx, current))
        return blocks

    @staticmethod
    def _make_block(idx, opcodes):
        return {"idx": idx, "start_pc": opcodes[0].pc, "end_pc": opcodes[-1].pc, "opcodes": opcodes}

    def _fold_target(self, block_opcodes):
        if not block_opcodes:
            return None
        term = block_opcodes[-1]
        body = block_opcodes[:-1]
        stack: List[Optional[int]] = []
        for instr in body:
            name = instr.name
            if instr.opcode in _PUSH_OPCODES:
                stack.append(instr.operand)
            elif name.startswith("DUP") and name[3:].isdigit():
                n = int(name[3:])
                stack.append(stack[-n] if len(stack) >= n else None)
            elif name.startswith("SWAP") and name[4:].isdigit():
                n = int(name[4:])
                if len(stack) > n:
                    stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]
            elif name == "POP":
                if stack: stack.pop()
            elif name in _FOLDABLE_BINARY:
                b = stack.pop() if stack else None
                a = stack.pop() if stack else None
                if a is not None and b is not None:
                    stack.append(self._fold(name, a, b))
                else:
                    stack.append(None)
            else:
                stack.append(None)

        if term.name == "JUMP":
            val = stack[-1] if stack else None
        else:  # JUMPI
            val = stack[-2] if len(stack) >= 2 else None
        return val if isinstance(val, int) else None

    @staticmethod
    def _fold(op, a, b):
        mask = 0xFFFFFFFFFFFFFFFF
        if op == "ADD":  return (a + b) & mask
        if op == "SUB":  return (a - b) & mask
        if op == "MUL":  return (a * b) & mask
        if op == "DIV":  return a // b if b != 0 else 0
        if op == "MOD":  return a % b  if b != 0 else 0
        if op == "AND":  return a & b
        if op == "OR":   return a | b
        if op == "XOR":  return a ^ b
        if op == "SHL":  return 0 if a >= 256 else (b << a) & mask
        if op == "SHR":  return 0 if a >= 256 else b >> a
        return 0

    @staticmethod
    def _empty(error):
        return {"blocks": [], "edges": [], "jumpdest_pcs": [], "resolved": 0, "approximated": 0, "error": error}
