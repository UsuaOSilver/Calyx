"""
detectors/bytecode_analyzer/cfg_deobfuscator.py

CFG deobfuscator for EVM bytecode — Full SKANF Gap 1.

Resolves indirect JUMP/JUMPI destinations that CFGProfiler cannot determine
statically.  Two strategies, applied in order:

1. Constant-fold resolution
   If the jump target can be computed from a short push/arithmetic chain within
   the same basic block (e.g. PUSH1 5, PUSH1 3, ADD, JUMP → target = 8),
   resolve it exactly.  Covers dispatchers that compute targets from constant
   tables embedded in the bytecode.

2. Conservative over-approximation (SKANF branch table semantics)
   For truly runtime-dynamic targets (CALLDATALOAD, SLOAD, etc.) where the
   destination cannot be determined without execution, connect the block to
   ALL valid JUMPDEST addresses in the contract.  This mirrors what SKANF's
   branch table injection achieves: every possible destination becomes
   statically reachable.  The result is a complete (over-approximate) CFG
   with no missing edges — exactly what the GNN and taint analyzer need.

Usage:
    from detectors.bytecode_analyzer.cfg_deobfuscator import CFGDeobfuscator

    deob = CFGDeobfuscator()
    result = deob.resolve_cfg(bytecode_hex)

    # result["blocks"]       — list of block dicts {idx, start_pc, end_pc, opcodes}
    # result["edges"]        — [[src_idx, dst_idx], ...]  (complete CFG)
    # result["resolved"]     — indirect jumps resolved by constant folding
    # result["approximated"] — indirect jumps handled by over-approximation
    # result["jumpdest_pcs"] — all valid JUMPDEST program counters
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pyevmasm import disassemble_all, Instruction

# PUSH1–PUSH32: opcodes 0x60–0x7f
_PUSH_OPCODES: set = set(range(0x60, 0x80))

# Block terminators
_TERMINATORS = {
    "JUMP", "JUMPI",
    "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT",
}

# Binary opcodes we can constant-fold (both operands must be known integers)
_FOLDABLE_BINARY = {
    "ADD", "SUB", "MUL", "DIV", "MOD",
    "AND", "OR", "XOR",
    "SHL", "SHR",
}


class CFGDeobfuscator:
    """
    Produces a complete control-flow graph from EVM bytecode by resolving
    indirect jump targets that are missing from a naive static disassembly.
    """

    def resolve_cfg(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Fully resolve the CFG for the given bytecode.

        Returns:
            {
                "blocks":        List[dict]  — {idx, start_pc, end_pc, opcodes}
                "edges":         List[[int, int]]  — [src_block_idx, dst_block_idx]
                "jumpdest_pcs":  List[int]   — all valid JUMPDEST PCs
                "resolved":      int         — jumps resolved via constant folding
                "approximated":  int         — jumps over-approximated to all JUMPDESTs
                "error":         Optional[str]
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
                # Non-jump block: sequential fall-through unless it halts
                if term.name not in {
                    "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"
                }:
                    if next_idx is not None:
                        raw_edges.append((block["idx"], next_idx))
                continue

            # Try constant-fold resolution within this block's opcode sequence
            target_pc = self._fold_target(block["opcodes"])

            if target_pc is not None:
                resolved += 1
                dst = pc_to_block.get(target_pc)
                if dst is not None:
                    raw_edges.append((block["idx"], dst))
            else:
                # Over-approximate: connect to every valid JUMPDEST
                approximated += 1
                for jpc in jumpdest_pcs:
                    dst = pc_to_block.get(jpc)
                    if dst is not None:
                        raw_edges.append((block["idx"], dst))

            # JUMPI also has a fall-through branch (condition = false)
            if term.name == "JUMPI" and next_idx is not None:
                raw_edges.append((block["idx"], next_idx))

        # Deduplicate while preserving order
        seen: set = set()
        edges: List[List[int]] = []
        for s, d in raw_edges:
            if (s, d) not in seen:
                seen.add((s, d))
                edges.append([s, d])

        return {
            "blocks":       blocks,
            "edges":        edges,
            "jumpdest_pcs": jumpdest_pcs,
            "resolved":     resolved,
            "approximated": approximated,
            "error":        None,
        }

    # ── Block decomposition ────────────────────────────────────────────────────

    def _build_blocks(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """Split a flat instruction stream into basic blocks."""
        blocks: List[Dict[str, Any]] = []
        current: List[Instruction] = []
        idx = 0

        for instr in instructions:
            # JUMPDEST starts a new block (flush the previous one first)
            if instr.name == "JUMPDEST" and current:
                blocks.append(self._make_block(idx, current))
                idx += 1
                current = []

            current.append(instr)

            # Terminators end the current block
            if instr.name in _TERMINATORS:
                blocks.append(self._make_block(idx, current))
                idx += 1
                current = []

        if current:
            blocks.append(self._make_block(idx, current))

        return blocks

    @staticmethod
    def _make_block(idx: int, opcodes: List[Instruction]) -> Dict[str, Any]:
        return {
            "idx":      idx,
            "start_pc": opcodes[0].pc,
            "end_pc":   opcodes[-1].pc,
            "opcodes":  opcodes,
        }

    # ── Constant-fold target resolution ───────────────────────────────────────

    def _fold_target(self, block_opcodes: List[Instruction]) -> Optional[int]:
        """
        Simulate a minimal constant-propagation stack over block_opcodes
        (excluding the terminal JUMP/JUMPI) to determine whether the jump
        destination is a compile-time constant.

        Returns the resolved target PC as an int, or None if unresolvable.
        """
        if not block_opcodes:
            return None

        term = block_opcodes[-1]
        body = block_opcodes[:-1]  # everything before JUMP/JUMPI

        # Stack of Optional[int]: None = unknown/tainted, int = known constant
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
                if stack:
                    stack.pop()

            elif name in _FOLDABLE_BINARY:
                b = stack.pop() if stack else None
                a = stack.pop() if stack else None
                if a is not None and b is not None:
                    stack.append(self._fold(name, a, b))
                else:
                    stack.append(None)

            else:
                # Unknown opcode — assume it produces one unknown value
                # (conservative: we don't model stack depth of every opcode)
                stack.append(None)

        # For JUMP:  stack top  = destination
        # For JUMPI: stack[-2]  = destination, stack[-1] = condition
        if term.name == "JUMP":
            val = stack[-1] if stack else None
        else:  # JUMPI
            val = stack[-2] if len(stack) >= 2 else None

        return val if isinstance(val, int) else None

    # ── Constant folding arithmetic ────────────────────────────────────────────

    @staticmethod
    def _fold(op: str, a: int, b: int) -> int:
        mask = 0xFFFFFFFFFFFFFFFF
        if op == "ADD":  return (a + b) & mask
        if op == "SUB":  return (a - b) & mask
        if op == "MUL":  return (a * b) & mask
        if op == "DIV":  return a // b if b != 0 else 0
        if op == "MOD":  return a % b  if b != 0 else 0
        if op == "AND":  return a & b
        if op == "OR":   return a | b
        if op == "XOR":  return a ^ b
        if op == "SHL":  return (b << min(a, 255)) & mask if a < 256 else 0
        if op == "SHR":  return (b >> min(a, 255)) if a < 256 else 0
        return 0

    # ── Fallback ───────────────────────────────────────────────────────────────

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {
            "blocks":       [],
            "edges":        [],
            "jumpdest_pcs": [],
            "resolved":     0,
            "approximated": 0,
            "error":        error,
        }
