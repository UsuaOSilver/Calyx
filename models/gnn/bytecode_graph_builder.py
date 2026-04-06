"""
models/gnn/bytecode_graph_builder.py

Converts raw EVM bytecode into a graph dict compatible with CalyxGNN.

Approach:
  - Decompose bytecode into basic blocks (maximal sequences between jumps/halts)
  - Nodes  = basic blocks; features = 16-dim opcode-category vector
  - Edges  = control-flow edges (resolved JUMP/JUMPI targets only)

Node feature vector (16 dims):
  [0]  ARITHMETIC  opcode frequency in block (normalized by block size)
  [1]  COMPARISON  opcode frequency
  [2]  MEMORY      opcode frequency
  [3]  STORAGE     opcode frequency
  [4]  CALL_OPS    opcode frequency
  [5]  JUMP_OPS    opcode frequency
  [6]  ENV_INFO    opcode frequency
  [7]  PUSH_POP    opcode frequency
  [8]  has_indirect_jump   (1.0 if block ends with indirect JUMP/JUMPI)
  [9]  has_calldataload    (1.0 if CALLDATALOAD appears in block)
  [10] has_value_op        (1.0 if CALLVALUE / ORIGIN / CALLER in block)
  [11] has_external_call   (1.0 if CALL/DELEGATECALL/CALLCODE/STATICCALL)
  [12] block_size_norm     (num_opcodes / 50.0, clipped to 1.0)
  [13] is_entry_block      (1.0 for block 0)
  [14] has_selfdestruct    (1.0 if SELFDESTRUCT in block)
  [15] has_sstore          (1.0 if SSTORE in block)

Output graph dict matches the schema consumed by dataset.py / collate_graphs():
  {
    "graph_id":  str,
    "label":     0 | 1,
    "category":  str,
    "num_nodes": int,
    "num_edges": int,
    "nodes":     [{"role": "basic_block", "features": [float x 16]}, ...],
    "edges":     [],
    "edge_index": [[src_idx, dst_idx], ...],
    "metadata":  dict,
  }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pyevmasm import disassemble_all, Instruction

# ── Opcode category sets ───────────────────────────────────────────────────────

_ARITHMETIC = {
    "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD",
    "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND",
}
_COMPARISON = {
    "LT", "GT", "SLT", "SGT", "EQ", "ISZERO",
    "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR", "SAR",
}
_MEMORY = {"MLOAD", "MSTORE", "MSTORE8", "MSIZE"}
_STORAGE = {"SLOAD", "SSTORE"}
_CALL_OPS = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2", "SELFDESTRUCT"}
_JUMP_OPS = {"JUMP", "JUMPI", "JUMPDEST"}
_ENV_INFO = {
    "ADDRESS", "BALANCE", "ORIGIN", "CALLER", "CALLVALUE",
    "CALLDATALOAD", "CALLDATASIZE", "CALLDATACOPY",
    "CODESIZE", "CODECOPY", "GASPRICE",
    "EXTCODESIZE", "EXTCODECOPY", "RETURNDATASIZE", "RETURNDATACOPY", "EXTCODEHASH",
    "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY",
    "GASLIMIT", "CHAINID", "SELFBALANCE", "BASEFEE", "GAS",
}
# PUSH1–PUSH32, POP, DUP1–DUP16, SWAP1–SWAP16
_PUSH_POP: set = (
    {f"PUSH{n}" for n in range(1, 33)} |
    {"POP"} |
    {f"DUP{n}" for n in range(1, 17)} |
    {f"SWAP{n}" for n in range(1, 17)}
)

_CATEGORIES = [
    _ARITHMETIC, _COMPARISON, _MEMORY, _STORAGE,
    _CALL_OPS, _JUMP_OPS, _ENV_INFO, _PUSH_POP,
]

# Opcodes that end a basic block
_BLOCK_TERMINATORS = {"JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}
_PUSH_OPCODES = set(range(0x60, 0x80))

# Opcodes used for binary feature computation
_EXTERNAL_CALLS = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}
_VALUE_OPS      = {"CALLVALUE", "ORIGIN", "CALLER"}


# ── BasicBlock dataclass ───────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    idx:        int
    start_pc:   int
    end_pc:     int
    opcodes:    List[Instruction] = field(default_factory=list)


# ── BytecodeGraphBuilder ───────────────────────────────────────────────────────

class BytecodeGraphBuilder:
    """
    Converts EVM bytecode hex into a graph dict ready for CalyxGNN inference
    or dataset generation.
    """

    def build_graph(
        self,
        bytecode_hex: str,
        graph_id:  str = "bytecode_graph",
        label:     int = 0,
        category:  str = "unknown",
        metadata:  Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Full pipeline: bytecode → basic blocks → CFG edges → node features → graph dict.

        Args:
            bytecode_hex: Raw hex string (with or without 0x prefix).
            graph_id:     Unique identifier for this graph.
            label:        Ground-truth label (0=benign, 1=vulnerable).
            category:     Vulnerability category string.
            metadata:     Extra fields to include in graph["metadata"].

        Returns:
            Graph dict compatible with CalyxGNN / collate_graphs().
        """
        hex_str = (
            bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        ).strip()

        if not hex_str:
            return self._minimal_graph(graph_id, label, category, metadata, "empty bytecode")

        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._minimal_graph(graph_id, label, category, metadata, str(e))

        blocks    = self._build_basic_blocks(instructions)
        edges     = self._build_cfg_edges(blocks, instructions)
        nodes     = [self._node_features(b) for b in blocks]

        return {
            "graph_id":   graph_id,
            "label":      label,
            "category":   category,
            "num_nodes":  len(nodes),
            "num_edges":  len(edges),
            "nodes":      nodes,
            "edges":      [],           # edge features not used by CalyxGNN
            "edge_index": edges,
            "metadata":   {
                **(metadata or {}),
                "instruction_count": len(instructions),
                "block_count":       len(blocks),
            },
        }

    # ── Basic block decomposition ──────────────────────────────────────────────

    def _build_basic_blocks(self, instructions: List[Instruction]) -> List[BasicBlock]:
        """
        Split instruction stream into basic blocks.
        A new block starts at:
          - The very first instruction
          - Any JUMPDEST
        A block ends at (inclusive):
          - JUMP / JUMPI / STOP / RETURN / REVERT / INVALID / SELFDESTRUCT
          - The instruction before a JUMPDEST
        """
        if not instructions:
            return []

        blocks: List[BasicBlock] = []
        current: List[Instruction] = []
        block_idx = 0

        for i, instr in enumerate(instructions):
            # Start a new block at JUMPDEST (flush current first)
            if instr.name == "JUMPDEST" and current:
                blocks.append(BasicBlock(
                    idx=block_idx,
                    start_pc=current[0].pc,
                    end_pc=current[-1].pc,
                    opcodes=current,
                ))
                block_idx += 1
                current = []

            current.append(instr)

            # End block at terminators
            if instr.name in _BLOCK_TERMINATORS:
                blocks.append(BasicBlock(
                    idx=block_idx,
                    start_pc=current[0].pc,
                    end_pc=current[-1].pc,
                    opcodes=current,
                ))
                block_idx += 1
                current = []

        # Flush remaining opcodes as a final block
        if current:
            blocks.append(BasicBlock(
                idx=block_idx,
                start_pc=current[0].pc,
                end_pc=current[-1].pc,
                opcodes=current,
            ))

        return blocks

    # ── CFG edge construction ──────────────────────────────────────────────────

    def _build_cfg_edges(
        self,
        blocks: List[BasicBlock],
        instructions: List[Instruction],
    ) -> List[Tuple[int, int]]:
        """
        Build control-flow edges between basic blocks.

        For JUMP: resolve destination if preceded by a PUSH constant.
        For JUMPI: resolved jump target + fall-through to next block.
        Fall-through (non-jump terminators): sequential edge to next block.

        Indirect jumps (runtime-computed destinations) cannot be resolved
        statically — no edge is added for those.
        """
        if not blocks:
            return []

        # Map start_pc → block index for O(1) lookup
        pc_to_block: Dict[int, int] = {b.start_pc: b.idx for b in blocks}

        # Build a flat index: instruction pc → preceding instruction
        pc_to_prev: Dict[int, Optional[Instruction]] = {}
        all_instrs = instructions
        for i, instr in enumerate(all_instrs):
            pc_to_prev[instr.pc] = all_instrs[i - 1] if i > 0 else None

        edges: List[Tuple[int, int]] = []

        for i, block in enumerate(blocks):
            if not block.opcodes:
                continue
            terminator = block.opcodes[-1]
            next_block_idx = i + 1 if i + 1 < len(blocks) else None

            if terminator.name == "JUMP":
                prev = pc_to_prev.get(terminator.pc)
                if prev and prev.opcode in _PUSH_OPCODES:
                    target_pc = prev.operand
                    dst = pc_to_block.get(target_pc)
                    if dst is not None:
                        edges.append((block.idx, dst))
                # Indirect JUMP — no edge

            elif terminator.name == "JUMPI":
                prev = pc_to_prev.get(terminator.pc)
                if prev and prev.opcode in _PUSH_OPCODES:
                    target_pc = prev.operand
                    dst = pc_to_block.get(target_pc)
                    if dst is not None:
                        edges.append((block.idx, dst))
                # Fall-through branch
                if next_block_idx is not None:
                    edges.append((block.idx, next_block_idx))

            elif terminator.name not in {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}:
                # Non-terminator end of block (e.g., block ended because next is JUMPDEST)
                if next_block_idx is not None:
                    edges.append((block.idx, next_block_idx))

        return edges

    # ── Node feature computation ───────────────────────────────────────────────

    def _node_features(self, block: BasicBlock) -> Dict[str, Any]:
        """Compute the 16-dim feature vector for a basic block."""
        opcodes = block.opcodes
        n = len(opcodes) or 1  # avoid /0
        names = {instr.name for instr in opcodes}
        name_list = [instr.name for instr in opcodes]

        # [0–7] Opcode category frequencies (normalized)
        cat_freqs = []
        for cat in _CATEGORIES:
            count = sum(1 for nm in name_list if nm in cat)
            cat_freqs.append(count / n)

        # [8] Indirect jump: block ends with JUMP/JUMPI and preceding is not PUSH
        is_indirect = 0.0
        if opcodes and opcodes[-1].name in {"JUMP", "JUMPI"}:
            prev = opcodes[-2] if len(opcodes) >= 2 else None
            if prev is None or prev.opcode not in _PUSH_OPCODES:
                is_indirect = 1.0

        # [9] CALLDATALOAD present
        has_cdl = 1.0 if "CALLDATALOAD" in names else 0.0

        # [10] Value-sensitive ops (CALLVALUE, ORIGIN, CALLER)
        has_val = 1.0 if names & _VALUE_OPS else 0.0

        # [11] External call
        has_ext = 1.0 if names & _EXTERNAL_CALLS else 0.0

        # [12] Block size (normalized)
        size_norm = min(len(opcodes) / 50.0, 1.0)

        # [13] Entry block
        is_entry = 1.0 if block.idx == 0 else 0.0

        # [14] SELFDESTRUCT
        has_sd = 1.0 if "SELFDESTRUCT" in names else 0.0

        # [15] SSTORE
        has_sstore = 1.0 if "SSTORE" in names else 0.0

        features = cat_freqs + [
            is_indirect, has_cdl, has_val, has_ext,
            size_norm, is_entry, has_sd, has_sstore,
        ]
        assert len(features) == 16, f"expected 16 features, got {len(features)}"

        return {"role": "basic_block", "features": features}

    # ── Fallback for empty/invalid bytecode ───────────────────────────────────

    @staticmethod
    def _minimal_graph(
        graph_id: str,
        label: int,
        category: str,
        metadata: Optional[Dict],
        error: str,
    ) -> Dict[str, Any]:
        """Return a single-node graph with zero features when bytecode is invalid."""
        return {
            "graph_id":   graph_id,
            "label":      label,
            "category":   category,
            "num_nodes":  1,
            "num_edges":  0,
            "nodes":      [{"role": "basic_block", "features": [0.0] * 16}],
            "edges":      [],
            "edge_index": [],
            "metadata":   {**(metadata or {}), "error": error},
        }
