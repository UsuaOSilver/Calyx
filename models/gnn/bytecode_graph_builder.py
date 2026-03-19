"""
models/gnn/bytecode_graph_builder.py

Converts raw EVM bytecode into a graph dict compatible with CalyxGNN.

Node feature vector (16 dims):
  [0-7]  Opcode category frequencies (arithmetic, comparison, memory, storage,
         call_ops, jump_ops, env_info, push_pop) — normalized by block size
  [8]    has_indirect_jump   (1.0 if block ends with indirect JUMP/JUMPI)
  [9]    has_calldataload    (1.0 if CALLDATALOAD appears in block)
  [10]   has_value_op        (1.0 if CALLVALUE/ORIGIN/CALLER in block)
  [11]   has_external_call   (1.0 if CALL/DELEGATECALL/CALLCODE/STATICCALL)
  [12]   block_size_norm     (num_opcodes / 50.0, clipped to 1.0)
  [13]   is_entry_block      (1.0 for block 0)
  [14]   has_selfdestruct    (1.0 if SELFDESTRUCT in block)
  [15]   has_sstore          (1.0 if SSTORE in block)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from pyevmasm import disassemble_all, Instruction

_ARITHMETIC = {"ADD","MUL","SUB","DIV","SDIV","MOD","SMOD","ADDMOD","MULMOD","EXP","SIGNEXTEND"}
_COMPARISON = {"LT","GT","SLT","SGT","EQ","ISZERO","AND","OR","XOR","NOT","BYTE","SHL","SHR","SAR"}
_MEMORY     = {"MLOAD","MSTORE","MSTORE8","MSIZE"}
_STORAGE    = {"SLOAD","SSTORE"}
_CALL_OPS   = {"CALL","CALLCODE","DELEGATECALL","STATICCALL","CREATE","CREATE2","SELFDESTRUCT"}
_JUMP_OPS   = {"JUMP","JUMPI","JUMPDEST"}
_ENV_INFO   = {
    "ADDRESS","BALANCE","ORIGIN","CALLER","CALLVALUE","CALLDATALOAD","CALLDATASIZE",
    "CALLDATACOPY","CODESIZE","CODECOPY","GASPRICE","EXTCODESIZE","EXTCODECOPY",
    "RETURNDATASIZE","RETURNDATACOPY","EXTCODEHASH","BLOCKHASH","COINBASE","TIMESTAMP",
    "NUMBER","DIFFICULTY","GASLIMIT","CHAINID","SELFBALANCE","BASEFEE","GAS",
}
_PUSH_POP: set = (
    {f"PUSH{n}" for n in range(1,33)} | {"POP"} |
    {f"DUP{n}" for n in range(1,17)} | {f"SWAP{n}" for n in range(1,17)}
)
_CATEGORIES = [_ARITHMETIC,_COMPARISON,_MEMORY,_STORAGE,_CALL_OPS,_JUMP_OPS,_ENV_INFO,_PUSH_POP]
_BLOCK_TERMINATORS = {"JUMP","JUMPI","STOP","RETURN","REVERT","INVALID","SELFDESTRUCT"}
_PUSH_OPCODES = set(range(0x60, 0x80))
_EXTERNAL_CALLS = {"CALL","CALLCODE","DELEGATECALL","STATICCALL"}
_VALUE_OPS      = {"CALLVALUE","ORIGIN","CALLER"}


@dataclass
class BasicBlock:
    idx: int
    start_pc: int
    end_pc: int
    opcodes: List[Instruction] = field(default_factory=list)


class BytecodeGraphBuilder:
    """Converts EVM bytecode hex into a graph dict ready for CalyxGNN inference."""

    def build_graph(self, bytecode_hex: str, graph_id: str = "bytecode_graph",
                    label: int = 0, category: str = "unknown",
                    metadata: Optional[Dict] = None) -> Dict[str, Any]:
        hex_str = (bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex).strip()
        if not hex_str:
            return self._minimal_graph(graph_id, label, category, metadata, "empty bytecode")
        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._minimal_graph(graph_id, label, category, metadata, str(e))

        blocks = self._build_basic_blocks(instructions)
        edges  = self._build_cfg_edges(blocks, instructions)
        nodes  = [self._node_features(b) for b in blocks]

        return {
            "graph_id": graph_id, "label": label, "category": category,
            "num_nodes": len(nodes), "num_edges": len(edges),
            "nodes": nodes, "edges": [], "edge_index": edges,
            "metadata": {**(metadata or {}), "instruction_count": len(instructions),
                         "block_count": len(blocks)},
        }

    def _build_basic_blocks(self, instructions) -> List[BasicBlock]:
        blocks, current, block_idx = [], [], 0
        for instr in instructions:
            if instr.name == "JUMPDEST" and current:
                blocks.append(BasicBlock(block_idx, current[0].pc, current[-1].pc, current))
                block_idx += 1
                current = []
            current.append(instr)
            if instr.name in _BLOCK_TERMINATORS:
                blocks.append(BasicBlock(block_idx, current[0].pc, current[-1].pc, current))
                block_idx += 1
                current = []
        if current:
            blocks.append(BasicBlock(block_idx, current[0].pc, current[-1].pc, current))
        return blocks

    def _build_cfg_edges(self, blocks, instructions) -> List[Tuple[int, int]]:
        if not blocks:
            return []
        pc_to_block = {b.start_pc: b.idx for b in blocks}
        pc_to_prev  = {instr.pc: (instructions[i-1] if i > 0 else None)
                       for i, instr in enumerate(instructions)}
        edges = []
        for i, block in enumerate(blocks):
            if not block.opcodes:
                continue
            term = block.opcodes[-1]
            next_idx = i + 1 if i + 1 < len(blocks) else None
            if term.name == "JUMP":
                prev = pc_to_prev.get(term.pc)
                if prev and prev.opcode in _PUSH_OPCODES:
                    dst = pc_to_block.get(prev.operand)
                    if dst is not None:
                        edges.append((block.idx, dst))
            elif term.name == "JUMPI":
                prev = pc_to_prev.get(term.pc)
                if prev and prev.opcode in _PUSH_OPCODES:
                    dst = pc_to_block.get(prev.operand)
                    if dst is not None:
                        edges.append((block.idx, dst))
                if next_idx is not None:
                    edges.append((block.idx, next_idx))
            elif term.name not in {"STOP","RETURN","REVERT","INVALID","SELFDESTRUCT"}:
                if next_idx is not None:
                    edges.append((block.idx, next_idx))
        return edges

    def _node_features(self, block: BasicBlock) -> Dict[str, Any]:
        opcodes = block.opcodes
        n = len(opcodes) or 1
        names = {instr.name for instr in opcodes}
        name_list = [instr.name for instr in opcodes]
        cat_freqs = [sum(1 for nm in name_list if nm in cat) / n for cat in _CATEGORIES]
        is_indirect = 0.0
        if opcodes and opcodes[-1].name in {"JUMP","JUMPI"}:
            prev = opcodes[-2] if len(opcodes) >= 2 else None
            if prev is None or prev.opcode not in _PUSH_OPCODES:
                is_indirect = 1.0
        features = cat_freqs + [
            is_indirect,
            1.0 if "CALLDATALOAD" in names else 0.0,
            1.0 if names & _VALUE_OPS else 0.0,
            1.0 if names & _EXTERNAL_CALLS else 0.0,
            min(len(opcodes) / 50.0, 1.0),
            1.0 if block.idx == 0 else 0.0,
            1.0 if "SELFDESTRUCT" in names else 0.0,
            1.0 if "SSTORE" in names else 0.0,
        ]
        assert len(features) == 16
        return {"role": "basic_block", "features": features}

    @staticmethod
    def _minimal_graph(graph_id, label, category, metadata, error):
        return {
            "graph_id": graph_id, "label": label, "category": category,
            "num_nodes": 1, "num_edges": 0,
            "nodes": [{"role": "basic_block", "features": [0.0]*16}],
            "edges": [], "edge_index": [],
            "metadata": {**(metadata or {}), "error": error},
        }
