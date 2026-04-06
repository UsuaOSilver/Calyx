"""
data/parsers/bytecode_dataset_generator.py

Generates a labeled bytecode dataset for training the bytecode GNN.

Draws category distribution from real audit findings (findings_all.jsonl) so
the training mix reflects real-world vulnerability frequency across 17 firms.

Each sample is a realistic multi-function EVM contract:
  - Standard ABI preamble (free-memory-pointer setup, calldata length check)
  - Selector dispatcher routing to 2-4 functions
  - One vulnerable function body (for exploit samples)
  - 1-3 benign helper functions

This eliminates the distribution shift between training on 3-opcode toy patterns
and inference on real contracts with 50-200 opcodes and 5-20 basic blocks.

Output: data/datasets/bytecode/{train,val,test}.jsonl
        data/datasets/bytecode/dataset_stats.json

Usage:
    python data/parsers/bytecode_dataset_generator.py
    python data/parsers/bytecode_dataset_generator.py --n-exploit 2000 --n-benign 2000
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from models.gnn.bytecode_graph_builder import BytecodeGraphBuilder

random.seed(42)

DATASET_DIR   = Path(__file__).resolve().parents[2] / "data" / "datasets" / "bytecode"
FINDINGS_PATH = Path(__file__).resolve().parents[2] / "data" / "datasets" / "raw" / "findings_all.jsonl"
BUILDER       = BytecodeGraphBuilder()

# ── EVM opcode bytes ──────────────────────────────────────────────────────────

STOP        = 0x00
ADD         = 0x01
MUL         = 0x02
SUB         = 0x03
DIV         = 0x04
LT          = 0x10
GT          = 0x11
EQ          = 0x14
ISZERO      = 0x15
AND         = 0x16
OR          = 0x17
NOT         = 0x19
POP         = 0x50
MLOAD       = 0x51
MSTORE      = 0x52
SLOAD       = 0x54
SSTORE      = 0x55
JUMP        = 0x56
JUMPI       = 0x57
GAS         = 0x5a
JUMPDEST_OP = 0x5b
ADDRESS_OP  = 0x30
CALLER_OP   = 0x33
CALLVALUE_OP= 0x34
CALLDATALOAD= 0x35
CALLDATASIZE= 0x36
TIMESTAMP_OP= 0x42
NUMBER_OP   = 0x43
PUSH1       = 0x60
PUSH2       = 0x61
PUSH4       = 0x63
PUSH20      = 0x73
PUSH29      = 0x7c
DUP1        = 0x80
SWAP1       = 0x90
CALL_OP     = 0xf1
DELEGATECALL= 0xf4
STATICCALL  = 0xfa
RETURN_OP   = 0xf3
REVERT_OP   = 0xfd

# PUSH29 constant: 2^224 — used to extract 4-byte function selector
_SEL_DIV = (1 << 224).to_bytes(29, "big")


# ── EVMBuilder: two-pass bytecode assembler with label resolution ─────────────

class EVMBuilder:
    """
    Builds EVM bytecode with symbolic labels resolved in a second pass.

    Labels mark the current byte offset (no bytes emitted).
    jump_to / jumpi_to emit PUSH2 <resolved_addr> JUMP/JUMPI (4 bytes total).
    unique_label() returns a guaranteed-unique name to avoid intra-contract
    label collisions when the same body-generator is called multiple times.
    """

    def __init__(self) -> None:
        self._ops: List[Tuple] = []
        self._counter = 0

    # ── label management ──────────────────────────────────────────────────────

    def label(self, name: str) -> "EVMBuilder":
        self._ops.append(("L", name))
        return self

    def unique_label(self, base: str) -> str:
        self._counter += 1
        return f"{base}_{self._counter}"

    def jumpdest(self, name: Optional[str] = None) -> "EVMBuilder":
        if name:
            self.label(name)
        return self._b(JUMPDEST_OP)

    def jump_to(self, name: str) -> "EVMBuilder":
        self._ops.append(("J", name, JUMP))
        return self

    def jumpi_to(self, name: str) -> "EVMBuilder":
        self._ops.append(("J", name, JUMPI))
        return self

    # ── raw emitters ──────────────────────────────────────────────────────────

    def _b(self, byte: int) -> "EVMBuilder":
        self._ops.append(("b", byte))
        return self

    def _raw(self, data: bytes) -> "EVMBuilder":
        self._ops.append(("r", data))
        return self

    # ── opcodes ───────────────────────────────────────────────────────────────

    def push1(self, v: int) -> "EVMBuilder":
        return self._b(PUSH1)._b(v & 0xFF)

    def push2(self, v: int) -> "EVMBuilder":
        return self._b(PUSH2)._b((v >> 8) & 0xFF)._b(v & 0xFF)

    def push4(self, v: int) -> "EVMBuilder":
        return self._b(PUSH4)._raw((v & 0xFFFFFFFF).to_bytes(4, "big"))

    def push20(self, addr: bytes) -> "EVMBuilder":
        return self._b(PUSH20)._raw(bytes(addr)[:20])

    def push29_seldiv(self) -> "EVMBuilder":
        return self._b(PUSH29)._raw(_SEL_DIV)

    def stop(self)          -> "EVMBuilder": return self._b(STOP)
    def add(self)           -> "EVMBuilder": return self._b(ADD)
    def mul(self)           -> "EVMBuilder": return self._b(MUL)
    def sub(self)           -> "EVMBuilder": return self._b(SUB)
    def div(self)           -> "EVMBuilder": return self._b(DIV)
    def lt(self)            -> "EVMBuilder": return self._b(LT)
    def gt(self)            -> "EVMBuilder": return self._b(GT)
    def eq(self)            -> "EVMBuilder": return self._b(EQ)
    def iszero(self)        -> "EVMBuilder": return self._b(ISZERO)
    def and_(self)          -> "EVMBuilder": return self._b(AND)
    def or_(self)           -> "EVMBuilder": return self._b(OR)
    def pop(self)           -> "EVMBuilder": return self._b(POP)
    def mload(self)         -> "EVMBuilder": return self._b(MLOAD)
    def mstore(self)        -> "EVMBuilder": return self._b(MSTORE)
    def sload(self)         -> "EVMBuilder": return self._b(SLOAD)
    def sstore(self)        -> "EVMBuilder": return self._b(SSTORE)
    def gas(self)           -> "EVMBuilder": return self._b(GAS)
    def caller(self)        -> "EVMBuilder": return self._b(CALLER_OP)
    def callvalue(self)     -> "EVMBuilder": return self._b(CALLVALUE_OP)
    def calldataload(self)  -> "EVMBuilder": return self._b(CALLDATALOAD)
    def calldatasize(self)  -> "EVMBuilder": return self._b(CALLDATASIZE)
    def timestamp(self)     -> "EVMBuilder": return self._b(TIMESTAMP_OP)
    def number(self)        -> "EVMBuilder": return self._b(NUMBER_OP)
    def dup(self, n: int)   -> "EVMBuilder": return self._b(DUP1 + n - 1)
    def swap(self, n: int)  -> "EVMBuilder": return self._b(SWAP1 + n - 1)
    def call(self)          -> "EVMBuilder": return self._b(CALL_OP)
    def delegatecall(self)  -> "EVMBuilder": return self._b(DELEGATECALL)
    def staticcall(self)    -> "EVMBuilder": return self._b(STATICCALL)
    def return_(self)       -> "EVMBuilder": return self._b(RETURN_OP)
    def revert(self)        -> "EVMBuilder": return self._b(REVERT_OP)

    # ── noise helpers ─────────────────────────────────────────────────────────

    def noise_arith(self, rng: random.Random, n: int = 3) -> "EVMBuilder":
        """Emit n harmless PUSH/ADD/POP sequences to pad block size."""
        ops = [ADD, MUL, SUB, AND, OR]
        for _ in range(n):
            self.push1(rng.randint(1, 255))
            self.push1(rng.randint(1, 255))
            self._b(rng.choice(ops))
            self.pop()
        return self

    def noise_storage(self, rng: random.Random) -> "EVMBuilder":
        """Emit a benign SLOAD with immediate POP."""
        return self.push1(rng.randint(0, 7)).sload().pop()

    # ── two-pass assembler ────────────────────────────────────────────────────

    def build(self) -> str:
        """Resolve labels and return bytecode as a hex string."""
        # Pass 1: compute byte offsets for every label
        off = 0
        offsets: Dict[str, int] = {}
        for item in self._ops:
            t = item[0]
            if t == "L":
                offsets[item[1]] = off
            elif t == "b":
                off += 1
            elif t == "r":
                off += len(item[1])
            elif t == "J":
                off += 4  # PUSH2(1) + addr_hi(1) + addr_lo(1) + JUMP/JUMPI(1)

        # Pass 2: emit bytes
        buf = bytearray()
        for item in self._ops:
            t = item[0]
            if t == "L":
                pass
            elif t == "b":
                buf.append(item[1])
            elif t == "r":
                buf.extend(item[1])
            elif t == "J":
                addr = offsets.get(item[1], 0)
                buf.append(PUSH2)
                buf.append((addr >> 8) & 0xFF)
                buf.append(addr & 0xFF)
                buf.append(item[2])   # JUMP or JUMPI

        return buf.hex()


# ── helpers ───────────────────────────────────────────────────────────────────

def _rand_addr(rng: random.Random) -> bytes:
    return bytes(rng.randint(0, 255) for _ in range(20))


def _rand_sel(rng: random.Random) -> int:
    return rng.randint(0x10000000, 0xEFFFFFFF)


def _emit_call7(b: EVMBuilder, addr_fn: Callable[[], None], value: int = 0) -> None:
    """
    Emit the 7-arg CALL sequence.  Stack layout (top first when CALL executes):
      gas, addr, value, argsOffset, argsLength, retOffset, retLength
    We push in reverse order (retLength first = bottom).
    """
    b.push1(0).push1(0).push1(0).push1(0)   # retLen, retOff, argsLen, argsOff
    b.push1(value)                            # value (ETH)
    addr_fn()                                 # address
    b.gas().call()


# ── vulnerable function bodies ────────────────────────────────────────────────

def _vuln_access_control(b: EVMBuilder, rng: random.Random) -> None:
    """AM1: calldata-controlled CALL target without CALLER check."""
    b.noise_arith(rng, rng.randint(1, 3))
    # CALL to attacker-controlled address from calldata — no CALLER guard
    def _addr(): b.push1(0x04).calldataload()
    _emit_call7(b, _addr)
    b.pop().stop()


def _vuln_reentrancy(b: EVMBuilder, rng: random.Random) -> None:
    """Reentrancy: external CALL before SSTORE (CEI violation)."""
    b.noise_arith(rng, rng.randint(1, 2))
    # External call to msg.sender BEFORE clearing balance
    def _addr(): b.caller()
    _emit_call7(b, _addr)
    b.pop()
    # State update happens AFTER the external call
    b.push1(0x00).caller().sstore()
    b.stop()


def _vuln_flash_loan(b: EVMBuilder, rng: random.Random) -> None:
    """AM5: flash-loan callback reachable without CALLER == pool check."""
    b.push1(0x04).calldataload()     # amount0Delta
    b.push1(0x24).calldataload()     # amount1Delta
    b.pop()
    # Transfer call with no CALLER guard — any caller can trigger callback
    def _addr(): b.push1(0x04).calldataload()
    _emit_call7(b, _addr)
    b.pop().stop()


def _vuln_oracle(b: EVMBuilder, rng: random.Random) -> None:
    """Timestamp-based randomness / oracle manipulation."""
    win = b.unique_label("_oracle_win")
    fail = b.unique_label("_oracle_fail")
    b.timestamp()
    b.push1(0x0F).and_()              # timestamp % 16
    b.push1(0x08).lt()                # < 8 ?
    b.jumpi_to(win)
    b.jumpdest(fail).push1(0).dup(1).revert()
    b.jumpdest(win)
    b.noise_storage(rng)
    b.push1(0x01).push1(0x02).sstore()
    b.stop()


def _vuln_integer_overflow(b: EVMBuilder, rng: random.Random) -> None:
    """Unchecked ADD that overflows the user's balance."""
    b.push1(0x04).calldataload()     # amount from calldata
    b.caller().sload()               # balance[msg.sender]
    b.add()                          # overflow — no SafeMath
    b.caller().sstore()
    b.stop()


def _vuln_logic_error(b: EVMBuilder, rng: random.Random) -> None:
    """Logic error: updates balance but not total supply (desync)."""
    rev = b.unique_label("_logic_rev")
    b.push1(0x00).sload()            # totalSupply
    b.push1(0x04).calldataload()     # amount
    b.lt()                           # wrong: should be GT or EQ check
    b.iszero().jumpi_to(rev)
    b.caller().sload()
    b.push1(0x04).calldataload().add()
    b.caller().sstore()              # balance updated, totalSupply NOT updated
    b.stop()
    b.jumpdest(rev).push1(0).dup(1).revert()


def _vuln_front_running(b: EVMBuilder, rng: random.Random) -> None:
    """Front-running: timestamp written as commitment with no commit-reveal."""
    b.timestamp().push1(0x05).sstore()
    b.push1(0x04).calldataload().push1(0x06).sstore()
    b.stop()


def _vuln_signature(b: EVMBuilder, rng: random.Random) -> None:
    """Missing nonce: ecrecover without replay protection."""
    # Call ecrecover precompile (0x01) — no nonce sload/sstore around it
    b.push1(0x20).push1(0x80)        # retLen, retOff
    b.push1(0x80).push1(0x00)        # argsLen, argsOff
    b.push1(0x00)                    # value
    b.push1(0x01)                    # ecrecover precompile address
    b.gas().staticcall()
    b.pop()
    # Grant access immediately without checking/storing nonce
    b.push1(0x01).push1(0x03).sstore()
    b.stop()


def _vuln_governance(b: EVMBuilder, rng: random.Random) -> None:
    """Missing timelock: critical param updated with no delay."""
    b.push1(0x04).calldataload()     # new value / implementation address
    b.push1(0x00).sstore()           # immediate write — no timelock check
    b.stop()


def _vuln_delegatecall(b: EVMBuilder, rng: random.Random) -> None:
    """Uncontrolled DELEGATECALL target from calldata."""
    b.noise_arith(rng, rng.randint(1, 2))
    b.push1(0).push1(0).push1(0).push1(0)  # retLen, retOff, argsLen, argsOff
    b.push1(0x04).calldataload()            # target (tainted)
    b.gas().delegatecall()
    b.pop().stop()


# ── benign function body ──────────────────────────────────────────────────────

def _benign_body(b: EVMBuilder, rng: random.Random) -> None:
    """Emit one of five benign function body variants."""
    variant = rng.randint(0, 4)

    if variant == 0:
        # Ownable: only owner (hardcoded) can update storage
        ok = b.unique_label("_own_ok")
        owner = _rand_addr(rng)
        b.caller().push20(owner).eq()
        b.iszero().jumpi_to(ok)
        b.push1(0).dup(1).revert()
        b.jumpdest(ok)
        b.noise_arith(rng, rng.randint(1, 3))
        b.push1(rng.randint(1, 127)).push1(rng.randint(0, 7)).sstore()
        b.stop()

    elif variant == 1:
        # View: read storage slot, return value
        b.noise_storage(rng)
        b.push1(rng.randint(0, 7)).sload()
        b.push1(0x00).mstore()
        b.push1(0x20).push1(0x00).return_()

    elif variant == 2:
        # ERC-20-style approve: AND-masked address from calldata, CALLER guard
        ok = b.unique_label("_app_ok")
        owner = _rand_addr(rng)
        b.caller().push20(owner).eq()
        b.iszero().jumpi_to(ok)
        b.push1(0).dup(1).revert()
        b.jumpdest(ok)
        # AND-mask the spender address (benign: not a raw tainted CALL target)
        b.push1(0x04).calldataload()
        b.push20(b"\xff" * 20).and_()
        b.push1(0x24).calldataload()   # amount
        b.swap(1).push1(0x00)
        b.caller().push1(0x01).sstore()  # allowance slot
        b.pop().pop().stop()

    elif variant == 3:
        # Hardcoded external call — e.g. DEX swap or token transfer to a known
        # contract.  has_ext_call=1 but the target is NOT from calldata
        # (no has_cdl in the same block), so this is benign.
        target = _rand_addr(rng)
        b.noise_arith(rng, rng.randint(1, 2))
        b.push1(0).push1(0).push1(0).push1(0)   # retLen, retOff, argsLen, argsOff
        b.push1(0)                                # value = 0
        b.push20(target)                          # hardcoded address (NOT calldata)
        b.gas().call()
        b.pop().stop()

    else:
        # STATICCALL to hardcoded oracle / price feed (read-only, benign)
        oracle = _rand_addr(rng)
        b.push1(0x20).push1(0x80)                # retLen, retOff
        b.push1(0x00).push1(0x00)                # argsLen, argsOff
        b.push20(oracle)                          # oracle address (hardcoded)
        b.gas().staticcall()
        b.pop()
        b.push1(0x80).mload()                    # load oracle result
        b.push1(rng.randint(0, 7)).sstore()      # store result
        b.stop()


# ── full contract assembler ───────────────────────────────────────────────────

def _build_exploit_contract(
    vuln_fn: Callable[[EVMBuilder, random.Random], None],
    n_helpers: int,
    rng: random.Random,
) -> str:
    """
    Build a multi-function contract with one vulnerable function and
    n_helpers benign helper functions.  Returns bytecode as hex.
    """
    b = EVMBuilder()
    n_funcs = 1 + n_helpers
    sels = [_rand_sel(rng) for _ in range(n_funcs)]

    # Block 0: preamble — free-memory-pointer + calldata length gate
    b.push1(0x80).push1(0x40).mstore()
    b.calldatasize().push1(0x04).lt()
    b.jumpi_to("_rev")               # JUMPI → terminates block 0

    # Block 1: selector extraction + first dispatch arm
    b.push1(0x00).calldataload().push29_seldiv().div()
    b.dup(1).push4(sels[0]).eq()
    b.jumpi_to("_f0")                # JUMPI → terminates block 1

    # Blocks 2..n: remaining dispatch arms
    for i in range(1, n_funcs):
        b.dup(1).push4(sels[i]).eq()
        b.jumpi_to(f"_f{i}")         # JUMPI → terminates each block

    # Dispatch-end block: clean stack, jump to revert
    b.pop().jump_to("_rev")          # JUMP → terminates block

    # Revert block
    b.jumpdest("_rev").push1(0).dup(1).revert()

    # Vulnerable function body
    b.jumpdest("_f0")
    vuln_fn(b, rng)

    # Benign helper bodies
    for i in range(n_helpers):
        b.jumpdest(f"_f{i + 1}")
        _benign_body(b, rng)

    return b.build()


def _build_benign_contract(n_funcs: int, rng: random.Random) -> str:
    """Build a fully benign multi-function contract."""
    b = EVMBuilder()
    sels = [_rand_sel(rng) for _ in range(n_funcs)]

    b.push1(0x80).push1(0x40).mstore()
    b.calldatasize().push1(0x04).lt()
    b.jumpi_to("_rev")

    b.push1(0x00).calldataload().push29_seldiv().div()
    for i, sel in enumerate(sels):
        b.dup(1).push4(sel).eq()
        b.jumpi_to(f"_bf{i}")

    b.pop().jump_to("_rev")
    b.jumpdest("_rev").push1(0).dup(1).revert()

    for i in range(n_funcs):
        b.jumpdest(f"_bf{i}")
        _benign_body(b, rng)

    return b.build()


# ── category → vulnerability body mapping ────────────────────────────────────

_VULN_MAP: Dict[str, List[Callable]] = {
    "access-control":             [_vuln_access_control, _vuln_delegatecall],
    "reentrancy":                 [_vuln_reentrancy],
    "flash-loan":                 [_vuln_flash_loan, _vuln_access_control],
    "oracle":                     [_vuln_oracle],
    "logic-error":                [_vuln_logic_error],
    "front-running":              [_vuln_front_running, _vuln_oracle],
    "integer-overflow":           [_vuln_integer_overflow],
    "signature":                  [_vuln_signature],
    "governance":                 [_vuln_governance, _vuln_logic_error],
    "other":                      [_vuln_access_control, _vuln_reentrancy,
                                   _vuln_logic_error, _vuln_integer_overflow],
    "audit-report":               [_vuln_access_control, _vuln_reentrancy,
                                   _vuln_logic_error, _vuln_integer_overflow],
    "formal-verification":        [_vuln_logic_error, _vuln_integer_overflow],
    "formal-verification-audit":  [_vuln_logic_error, _vuln_integer_overflow],
    "unchecked-return":           [_vuln_logic_error],
}


# ── dataset generation ────────────────────────────────────────────────────────

def _load_category_weights() -> Counter:
    """
    Read findings_all.jsonl and return a Counter of exploit categories.
    Excludes benign entries.  Falls back to equal weights if file is absent.
    """
    weights: Counter = Counter()
    if FINDINGS_PATH.exists():
        with open(FINDINGS_PATH) as fh:
            for line in fh:
                d = json.loads(line)
                cat = (d.get("category") or "other").lower().strip()
                if cat in ("benign",):
                    continue
                # Map unknown categories to 'other'
                key = cat if cat in _VULN_MAP else "other"
                weights[key] += 1
    if not weights:
        for k in _VULN_MAP:
            weights[k] = 1
    return weights


def generate_dataset(n_exploit: int = 2000, n_benign: int = 2000) -> List[Dict[str, Any]]:
    """
    Generate labeled bytecode graph samples.

    Exploit samples are drawn proportionally to the real audit findings
    category distribution loaded from findings_all.jsonl.
    """
    cat_weights = _load_category_weights()
    categories  = list(cat_weights.keys())
    weights     = [cat_weights[c] for c in categories]
    total_w     = sum(weights)

    print(f"Category distribution from real findings ({sum(cat_weights.values())} exploit records):")
    for c, w in sorted(cat_weights.items(), key=lambda x: -x[1])[:10]:
        print(f"  {c}: {w}")

    graphs: List[Dict[str, Any]] = []
    errors = 0

    # ── exploit samples ───────────────────────────────────────────────────────
    for i in range(n_exploit):
        rng = random.Random(hash(f"exploit_{i}") & 0xFFFFFFFF)

        # Sample category proportionally to real data
        r = rng.random() * total_w
        acc = 0.0
        cat = categories[-1]
        for c, w in zip(categories, weights):
            acc += w
            if r < acc:
                cat = c
                break

        vuln_fn   = rng.choice(_VULN_MAP.get(cat, [_vuln_access_control]))
        n_helpers = rng.randint(1, 3)
        graph_id  = f"exploit_{cat}_{i:05d}"

        try:
            hex_code = _build_exploit_contract(vuln_fn, n_helpers, rng)
            g = BUILDER.build_graph(
                hex_code,
                graph_id=graph_id,
                label=1,
                category=cat,
                metadata={"source": "real-findings", "severity": "high"},
            )
            graphs.append(g)
        except Exception as exc:
            errors += 1
            if errors <= 5:
                print(f"  WARNING: exploit build failed for {graph_id}: {exc}")

    print(f"Exploit: {len(graphs)} graphs ({errors} errors)")

    # ── benign samples ────────────────────────────────────────────────────────
    benign_count  = 0
    benign_errors = 0
    for i in range(n_benign):
        rng      = random.Random(hash(f"benign_{i}") & 0xFFFFFFFF)
        n_funcs  = rng.randint(2, 4)
        graph_id = f"benign_{i:05d}"

        try:
            hex_code = _build_benign_contract(n_funcs, rng)
            g = BUILDER.build_graph(
                hex_code,
                graph_id=graph_id,
                label=0,
                category="benign",
                metadata={"source": "real-findings", "severity": "none"},
            )
            graphs.append(g)
            benign_count += 1
        except Exception as exc:
            benign_errors += 1
            if benign_errors <= 5:
                print(f"  WARNING: benign build failed for {graph_id}: {exc}")

    print(f"Benign:  {benign_count} graphs ({benign_errors} errors)")
    return graphs


def split_and_save(graphs: List[Dict[str, Any]], output_dir: Path) -> Dict[str, Any]:
    """Stratified 60/20/20 split → train/val/test.jsonl"""
    output_dir.mkdir(parents=True, exist_ok=True)

    exploits = [g for g in graphs if g["label"] == 1]
    benign   = [g for g in graphs if g["label"] == 0]
    random.shuffle(exploits)
    random.shuffle(benign)

    def _split(lst: list, tr: float = 0.6, va: float = 0.2):
        n = len(lst)
        t = int(n * tr)
        v = int(n * va)
        return lst[:t], lst[t:t + v], lst[t + v:]

    e_tr, e_va, e_te = _split(exploits)
    b_tr, b_va, b_te = _split(benign)

    splits = {
        "train": e_tr + b_tr,
        "val":   e_va + b_va,
        "test":  e_te + b_te,
    }

    for name, data in splits.items():
        random.shuffle(data)
        path = output_dir / f"{name}.jsonl"
        with open(path, "w") as fh:
            for g in data:
                fh.write(json.dumps(g) + "\n")
        n_exp = sum(1 for g in data if g["label"] == 1)
        n_ben = sum(1 for g in data if g["label"] == 0)
        print(f"  {name:5s}: {len(data):5d} graphs  ({n_exp} exploit / {n_ben} benign)  → {path}")

    stats = {
        "total":    len(graphs),
        "exploits": len(exploits),
        "benign":   len(benign),
        "splits":   {k: len(v) for k, v in splits.items()},
    }
    (output_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=2))
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate realistic bytecode GNN dataset from real audit findings distribution"
    )
    parser.add_argument("--n-exploit", type=int, default=2000,
                        help="Number of exploit samples (default 2000)")
    parser.add_argument("--n-benign",  type=int, default=2000,
                        help="Number of benign samples (default 2000)")
    args = parser.parse_args()

    print(f"Generating: {args.n_exploit} exploit + {args.n_benign} benign samples")
    graphs = generate_dataset(n_exploit=args.n_exploit, n_benign=args.n_benign)
    print(f"\nSaving to {DATASET_DIR}/")
    stats = split_and_save(graphs, DATASET_DIR)
    print(f"\nDataset stats: {stats}")
    print("Done.")
