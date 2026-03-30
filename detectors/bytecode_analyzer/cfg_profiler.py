# detectors/bytecode_analyzer/cfg_profiler.py
"""
Control-flow obfuscation profiler + AM vulnerability pattern detector for EVM bytecode.

CFGProfiler:
    Detects indirect JUMP/JUMPI instructions (runtime-computed destinations) —
    the core obfuscation technique analyzed in SKANF (IC3/Yale, arXiv:2504.13398).

    Also provides:
    - split_by_selector(): partition bytecode by 4-byte function selectors (T2,
      arXiv:2506.19624 — enables per-function vulnerability attribution)
    - detect_complex_defi_patterns(): multi-hop flash loan + swap sequence detection
      (T4 — flags contracts needing human review)

AMPatternDetector:
    Heuristic opcode-sequence scanner for SKANF AM3–AM8 vulnerability patterns.
    Uses sliding-window analysis — no symbolic execution or taint tracking.

    AM3: tx.origin used as authorization check (ORIGIN → EQ → JUMPI)
    AM4: approve() + transferFrom() selectors present without CALLER guard
    AM5: Known flash-loan/swap callback selector reachable without CALLER check
    AM7: Public function selector dispatches to SSTORE without any CALLER guard
         (SoK DeFi Attacks arXiv:2208.13035 — permissionless/camouflage pattern)
    AM8: DELEGATECALL preceded by SLOAD without constant PUSH20 target
         (proxy implementation slot controllable via storage — SoK AM8)

    NOTE: AM1, AM2 detected by TaintAnalyzer (data-flow tracking).
          AM6 detected by TaintAnalyzer (oracle taint: RETURNDATACOPY → SSTORE).
          AMPatternDetector.detect() covers AM3/AM4/AM5/AM7/AM8.

Usage:
    from detectors.bytecode_analyzer.cfg_profiler import CFGProfiler, AMPatternDetector

    profiler = CFGProfiler()
    profile  = profiler.profile(bytecode_hex)
    funcs    = profiler.split_by_selector(bytecode_hex)   # T2
    hard     = profiler.detect_complex_defi_patterns(bytecode_hex)  # T4

    detector = AMPatternDetector()
    findings = detector.detect(bytecode_hex)
    # findings["findings"]        — list of {type, severity, pc, description}
    # findings["am_types_found"]  — e.g. ["AM3", "AM5", "AM7"]
"""

from __future__ import annotations

from pyevmasm import disassemble_all, Instruction
from typing import Any, Dict, List, Optional, Tuple


# Opcodes that can push a constant (potential jump destination) onto the stack.
# PUSH1–PUSH32 = 0x60–0x7f
PUSH_OPCODES = set(range(0x60, 0x80))

# ── AM pattern constants ───────────────────────────────────────────────────────

# Opcodes that perform an external call (CALL, CALLCODE, DELEGATECALL, STATICCALL)
CALL_OPCODES = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"}

# ERC20 function selectors (as 4-byte big-endian integers)
_SEL_APPROVE        = 0x095ea7b3   # approve(address,uint256)
_SEL_TRANSFER_FROM  = 0x23b872dd   # transferFrom(address,address,uint256)

# Known flash-loan / swap callback selectors
CALLBACK_SELECTORS = {
    0xfa461e33: "uniswapV3SwapCallback",
    0x10d1e85c: "uniswapV2Call",
    0x920f5c84: "executeOperation",     # AAVE v2
    0xd9d98ce4: "executeOperation",     # AAVE v3
    0x23e30c8b: "onFlashLoan",          # EIP-3156
    0x4ec7d75d: "pancakeCall",          # PancakeSwap
}

# Backward window size (in instruction count) for AM1/AM2 scanning
_CALL_WINDOW = 20

# Forward window for AM5 callback body scan
_CALLBACK_WINDOW = 50


def _preceding_instruction(instructions: List[Instruction], idx: int) -> Optional[Instruction]:
    """Return the instruction immediately before idx in the list, or None."""
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
        """
        Analyze bytecode and return an obfuscation profile.

        Args:
            bytecode_hex: Raw hex bytecode string (with or without 0x prefix).

        Returns:
            {
                "total_jumps":        int,
                "direct_jumps":       int,
                "indirect_jumps":     int,
                "obfuscation_score":  float,   # indirect / total, 0 if no jumps
                "indirect_jump_pcs":  list[dict],  # [{"pc": int, "opcode": str}, ...]
                "all_jumpdest_pcs":   list[int],
                "instruction_count":  int,
                "assessment":         str,      # "clean" | "likely_obfuscated" | "obfuscated"
            }
        """
        hex_str = bytecode_hex.lstrip("0x").strip() if bytecode_hex.startswith("0x") else bytecode_hex.strip()
        if not hex_str:
            return self._empty_result("empty bytecode")

        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._empty_result(f"disassemble failed: {e}")

        # Index instructions by position in list for O(1) preceding-instruction lookup
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
                # Direct: the immediately preceding instruction is a PUSH constant
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
            "total_jumps": 0,
            "direct_jumps": 0,
            "indirect_jumps": 0,
            "obfuscation_score": 0.0,
            "indirect_jump_pcs": [],
            "all_jumpdest_pcs": [],
            "instruction_count": 0,
            "assessment": "unknown",
            "error": error,
        }

    # ── T2: Function-level split by selector ──────────────────────────────────

    def split_by_selector(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Partition bytecode by 4-byte function selectors (T2 — arXiv:2506.19624).

        Scans the function dispatcher for PUSH4 → EQ → PUSH2/PUSH3 → JUMPI patterns
        and records the dispatch target PC for each selector. Enables per-function
        vulnerability attribution instead of whole-contract scoring.

        Returns:
            {
                "functions": {
                    "0x<selector>": {
                        "selector": str,
                        "dispatch_pc": int,   # PC of the PUSH4 instruction
                        "entry_pc":    int,   # JUMPDEST target the selector routes to
                    }, ...
                },
                "function_count": int,
                "error": str | None,
            }
        """
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
            sel_int = instr.operand
            sel_hex = hex(sel_int)

            # Look ahead up to 6 instructions for: EQ ... PUSH<n> <dest> ... JUMPI
            lookahead = instructions[i: i + 8]
            la_names = [x.name for x in lookahead]

            if "EQ" not in la_names or "JUMPI" not in la_names:
                continue

            # Find the PUSH before JUMPI — that's the branch target
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

            functions[sel_hex] = {
                "selector":   sel_hex,
                "dispatch_pc": instr.pc,
                "entry_pc":    entry_pc,
            }

        return {
            "functions":      functions,
            "function_count": len(functions),
            "error":          None,
        }

    # ── T4: Complex DeFi pattern detection ────────────────────────────────────

    def detect_complex_defi_patterns(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Detect multi-hop flash loan + swap sequences (T4 — hard cases from arXiv:2506.19624).

        Flags contracts where a flash-loan callback selector is followed by multiple
        external CALLs to distinct DEX swap selectors — the structural fingerprint of
        flash loan + price manipulation attacks. These contracts require human review
        because automated analysis is most likely to miss the full attack path.

        Returns:
            {
                "complexity_score":     float,    # 0.0–1.0
                "review_recommended":   bool,
                "patterns_found":       list[str],
                "detail":               str,
                "error":                str | None,
            }
        """
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str:
            return self._empty_complex("empty bytecode")

        try:
            instructions = list(disassemble_all(bytes.fromhex(hex_str)))
        except Exception as e:
            return self._empty_complex(str(e))

        # Known DEX swap selectors (4-byte)
        _DEX_SWAP_SELECTORS = {
            0x38ed1739: "swapExactTokensForTokens (UniV2)",
            0x7ff36ab5: "swapExactETHForTokens (UniV2)",
            0x128acb08: "swap (UniV3)",
            0x022c0d9f: "swap (UniV2 pool)",
            0xd0e30db0: "deposit (WETH)",
            0x2e1a7d4d: "withdraw (WETH)",
        }

        patterns_found: List[str] = []
        has_flash_callback = False
        swap_selector_count = 0
        call_count = 0

        names = [i.name for i in instructions]

        for i, instr in enumerate(instructions):
            if instr.name == "PUSH4":
                sel = instr.operand
                if sel in CALLBACK_SELECTORS:
                    has_flash_callback = True
                if sel in _DEX_SWAP_SELECTORS:
                    swap_selector_count += 1
            if instr.name == "CALL":
                call_count += 1

        if has_flash_callback:
            patterns_found.append("flash_loan_callback")
        if swap_selector_count >= 2:
            patterns_found.append(f"multi_dex_swap ({swap_selector_count} selectors)")
        if call_count >= 4:
            patterns_found.append(f"high_call_count ({call_count} CALLs)")

        # Complexity: each pattern adds weight
        score = min(1.0, (
            (0.4 if has_flash_callback else 0.0) +
            (0.3 if swap_selector_count >= 2 else 0.0) +
            (0.2 if call_count >= 4 else 0.0) +
            (0.1 if swap_selector_count >= 3 else 0.0)
        ))

        review_recommended = has_flash_callback and (swap_selector_count >= 1 or call_count >= 3)

        detail = (
            f"flash_callback={'yes' if has_flash_callback else 'no'}, "
            f"dex_selectors={swap_selector_count}, "
            f"total_calls={call_count}"
        )

        return {
            "complexity_score":   round(score, 3),
            "review_recommended": review_recommended,
            "patterns_found":     patterns_found,
            "detail":             detail,
            "error":              None,
        }

    @staticmethod
    def _empty_complex(error: str) -> Dict[str, Any]:
        return {
            "complexity_score":   0.0,
            "review_recommended": False,
            "patterns_found":     [],
            "detail":             "",
            "error":              error,
        }


# ── AMPatternDetector ─────────────────────────────────────────────────────────

class AMPatternDetector:
    """
    Heuristic scanner for SKANF AM1–AM5 vulnerability patterns.

    Uses sliding-window analysis on the disassembled EVM instruction stream.
    No symbolic execution or taint tracking — results are probabilistic and
    should be treated as candidate findings requiring human confirmation.

    Each finding has:
        {
            "type":        "AM3" | "AM4" | "AM5" | "AM7" | "AM8",
            "severity":    "high" | "medium" | "low",
            "pc":          int,          # program counter of the flagged instruction
            "description": str,
        }
    """

    def detect(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Run AM3/AM4/AM5/AM7/AM8 pattern scans on bytecode_hex.

        AM1/AM2 are handled by TaintAnalyzer (data-flow based) and are
        NOT included here.

        Returns:
            {
                "findings":      list[dict],   # AM3/AM4/AM5/AM7/AM8 findings
                "am_types_found": list[str],   # deduplicated AM types
                "error":         str | None,
            }
        """
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

    # ── AM3: ORIGIN → EQ → JUMPI → access control via tx.origin ─────────────

    def _scan_am3(self, instructions: List[Instruction]) -> List[Dict]:
        """
        Detect: ORIGIN ... EQ ... JUMPI within a 5-instruction window.
        Compiled from: require(tx.origin == owner) / if (tx.origin != x) revert.
        tx.origin is spoofable in certain contexts and is a deprecated auth pattern.
        """
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
                    "type": "AM3",
                    "severity": "medium",
                    "pc": pc,
                    "description": (
                        f"ORIGIN at PC {pc} followed by EQ+JUMPI within {window} instructions — "
                        f"tx.origin used as authorization check (spoofable via contract relay)"
                    ),
                })
        return findings

    # ── AM4: approve + transferFrom selectors without CALLER guard ────────────

    def _scan_am4(self, instructions: List[Instruction]) -> List[Dict]:
        """
        Check for presence of both ERC20 approve() (0x095ea7b3) and
        transferFrom() (0x23b872dd) selectors in PUSH4 operands, combined with
        absence of a CALLER+EQ guard anywhere in the bytecode.

        Fires on most ERC20 tokens — treated as LOW severity to avoid alert fatigue.
        A HIGH finding requires a pattern where transferFrom is callable without
        any caller validation (rare; needs manual confirmation).
        """
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
            # CALLER followed by EQ within 3 instructions = caller validation
            if instr.name == "CALLER":
                lookahead = names[i: i + 3]
                if "EQ" in lookahead:
                    has_caller_eq = True

        if has_approve and has_transfer_from and not has_caller_eq:
            findings.append({
                "type": "AM4",
                "severity": "low",
                "pc": 0,
                "description": (
                    "approve() and transferFrom() selectors both present; "
                    "no CALLER+EQ guard detected in bytecode — "
                    "confirm whether transferFrom validates msg.sender"
                ),
            })
        return findings

    # ── AM5: known callback selector + CALL reachable without CALLER check ───

    def _scan_am5(self, instructions: List[Instruction]) -> List[Dict]:
        """
        Find known flash-loan/swap callback selectors in the dispatcher.
        Then scan the _CALLBACK_WINDOW instructions following the dispatch
        JUMPDEST for a CALL opcode without a preceding CALLER+EQ guard.

        A callback callable by any external address is exploitable: an attacker
        deploys a fake pool and triggers the callback on the victim contract,
        executing the internal CALL with their controlled inputs.
        """
        findings = []
        names   = [instr.name    for instr in instructions]
        opcodes = [instr.opcode  for instr in instructions]

        # Build map: jumpdest_pc → index in instruction list
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
            # Look for the JUMPI that dispatches this selector (within 6 instructions)
            lookahead_instrs = instructions[i: i + 6]
            lookahead_names  = [x.name for x in lookahead_instrs]

            jumpi_target_pc = None
            if "JUMPI" in lookahead_names:
                # The PUSH before JUMPI contains the branch target
                jumpi_idx_local = lookahead_names.index("JUMPI")
                push_before = lookahead_instrs[jumpi_idx_local - 1] if jumpi_idx_local > 0 else None
                if push_before and push_before.name in [f"PUSH{n}" for n in range(1, 33)]:
                    jumpi_target_pc = push_before.operand

            # Scan forward from the callback JUMPDEST
            start_idx = jumpdest_idx.get(jumpi_target_pc)
            if start_idx is None:
                # Fallback: scan from just after the current PUSH4
                start_idx = i + 1

            body = instructions[start_idx: start_idx + _CALLBACK_WINDOW]
            body_names = [x.name for x in body]

            has_call = any(n in CALL_OPCODES for n in body_names)
            if not has_call:
                continue

            # Check if CALLER+EQ appears before any CALL in the body
            caller_eq_before_call = False
            for j, bname in enumerate(body_names):
                if bname in CALL_OPCODES:
                    break
                if bname == "CALLER" and "EQ" in body_names[j: j + 3]:
                    caller_eq_before_call = True
                    break

            if not caller_eq_before_call:
                findings.append({
                    "type": "AM5",
                    "severity": "medium",
                    "pc": instr.pc,
                    "description": (
                        f"Callback selector {hex(sel)} ({callback_name}) at PC {instr.pc} — "
                        f"CALL reachable within {_CALLBACK_WINDOW} instructions of dispatch "
                        f"without CALLER+EQ guard; arbitrary callers may trigger the callback"
                    ),
                })
        return findings

    # ── AM7: permissionless SSTORE (SoK DeFi Attacks — camouflage pattern) ───

    def _scan_am7(self, instructions: List[Instruction]) -> List[Dict]:
        """
        Detect public functions that modify state without any access control.

        Pattern: bytecode contains PUSH4 dispatcher entries (public functions) AND
        SSTORE somewhere reachable, with no CALLER+EQ guard anywhere in the bytecode.

        This is the "permissionless interaction" / "camouflage" pattern from the
        SoK DeFi Attacks taxonomy (arXiv:2208.13035) — an attacker deploys a contract
        that impersonates a legitimate protocol but exposes state-changing functions
        without authorization.

        Fires at most once per contract to avoid alert fatigue.
        """
        names = [i.name for i in instructions]

        has_sstore = "SSTORE" in names
        if not has_sstore:
            return []

        # Count non-trivial PUSH4 selectors (public function entries)
        push4_count = sum(
            1 for instr in instructions
            if instr.name == "PUSH4"
            and instr.operand not in (_SEL_APPROVE, _SEL_TRANSFER_FROM)
            and instr.operand not in CALLBACK_SELECTORS
        )
        if push4_count == 0:
            return []

        # Suppress if any CALLER+EQ guard exists
        for i, name in enumerate(names):
            if name == "CALLER" and "EQ" in names[i: i + 5]:
                return []

        return [{
            "type": "AM7",
            "severity": "medium",
            "pc": 0,
            "description": (
                f"{push4_count} public function selector(s) dispatch to code with SSTORE "
                f"but no CALLER+EQ access control detected anywhere in the bytecode — "
                f"state modification may be permissionless (SoK camouflage/proxy pattern)"
            ),
        }]

    # ── AM8: DELEGATECALL to storage-derived target ────────────────────────────

    def _scan_am8(self, instructions: List[Instruction]) -> List[Dict]:
        """
        Detect DELEGATECALL where the target address is loaded from storage.

        Pattern: SLOAD within 15 instructions before DELEGATECALL, without an
        intervening PUSH20 constant (which would indicate a hardcoded target).

        Storage-derived delegatecall targets are controllable if the implementation
        slot can be overwritten — the core proxy upgrade attack (SoK AM8,
        arXiv:2208.13035). Distinct from AM1 because the attacker exploits the
        upgrade mechanism rather than tainted calldata.
        """
        findings = []
        names = [i.name for i in instructions]

        for i, instr in enumerate(instructions):
            if instr.name != "DELEGATECALL":
                continue

            # Look back 15 instructions for SLOAD
            lookback = names[max(0, i - 15): i]
            if "SLOAD" not in lookback:
                continue

            # Suppress if there's a constant PUSH20 target between SLOAD and DELEGATECALL
            # (hardcoded target address means it's not storage-derived)
            if "PUSH20" in lookback:
                continue

            findings.append({
                "type": "AM8",
                "severity": "high",
                "pc": instr.pc,
                "description": (
                    f"DELEGATECALL at PC {instr.pc} preceded by SLOAD (within 15 instructions) "
                    f"without constant PUSH20 target — implementation slot may be "
                    f"controllable via storage write (proxy upgrade attack, SoK AM8)"
                ),
            })

        return findings

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {"findings": [], "am_types_found": [], "error": error}
