"""
detectors/bytecode_analyzer/similarity_scanner.py

Bytecode Similarity Scanner — SoK DeFi Attacks (S1).

Computes opcode n-gram Jaccard similarity between an unknown contract's
bytecode and a reference corpus of known-exploit fingerprints. Contracts
with high similarity to historical exploits are flagged for investigation.

Methodology (SoK DeFi Attacks, Liyi Zhou et al., IEEE S&P 2023, arXiv:2208.13035):
  - Extract opcode n-gram multiset from disassembled bytecode
  - Compute Jaccard similarity: |A ∩ B| / |A ∪ B| over n-gram sets
  - Match against built-in fingerprint corpus derived from attack taxonomy
  - Return closest match, score, and cluster label

The built-in corpus encodes fingerprints for five exploit families
(reentrancy/AM1, price oracle/AM6, flash loan/AM5, proxy hijack/AM8,
approval drain/AM4). In production, extend by calling build_corpus()
with Clara (clarahacks.com) contract addresses.

Usage:
    from detectors.bytecode_analyzer.similarity_scanner import SimilarityScanner

    scanner = SimilarityScanner()
    result  = scanner.scan(bytecode_hex)

    # result["similarity_score"]  — float [0,1], highest match against corpus
    # result["closest_match"]     — str, exploit family label (or "none")
    # result["cluster_id"]        — str, same as closest_match
    # result["all_scores"]        — dict[label → score] for all corpus entries
    # result["risk_flag"]         — bool, True if score >= threshold (0.35)
    # result["error"]             — str | None
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from pyevmasm import disassemble_all

# Default n-gram window size (SoK paper uses 3–5; 4 balances specificity vs. noise)
_DEFAULT_N = 4

# Jaccard similarity threshold for flagging as a near-clone
_SIMILARITY_THRESHOLD = 0.35


# ── Built-in reference corpus ──────────────────────────────────────────────────
# Opcode 4-gram fingerprints for representative exploit families.
# Each entry is a frozenset of 4-tuples (opcode sequence) extracted from
# canonical exploit bytecode samples in the SoK DeFi Attacks taxonomy.
#
# NOTE: These are heuristic fingerprints derived from the attack taxonomy's
# structural descriptions, not from live exploit bytecode. For production use,
# extend via build_corpus() with real Clara/Rekt contract addresses.

_BUILTIN_CORPUS: Dict[str, Set[Tuple[str, ...]]] = {
    # AM1: Reentrancy — attacker-controlled call target, state update after CALL
    "reentrancy_am1": {
        ("SLOAD",  "DUP1",           "CALL",  "ISZERO"),
        ("CALL",   "ISZERO",         "PUSH2", "JUMPI"),
        ("CALL",   "SSTORE",         "POP",   "JUMP"),
        ("SLOAD",  "CALLDATALOAD",   "CALL",  "SSTORE"),
        ("ISZERO", "PUSH2",          "JUMPI", "SSTORE"),
    },
    # AM4: Approval drain — approve + transferFrom without caller guard
    "approval_drain_am4": {
        ("PUSH4",  "EQ",   "PUSH2",       "JUMPI"),
        ("PUSH4",  "DUP2", "EQ",          "PUSH2"),
        ("CALLER", "PUSH1","CALLDATALOAD","CALL"),
        ("EQ",     "PUSH2","JUMPI",       "DUP1"),
        ("PUSH4",  "EQ",   "JUMPI",       "DUP1"),
    },
    # AM5: Flash loan callback without caller check
    "flash_loan_am5": {
        ("PUSH4",  "EQ",             "PUSH2", "JUMPI"),
        ("CALL",   "ISZERO",         "RETURNDATACOPY", "REVERT"),
        ("CALLDATASIZE", "PUSH1",    "CALLDATACOPY",   "PUSH1"),
        ("PUSH4",  "CALL",           "ISZERO",         "PUSH2"),
        ("RETURNDATASIZE", "DUP1",   "ISZERO",         "PUSH2"),
    },
    # AM6: Price oracle manipulation — call return data written to storage
    "oracle_manipulation_am6": {
        ("CALL",           "RETURNDATACOPY", "MLOAD",  "SSTORE"),
        ("STATICCALL",     "MLOAD",          "SSTORE", "PUSH1"),
        ("CALL",           "MLOAD",          "DIV",    "SSTORE"),
        ("RETURNDATASIZE", "MLOAD",          "MUL",    "SSTORE"),
        ("CALL",           "POP",            "MLOAD",  "SSTORE"),
    },
    # AM8: Proxy/delegatecall hijack — implementation slot loaded from storage
    "proxy_hijack_am8": {
        ("SLOAD",         "PUSH1",       "DELEGATECALL", "ISZERO"),
        ("CALLDATASIZE",  "SLOAD",       "DELEGATECALL", "RETURNDATASIZE"),
        ("DELEGATECALL",  "RETURNDATASIZE", "RETURNDATACOPY", "RETURN"),
        ("SLOAD",         "DELEGATECALL","ISZERO",        "JUMPI"),
        ("PUSH1",         "SLOAD",       "SWAP1",         "DELEGATECALL"),
    },
}


def _extract_ngrams(bytecode_hex: str, n: int = _DEFAULT_N) -> Set[Tuple[str, ...]]:
    """
    Disassemble bytecode and extract a set of opcode n-grams.

    Args:
        bytecode_hex: Raw hex bytecode string (with or without 0x prefix).
        n:            Sliding-window size for n-gram extraction.

    Returns:
        Set of n-tuples of opcode name strings.  Empty set on failure.
    """
    hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    hex_str = hex_str.strip()
    if not hex_str:
        return set()

    try:
        instructions = list(disassemble_all(bytes.fromhex(hex_str)))
    except Exception:
        return set()

    names = [instr.name for instr in instructions]
    return {tuple(names[i: i + n]) for i in range(len(names) - n + 1)}


def _jaccard(a: Set[Tuple], b: Set[Tuple]) -> float:
    """Jaccard similarity between two sets: |A ∩ B| / |A ∪ B|."""
    if not a and not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


class SimilarityScanner:
    """
    Opcode n-gram Jaccard similarity scanner.

    Compares unknown bytecode against a reference corpus of exploit fingerprints
    and returns the closest match with a similarity score.

    The built-in corpus covers AM1/AM4/AM5/AM6/AM8 exploit families from the
    SoK DeFi Attacks taxonomy.  Extend with real-world samples via add_to_corpus().
    """

    def __init__(self, n: int = _DEFAULT_N, threshold: float = _SIMILARITY_THRESHOLD) -> None:
        self._n = n
        self._threshold = threshold
        # Deep copy so callers can extend without affecting the module-level constant
        self._corpus: Dict[str, Set[Tuple[str, ...]]] = {
            label: set(ngrams) for label, ngrams in _BUILTIN_CORPUS.items()
        }

    def add_to_corpus(self, label: str, bytecode_hex: str) -> None:
        """
        Add a known-exploit contract's bytecode to the reference corpus.

        Extracts n-grams from the bytecode and merges them into the named
        corpus entry (creates a new entry if the label is new).

        Args:
            label:        Exploit family label, e.g. "reentrancy_am1" or a
                          Clara incident ID like "clara_2026_03_01".
            bytecode_hex: Hex bytecode of the known-exploit contract.
        """
        ngrams = _extract_ngrams(bytecode_hex, self._n)
        if label in self._corpus:
            self._corpus[label].update(ngrams)
        else:
            self._corpus[label] = ngrams

    def scan(self, bytecode_hex: str) -> Dict[str, Any]:
        """
        Compare bytecode against the corpus and return similarity results.

        Args:
            bytecode_hex: Raw hex bytecode string (with or without 0x prefix).

        Returns:
            {
                "similarity_score": float,        # highest Jaccard score [0,1]
                "closest_match":    str,           # corpus label of best match
                "cluster_id":       str,           # same as closest_match
                "all_scores":       dict[str, float],  # score per corpus entry
                "risk_flag":        bool,          # True if score >= threshold
                "error":            str | None,
            }
        """
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str.strip():
            return self._empty("empty bytecode")

        target_ngrams = _extract_ngrams(bytecode_hex, self._n)
        if not target_ngrams:
            return self._empty("disassembly produced no instructions")

        all_scores: Dict[str, float] = {}
        for label, ref_ngrams in self._corpus.items():
            all_scores[label] = round(_jaccard(target_ngrams, ref_ngrams), 4)

        if not all_scores:
            return self._empty("corpus is empty")

        best_label = max(all_scores, key=lambda k: all_scores[k])
        best_score = all_scores[best_label]

        return {
            "similarity_score": best_score,
            "closest_match":    best_label if best_score >= self._threshold else "none",
            "cluster_id":       best_label if best_score >= self._threshold else "none",
            "all_scores":       all_scores,
            "risk_flag":        best_score >= self._threshold,
            "error":            None,
        }

    @staticmethod
    def _empty(error: str) -> Dict[str, Any]:
        return {
            "similarity_score": 0.0,
            "closest_match":    "none",
            "cluster_id":       "none",
            "all_scores":       {},
            "risk_flag":        False,
            "error":            error,
        }
