"""
detectors/bytecode_analyzer/similarity_scanner.py

Bytecode Similarity Scanner -- SoK DeFi Attacks S1 (arXiv:2208.13035).

Computes opcode n-gram Jaccard similarity between an unknown contract and
a reference corpus of known-exploit fingerprints. High similarity flags
contracts as near-clones of historical exploits for investigation.

Usage:
    from detectors.bytecode_analyzer.similarity_scanner import SimilarityScanner
    scanner = SimilarityScanner()
    result  = scanner.scan(bytecode_hex)
    # result["similarity_score"], ["closest_match"], ["risk_flag"]
"""

from __future__ import annotations
from typing import Any, Dict, Set, Tuple
from pyevmasm import disassemble_all

_DEFAULT_N = 4
_SIMILARITY_THRESHOLD = 0.35

_BUILTIN_CORPUS: Dict[str, Set[Tuple[str, ...]]] = {
    "reentrancy_am1": {
        ("SLOAD",  "DUP1",         "CALL",  "ISZERO"),
        ("CALL",   "ISZERO",       "PUSH2", "JUMPI"),
        ("CALL",   "SSTORE",       "POP",   "JUMP"),
        ("SLOAD",  "CALLDATALOAD", "CALL",  "SSTORE"),
    },
    "approval_drain_am4": {
        ("PUSH4",  "EQ",   "PUSH2",       "JUMPI"),
        ("PUSH4",  "DUP2", "EQ",          "PUSH2"),
        ("CALLER", "PUSH1","CALLDATALOAD","CALL"),
    },
    "flash_loan_am5": {
        ("PUSH4",  "EQ",            "PUSH2",          "JUMPI"),
        ("CALL",   "ISZERO",        "RETURNDATACOPY", "REVERT"),
        ("RETURNDATASIZE", "DUP1",  "ISZERO",         "PUSH2"),
    },
    "oracle_manipulation_am6": {
        ("CALL",       "RETURNDATACOPY", "MLOAD",  "SSTORE"),
        ("STATICCALL", "MLOAD",          "SSTORE", "PUSH1"),
        ("CALL",       "MLOAD",          "DIV",    "SSTORE"),
    },
    "proxy_hijack_am8": {
        ("SLOAD",        "PUSH1",          "DELEGATECALL",   "ISZERO"),
        ("CALLDATASIZE", "SLOAD",          "DELEGATECALL",   "RETURNDATASIZE"),
        ("DELEGATECALL", "RETURNDATASIZE", "RETURNDATACOPY", "RETURN"),
    },
}


def _extract_ngrams(bytecode_hex: str, n: int = _DEFAULT_N) -> Set[Tuple[str, ...]]:
    hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    if not hex_str.strip():
        return set()
    try:
        instructions = list(disassemble_all(bytes.fromhex(hex_str.strip())))
    except Exception:
        return set()
    names = [i.name for i in instructions]
    return {tuple(names[i: i + n]) for i in range(len(names) - n + 1)}


def _jaccard(a: Set[Tuple], b: Set[Tuple]) -> float:
    if not a and not b:
        return 0.0
    u = len(a | b)
    return len(a & b) / u if u > 0 else 0.0


class SimilarityScanner:
    def __init__(self, n: int = _DEFAULT_N, threshold: float = _SIMILARITY_THRESHOLD) -> None:
        self._n = n
        self._threshold = threshold
        self._corpus: Dict[str, Set[Tuple[str, ...]]] = {
            label: set(ngrams) for label, ngrams in _BUILTIN_CORPUS.items()
        }

    def add_to_corpus(self, label: str, bytecode_hex: str) -> None:
        ngrams = _extract_ngrams(bytecode_hex, self._n)
        if label in self._corpus:
            self._corpus[label].update(ngrams)
        else:
            self._corpus[label] = ngrams

    def scan(self, bytecode_hex: str) -> Dict[str, Any]:
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str.strip():
            return self._empty("empty bytecode")
        target = _extract_ngrams(bytecode_hex, self._n)
        if not target:
            return self._empty("disassembly produced no instructions")
        all_scores = {label: round(_jaccard(target, ref), 4) for label, ref in self._corpus.items()}
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
        return {"similarity_score": 0.0, "closest_match": "none", "cluster_id": "none",
                "all_scores": {}, "risk_flag": False, "error": error}
