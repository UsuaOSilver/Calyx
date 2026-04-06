"""
detectors/risk_scorer/scorer.py

Unified risk scorer for Calyx.

Combines signals from three analysis layers into a single [0.0, 1.0] risk score:
  1. GNN score        — structural graph-based exploit likelihood (fast path)
  2. AM/LLM findings  — TaintAnalyzer + AMPatternDetector findings
  3. Txn anomaly      — historical transaction anomaly score (bytecode mode)

Severity weights for findings:
  CRITICAL / high  → 0.35
  HIGH     / high  → 0.25
  MEDIUM   / med   → 0.10
  LOW      / low   → 0.03

Confirmed exploit bonus:
  A finding with "confirmed": True (from ExploitValidator) receives an
  additional +0.10 weight on top of its base severity weight.  This ensures
  fork-EVM-validated exploits always push the score into HIGH or CRITICAL.

Score formula:
  raw = clamp(gnn_weight * gnn_score + findings_weight * findings_sub + txn_weight * txn_score)
  where findings_sub = min(1.0, sum of (severity_weight + confirmed_bonus) for all findings)

Weights:
  gnn_weight      = 0.30
  findings_weight = 0.55
  txn_weight      = 0.15

Usage:
    from detectors.risk_scorer.scorer import RiskScorer

    scorer = RiskScorer()
    result = scorer.score(
        gnn_score=0.82,
        llm_findings=[{"severity": "high", "confirmed": True}, {"severity": "medium"}],
        txn_anomaly_score=0.4,
    )
    # result["risk_score"]   → float [0, 1]
    # result["risk_level"]   → "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    # result["breakdown"]    → dict with per-component contributions
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ── Weights ────────────────────────────────────────────────────────────────────

GNN_WEIGHT = 0.30
LLM_WEIGHT = 0.55
TXN_WEIGHT = 0.15

# LLM finding severity → contribution to llm_sub score
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 0.35,
    "high":     0.25,
    "medium":   0.10,
    "med":      0.10,
    "low":      0.03,
}

# Risk level thresholds
RISK_THRESHOLDS = [
    (0.75, "CRITICAL"),
    (0.50, "HIGH"),
    (0.25, "MEDIUM"),
    (0.0,  "LOW"),
]


# Bonus weight added when ExploitValidator confirms a finding is exploitable
CONFIRMED_BONUS = 0.10


def _severity_weight(finding: Dict[str, Any]) -> float:
    """Extract severity from a finding dict and return its weight.

    If the finding has "confirmed": True (set by ExploitValidator), an
    additional CONFIRMED_BONUS is added on top of the base severity weight.
    """
    sev = (
        finding.get("severity") or
        finding.get("risk") or
        ""
    ).lower().strip()
    base = SEVERITY_WEIGHTS.get(sev, 0.05)  # unknown severity → small contribution
    bonus = CONFIRMED_BONUS if finding.get("confirmed") is True else 0.0
    return base + bonus


def _risk_level(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


class RiskScorer:
    """
    Combines GNN, LLM, and transaction signals into a unified risk score.

    All inputs are optional — missing components default to 0 (no signal).
    This allows the scorer to work in partial-information modes:
      - Source-code only (no txn data)
      - Bytecode only (no GNN score)
      - GNN fast-path only (no LLM)
    """

    def score(
        self,
        gnn_score: float = 0.0,
        llm_findings: Optional[List[Dict[str, Any]]] = None,
        txn_anomaly_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Compute unified risk score.

        Args:
            gnn_score:          Float [0, 1] from GNN analyzer (exploit probability).
            llm_findings:       List of finding dicts from scan_evmbench_style(),
                                scan_bytecode_routed(), or scan_contract().
                                Each dict should have a "severity" key.
            txn_anomaly_score:  Float [0, 1] from TxnAnalyzer.analyze()["anomaly_score"].

        Returns:
            {
                "risk_score":   float,   # [0.0, 1.0]
                "risk_level":   str,     # CRITICAL | HIGH | MEDIUM | LOW
                "breakdown": {
                    "gnn_contribution":  float,
                    "llm_contribution":  float,
                    "txn_contribution":  float,
                    "llm_sub_score":     float,
                    "finding_count":     int,
                    "finding_severities": list[str],
                },
            }
        """
        findings = llm_findings or []

        # GNN component
        gnn_score = max(0.0, min(1.0, float(gnn_score)))
        gnn_contrib = GNN_WEIGHT * gnn_score

        # LLM component — sum severity weights, cap at 1.0
        severity_sum = sum(_severity_weight(f) for f in findings)
        llm_sub = min(1.0, severity_sum)
        llm_contrib = LLM_WEIGHT * llm_sub

        # Txn anomaly component
        txn_score = max(0.0, min(1.0, float(txn_anomaly_score)))
        txn_contrib = TXN_WEIGHT * txn_score

        raw = gnn_contrib + llm_contrib + txn_contrib
        risk_score = round(max(0.0, min(1.0, raw)), 4)

        severities = [
            (f.get("severity") or f.get("risk") or "unknown").upper()
            for f in findings
        ]

        return {
            "risk_score": risk_score,
            "risk_level": _risk_level(risk_score),
            "breakdown": {
                "gnn_contribution":   round(gnn_contrib, 4),
                "llm_contribution":   round(llm_contrib, 4),
                "txn_contribution":   round(txn_contrib, 4),
                "llm_sub_score":      round(llm_sub, 4),
                "finding_count":      len(findings),
                "finding_severities": severities,
            },
        }

    def score_from_scan_result(
        self,
        scan_result: Dict[str, Any],
        gnn_score: float = 0.0,
        txn_anomaly_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Convenience wrapper that accepts the raw output of any ClaudeScanner method.

        Handles both EVMbench format (key: "vulnerabilities") and
        bytecode format (key: "findings").
        """
        findings = (
            scan_result.get("findings") or
            scan_result.get("vulnerabilities") or
            []
        )
        return self.score(
            gnn_score=gnn_score,
            llm_findings=findings,
            txn_anomaly_score=txn_anomaly_score,
        )
