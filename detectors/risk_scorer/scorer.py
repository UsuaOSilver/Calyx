"""
detectors/risk_scorer/scorer.py

Unified risk scorer for Calyx.

Combines signals from three analysis layers into a single [0.0, 1.0] risk score:
  1. GNN score        — structural graph-based exploit likelihood (weight 0.30)
  2. AM/LLM findings  — TaintAnalyzer + AMPatternDetector findings (weight 0.55)
  3. Txn anomaly      — historical transaction anomaly score (weight 0.15)

Severity weights:  CRITICAL/high=0.35  HIGH/high=0.25  MEDIUM=0.10  LOW=0.03
Confirmed bonus:   +0.10 per ExploitValidator-confirmed finding
Thresholds:        CRITICAL>=0.75  HIGH>=0.50  MEDIUM>=0.25  LOW>=0.0

Usage:
    from detectors.risk_scorer.scorer import RiskScorer
    scorer = RiskScorer()
    result = scorer.score(gnn_score=0.82, llm_findings=[...], txn_anomaly_score=0.4)
    # result["risk_score"]  -> float [0, 1]
    # result["risk_level"]  -> "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

GNN_WEIGHT = 0.30
LLM_WEIGHT = 0.55
TXN_WEIGHT = 0.15

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 0.35, "high": 0.25, "medium": 0.10,
    "med": 0.10, "low": 0.03,
}

RISK_THRESHOLDS = [
    (0.75, "CRITICAL"), (0.50, "HIGH"), (0.25, "MEDIUM"), (0.0, "LOW"),
]

CONFIRMED_BONUS = 0.10


def _severity_weight(finding: Dict[str, Any]) -> float:
    sev  = (finding.get("severity") or finding.get("risk") or "").lower().strip()
    base = SEVERITY_WEIGHTS.get(sev, 0.05)
    bonus = CONFIRMED_BONUS if finding.get("confirmed") is True else 0.0
    return base + bonus


def _risk_level(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


class RiskScorer:
    """Combines GNN, LLM, and transaction signals into a unified risk score."""

    def score(self, gnn_score: float = 0.0,
              llm_findings: Optional[List[Dict[str, Any]]] = None,
              txn_anomaly_score: float = 0.0) -> Dict[str, Any]:
        findings = llm_findings or []
        gnn_score  = max(0.0, min(1.0, float(gnn_score)))
        gnn_contrib = GNN_WEIGHT * gnn_score

        severity_sum = sum(_severity_weight(f) for f in findings)
        llm_sub  = min(1.0, severity_sum)
        llm_contrib = LLM_WEIGHT * llm_sub

        txn_score  = max(0.0, min(1.0, float(txn_anomaly_score)))
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

    def score_from_scan_result(self, scan_result: Dict[str, Any],
                                gnn_score: float = 0.0,
                                txn_anomaly_score: float = 0.0) -> Dict[str, Any]:
        findings = (
            scan_result.get("findings") or scan_result.get("vulnerabilities") or []
        )
        return self.score(gnn_score=gnn_score, llm_findings=findings,
                          txn_anomaly_score=txn_anomaly_score)
