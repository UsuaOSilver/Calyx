"""
detectors/deployment_watcher/classifier.py

Adversarial Contract Classifier — Stage 9 (Pre-Attack Detection).

Classifies newly deployed contracts as adversarial, suspicious, or benign
based on BytecodePipeline analysis signals. Designed to fire BEFORE the
attack transaction, exploiting the rescue window identified by the SoK
DeFi Attacks paper (56% of attacks are non-atomic).

Research basis:
  - LookAhead (FSE 2025): F1=0.8966 for adversarial contract detection
    — but cannot handle obfuscated bytecode (Calyx's CFGDeobfuscator solves this)
  - FinDet (arXiv 2509.18934): BAC=0.9374 via LLM semantic interpretation
    — but no deobfuscation, no taint analysis
  - SoK DeFi Attacks (IEEE S&P 2023): 56% non-atomic attacks, avg rescue window 1h±4.1h
  - SKANF author direction: "can AI agent still achieve good results with SKANF?"

Calyx advantage: only tool combining deobfuscation + taint + GNN + similarity
in a single pipeline — making this classifier possible on obfuscated contracts
that defeat LookAhead and FinDet.

Signal weights (6 dimensions, tuned to LookAhead/FinDet literature):
  taint_signal:      0.30  — AM1/AM2 present (calldata → CALL sink)
  callback_signal:   0.15  — AM5 flash loan/swap callback without guard
  similarity_signal: 0.15  — n-gram Jaccard > threshold against exploit corpus
  complexity_signal: 0.15  — flash callback + multi-DEX swap + high CALL count
  gnn_signal:        0.15  — GNN exploit_probability
  obfuscation_signal:0.10  — intentional CFG hiding

Classification thresholds:
  adversarial:  score >= 0.55
  suspicious:   score >= 0.35
  benign:       score <  0.35

Usage:
    from detectors.deployment_watcher.classifier import AdversarialClassifier

    classifier = AdversarialClassifier()
    result = classifier.classify(pipeline_result)
    # result["classification"]       -> "adversarial" | "suspicious" | "benign"
    # result["adversarial_score"]    -> float [0, 1]
    # result["signals"]              -> per-signal breakdown
    # result["rescue_window_advisory"] -> "IMMEDIATE_RISK" | "MONITOR" | "BENIGN"
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# ── Signal weights ────────────────────────────────────────────────────────────
# Taint gets highest weight because AM1/AM2 are the most actionable finding:
# they mean the contract can redirect or drain funds via calldata control.
# LookAhead's key insight was that adversarial contracts overwhelmingly contain
# calldata-to-CALL taint paths. The remaining signals are corroborating evidence.

SIGNAL_WEIGHTS = {
    "taint":       0.30,
    "callback":    0.15,
    "similarity":  0.15,
    "complexity":  0.15,
    "gnn":         0.15,
    "obfuscation": 0.10,
}

# ── Classification thresholds ─────────────────────────────────────────────────

THRESHOLD_ADVERSARIAL = 0.55
THRESHOLD_SUSPICIOUS  = 0.35

# ── Confidence calibration ────────────────────────────────────────────────────
# Confidence depends on how many independent signals agree, not just the score.

_CONFIDENCE_HIGH   = 4   # 4+ signals firing → high confidence
_CONFIDENCE_MEDIUM = 2   # 2-3 signals firing → medium confidence


class AdversarialClassifier:
    """
    Classifies a newly deployed contract as adversarial, suspicious, or benign
    based on a weighted combination of BytecodePipeline analysis signals.

    Stateless — safe to reuse across multiple classifications.
    """

    def __init__(
        self,
        threshold_adversarial: float = THRESHOLD_ADVERSARIAL,
        threshold_suspicious: float = THRESHOLD_SUSPICIOUS,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self._thresh_adv  = threshold_adversarial
        self._thresh_sus  = threshold_suspicious
        self._weights     = weights or dict(SIGNAL_WEIGHTS)

    def classify(self, pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a contract based on its BytecodePipeline analysis result.

        Args:
            pipeline_result: The dict returned by BytecodePipeline.analyze_bytecode()
                             or analyze_address(). Must contain at minimum:
                             am_findings, gnn_result, cfg_profile.

        Returns:
            {
              "adversarial_score": float,         # [0, 1]
              "classification": str,              # "adversarial" | "suspicious" | "benign"
              "confidence": str,                  # "high" | "medium" | "low"
              "signals": {                        # per-signal breakdown
                "taint":       {"raw": float, "weighted": float, "detail": str},
                "callback":    {"raw": float, "weighted": float, "detail": str},
                "similarity":  {"raw": float, "weighted": float, "detail": str},
                "complexity":  {"raw": float, "weighted": float, "detail": str},
                "gnn":         {"raw": float, "weighted": float, "detail": str},
                "obfuscation": {"raw": float, "weighted": float, "detail": str},
              },
              "active_signal_count": int,         # signals with raw > 0.1
              "rescue_window_advisory": str,       # "IMMEDIATE_RISK" | "MONITOR" | "BENIGN"
              "evidence_summary": str,            # human-readable 1-2 sentence summary
            }
        """
        r = pipeline_result

        # ── Compute each signal ──────────────────────────────────────────

        signals: Dict[str, Dict[str, Any]] = {}

        for name, compute_fn in [
            ("taint",       self._compute_taint_signal),
            ("callback",    self._compute_callback_signal),
            ("similarity",  self._compute_similarity_signal),
            ("complexity",  self._compute_complexity_signal),
            ("gnn",         self._compute_gnn_signal),
            ("obfuscation", self._compute_obfuscation_signal),
        ]:
            raw, detail = compute_fn(r)
            raw = max(0.0, min(1.0, raw))
            weighted = raw * self._weights[name]
            signals[name] = {
                "raw": round(raw, 4),
                "weighted": round(weighted, 4),
                "detail": detail,
            }

        # ── Aggregate score ──────────────────────────────────────────────

        adversarial_score = sum(s["weighted"] for s in signals.values())
        adversarial_score = round(max(0.0, min(1.0, adversarial_score)), 4)

        # ── Classification ───────────────────────────────────────────────

        if adversarial_score >= self._thresh_adv:
            classification = "adversarial"
        elif adversarial_score >= self._thresh_sus:
            classification = "suspicious"
        else:
            classification = "benign"

        # ── Confidence ───────────────────────────────────────────────────

        active_count = sum(1 for s in signals.values() if s["raw"] > 0.1)

        if active_count >= _CONFIDENCE_HIGH:
            confidence = "high"
        elif active_count >= _CONFIDENCE_MEDIUM:
            confidence = "medium"
        else:
            confidence = "low"

        # ── Rescue window advisory ───────────────────────────────────────

        if classification == "adversarial" and confidence in ("high", "medium"):
            advisory = "IMMEDIATE_RISK"
        elif classification in ("adversarial", "suspicious"):
            advisory = "MONITOR"
        else:
            advisory = "BENIGN"

        # ── Evidence summary ─────────────────────────────────────────────

        evidence_summary = self._build_evidence_summary(
            classification, confidence, signals, active_count, r
        )

        return {
            "adversarial_score":      adversarial_score,
            "classification":         classification,
            "confidence":             confidence,
            "signals":                signals,
            "active_signal_count":    active_count,
            "rescue_window_advisory": advisory,
            "evidence_summary":       evidence_summary,
        }

    # ── Signal computation methods ────────────────────────────────────────────
    #
    # Each returns (raw_score: float [0,1], detail: str).
    # Raw score is the signal strength before weighting.

    @staticmethod
    def _compute_taint_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        AM1/AM2 findings = strongest adversarial indicator.

        AM1 (calldata → CALL target): attacker controls fund destination.
        AM2 (calldata → CALL value): attacker controls ETH amount.

        LookAhead's core insight: adversarial contracts overwhelmingly
        contain these data-flow patterns.
        """
        findings = r.get("am_findings", [])
        taint_result = r.get("taint_result", {})
        caller_guarded = taint_result.get("caller_guarded", False)

        am1_findings = [f for f in findings if f.get("type") == "AM1"]
        am2_findings = [f for f in findings if f.get("type") == "AM2"]
        am1_count = len(am1_findings)
        am2_count = len(am2_findings)

        if am1_count == 0 and am2_count == 0:
            return 0.0, "no AM1/AM2 taint findings"

        # Caller guard reduces confidence but doesn't eliminate the signal —
        # guards can be bypassed via tx.origin relay, delegatecall, or
        # the guard may protect only some code paths.
        if caller_guarded:
            base = 0.3 * min(am1_count + am2_count, 3)
            return min(1.0, base), (
                f"{am1_count} AM1 + {am2_count} AM2 findings BUT caller guard detected "
                f"— reduced confidence (guard may not cover all paths)"
            )

        # Check for ERC-20 sensitive targets — these are highest confidence
        # because they mean the CALL targets a real DeFi token contract
        erc20_sensitive = any(f.get("erc20_sensitive") for f in am1_findings)

        if erc20_sensitive:
            return 1.0, (
                f"{am1_count} AM1 + {am2_count} AM2 findings with ERC-20 sensitive target "
                f"— high-confidence token theft pattern"
            )

        base = 0.5 + 0.15 * min(am1_count + am2_count - 1, 3)
        return min(1.0, base), (
            f"{am1_count} AM1 + {am2_count} AM2 findings, no caller guard "
            f"— calldata controls fund flow"
        )

    @staticmethod
    def _compute_callback_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        AM5 (flash loan / DEX swap callback without CALLER guard) is a
        strong indicator of a contract designed to interact with DeFi
        protocols in an automated, potentially adversarial way.
        """
        findings = r.get("am_findings", [])
        am5_findings = [f for f in findings if f.get("type") == "AM5"]
        count = len(am5_findings)

        if count == 0:
            return 0.0, "no AM5 callback findings"

        if count >= 3:
            return 1.0, (
                f"{count} unguarded callback selectors — multi-protocol flash loan "
                f"attack contract pattern"
            )
        if count >= 2:
            return 0.8, (
                f"{count} unguarded callback selectors — likely automated DeFi interaction"
            )
        return 0.5, (
            f"1 unguarded callback selector — possible flash loan or swap callback"
        )

    @staticmethod
    def _compute_similarity_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        Bytecode n-gram similarity against known exploit corpus.
        SoK DeFi Attacks §5.3: 80% Jaccard threshold clusters 59 vulnerable
        + 50 adversarial contracts. We use a lower threshold (0.35) for
        early warning with higher recall.
        """
        # SimilarityScanner result may be nested in pipeline output
        # or available as a top-level key if pipeline was extended
        similarity = r.get("similarity", {})

        if not similarity or similarity.get("error"):
            # Try extracting from the pipeline result structure
            return 0.0, "similarity scanner not available or not run"

        score = similarity.get("similarity_score", 0.0)
        match_label = similarity.get("closest_match", "none")
        risk_flag = similarity.get("risk_flag", False)

        if risk_flag:
            return min(1.0, score * 1.5), (
                f"bytecode matches known exploit pattern '{match_label}' "
                f"(Jaccard={score:.3f}) — structural clone of prior attack"
            )

        if score > 0.2:
            return score, (
                f"partial similarity to '{match_label}' (Jaccard={score:.3f}) "
                f"— below threshold but notable"
            )

        return 0.0, f"no significant similarity (max Jaccard={score:.3f})"

    @staticmethod
    def _compute_complexity_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        Multi-hop flash loan + DEX swap detection.
        Adversarial contracts typically integrate multiple DeFi protocol
        interactions (flash loan → swap → swap → drain) in a single call.
        """
        # This comes from CFGProfiler.detect_complex_defi_patterns()
        # which may be in cfg_profile or as a separate key
        complexity = r.get("complexity", {})

        if not complexity:
            # Fall back to extracting from am_findings
            findings = r.get("am_findings", [])
            am5_count = sum(1 for f in findings if f.get("type") == "AM5")
            am7_count = sum(1 for f in findings if f.get("type") == "AM7")
            # Approximate complexity from finding diversity
            if am5_count >= 1 and am7_count >= 1:
                return 0.6, (
                    f"flash callback (AM5) + permissionless storage (AM7) — "
                    f"multi-stage attack pattern"
                )
            return 0.0, "complexity analysis not available"

        score = complexity.get("complexity_score", 0.0)
        review = complexity.get("review_recommended", False)
        patterns = complexity.get("patterns_found", [])

        if review:
            return max(0.8, score), (
                f"review recommended — patterns: {', '.join(patterns)}"
            )
        if score > 0.3:
            return score, f"moderate complexity ({', '.join(patterns)})"
        return 0.0, "low complexity"

    @staticmethod
    def _compute_gnn_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        GNN exploit probability from CFG graph topology.
        The GNN sees structural patterns (call depth, branching factor,
        loop structures) that individual heuristics miss.
        """
        gnn = r.get("gnn_result", {})
        if not gnn or not gnn.get("available", True):
            return 0.0, "GNN not available (checkpoint missing)"

        prob = gnn.get("exploit_probability", 0.0)
        level = gnn.get("risk_level", "UNKNOWN")
        blocks = gnn.get("block_count", 0)

        if prob >= 0.8:
            return 1.0, (
                f"GNN exploit probability {prob:.3f} ({level}) — "
                f"strong structural match to exploit patterns ({blocks} blocks)"
            )
        if prob >= 0.5:
            return prob, (
                f"GNN exploit probability {prob:.3f} ({level}) — "
                f"moderate structural signal ({blocks} blocks)"
            )
        return prob, f"GNN exploit probability {prob:.3f} ({level})"

    @staticmethod
    def _compute_obfuscation_signal(r: Dict[str, Any]) -> Tuple[float, str]:
        """
        Obfuscation is a weak positive signal for adversarial intent.
        Legitimate contracts (MEV bots) are also obfuscated, so this
        gets the lowest weight. But combined with taint/callback signals,
        obfuscation strengthens the adversarial hypothesis.
        """
        cfg_profile = r.get("cfg_profile", {})
        if not cfg_profile:
            return 0.0, "CFG profile not available"

        score = cfg_profile.get("obfuscation_score", 0.0)
        assessment = cfg_profile.get("assessment", "unknown")
        indirect = cfg_profile.get("indirect_jumps", 0)

        if assessment == "obfuscated":
            return 1.0, (
                f"obfuscation_score={score:.3f} ({assessment}) — "
                f"{indirect} indirect jumps — intentional control flow hiding"
            )
        if assessment == "likely_obfuscated":
            return score, (
                f"obfuscation_score={score:.3f} ({assessment}) — "
                f"{indirect} indirect jumps"
            )
        return 0.0, f"clean CFG (obfuscation_score={score:.3f})"

    # ── Evidence summary ──────────────────────────────────────────────────────

    @staticmethod
    def _build_evidence_summary(
        classification: str,
        confidence: str,
        signals: Dict[str, Dict[str, Any]],
        active_count: int,
        r: Dict[str, Any],
    ) -> str:
        """Build a human-readable 1-2 sentence summary of the classification."""

        if classification == "benign":
            return (
                "No significant adversarial indicators detected across taint analysis, "
                "pattern matching, GNN scoring, or bytecode similarity."
            )

        # Collect the top contributing signals
        ranked = sorted(
            signals.items(),
            key=lambda kv: kv[1]["weighted"],
            reverse=True,
        )
        top_signals = [
            f"{name} ({s['detail'][:60]})"
            for name, s in ranked
            if s["raw"] > 0.1
        ][:3]

        am_types = r.get("am_types_found", [])
        type_str = ", ".join(am_types) if am_types else "none"

        if classification == "adversarial":
            return (
                f"Contract classified as ADVERSARIAL ({confidence} confidence, "
                f"{active_count} active signals). "
                f"Vulnerability types: {type_str}. "
                f"Primary indicators: {'; '.join(top_signals)}."
            )
        else:
            return (
                f"Contract classified as SUSPICIOUS ({confidence} confidence, "
                f"{active_count} active signals). "
                f"Warrants monitoring — primary indicators: {'; '.join(top_signals)}."
            )
