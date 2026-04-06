"""
analysis/deployment_pipeline.py

Adversarial Deployment Pipeline — Stage 9 orchestrator.

End-to-end flow:
  DeploymentWatcher detects new contract → BytecodePipeline analyzes bytecode →
  AdversarialClassifier scores adversarial probability → Alert fires if threshold met →
  Optional AuditAgent deep dive on adversarial contracts.

This module answers the SKANF author's explicit research direction:
  "Can we build SKANF as a tool for some AI agent, which may first deobfuscate
   the contract flow and help them analyze the contract? Can AI agent still
   achieve good results with the idea from SKANF?"

The answer is yes — by turning SKANF from a forensic tool into a preventive one,
running bytecode analysis on contracts at deploy-time rather than post-exploit.

Integration with existing Calyx modules (zero changes needed):
  - BytecodePipeline.analyze_bytecode()  — called as-is
  - ContractAnalysisCache                — reused for dedup
  - ContextBuilder.build()               — generates evidence package per alert
  - AuditAgent.audit()                   — optional deep analysis on adversarial contracts
  - EtherscanClient                      — used by watcher for polling + bytecode fetch
  - SimilarityScanner                    — result extracted from pipeline output

Usage:
    import asyncio
    from analysis.deployment_pipeline import DeploymentPipeline

    # Basic: print alerts to stdout
    pipeline = DeploymentPipeline()
    asyncio.run(pipeline.run())

    # Advanced: custom alert handler + LLM audit on adversarial contracts
    async def my_alert_handler(alert):
        send_to_slack(alert)

    pipeline = DeploymentPipeline(
        alert_callback=my_alert_handler,
        audit_adversarial=True,
    )
    asyncio.run(pipeline.run(network="ethereum"))
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)


class DeploymentPipeline:
    """
    Orchestrates: watch new deployments → analyze → classify → alert.

    Lazy-imports all Calyx modules so this file can be imported even if
    some dependencies are missing (graceful degradation).
    """

    def __init__(
        self,
        alert_callback: Optional[Callable] = None,
        audit_adversarial: bool = False,
        min_adversarial_score: float = 0.35,
        save_alerts_dir: Optional[str] = None,
    ) -> None:
        """
        Args:
            alert_callback:       Async or sync callable invoked with alert dict.
                                  If None, prints to stdout with color.
            audit_adversarial:    Run AuditAgent on contracts classified as adversarial.
            min_adversarial_score: Minimum score to trigger an alert (default 0.35 = suspicious+).
            save_alerts_dir:      Directory to save alert JSON files (created if absent).
        """
        self._alert_cb        = alert_callback
        self._audit           = audit_adversarial
        self._min_score       = min_adversarial_score
        self._save_dir        = save_alerts_dir
        self._stats           = {
            "contracts_analyzed": 0,
            "adversarial": 0,
            "suspicious": 0,
            "benign": 0,
            "alerts_fired": 0,
            "audit_reports": 0,
            "errors": 0,
        }

        # Lazy-loaded modules
        self._pipeline    = None
        self._classifier  = None
        self._cache       = None
        self._audit_agent = None

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    # ── Module initialization (lazy) ──────────────────────────────────────────

    def _ensure_modules(self) -> None:
        """Lazy-import and instantiate all required modules."""
        if self._pipeline is not None:
            return

        from analysis.bytecode_pipeline import BytecodePipeline
        from detectors.deployment_watcher.classifier import AdversarialClassifier

        self._pipeline   = BytecodePipeline()
        self._classifier = AdversarialClassifier()

        try:
            from detectors.mempool_monitor.contract_cache import ContractAnalysisCache
            self._cache = ContractAnalysisCache(ttl=3600, maxsize=1000)
        except ImportError:
            log.warning("ContractAnalysisCache not available — no dedup caching")
            self._cache = None

        if self._audit:
            try:
                from analysis.audit_agent import AuditAgent
                if AuditAgent.available():
                    self._audit_agent = AuditAgent()
                    log.info("AuditAgent loaded — will audit adversarial contracts")
                else:
                    log.warning(
                        "AuditAgent not available (no LLM key configured). "
                        "Adversarial contracts will be classified but not audited."
                    )
            except ImportError:
                log.warning("AuditAgent not importable — skipping LLM audits")

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run(
        self,
        network: str = "ethereum",
        poll_interval: int = 15,
        mode: str = "poll",
        ws_url: Optional[str] = None,
    ) -> None:
        """
        Start monitoring and classifying new deployments.

        Args:
            network:       Chain to monitor (default "ethereum").
            poll_interval: Seconds between Etherscan polls (default 15).
            mode:          "poll" (default) or "stream" (stretch goal).
            ws_url:        WebSocket URL for stream mode.
        """
        self._ensure_modules()

        from integrations.etherscan_client import EtherscanClient
        from detectors.deployment_watcher.watcher import DeploymentWatcher

        client = EtherscanClient(network=network)
        watcher = DeploymentWatcher(
            etherscan_client=client,
            on_deploy=self._on_new_contract,
            poll_interval=poll_interval,
            network=network,
        )

        log.info(
            f"DeploymentPipeline starting — {mode} mode on {network}, "
            f"poll_interval={poll_interval}s, audit={'on' if self._audit else 'off'}"
        )

        if mode == "stream":
            url = ws_url or os.environ.get("MEMPOOL_WS_URL", "")
            await watcher.run_stream(url)
        else:
            await watcher.run_poll()

    # ── Per-deployment handler ────────────────────────────────────────────────

    async def _on_new_contract(
        self,
        address: str,
        bytecode_hex: str,
        deployer: str,
        tx_hash: str,
        block_number: int,
    ) -> None:
        """
        Called by DeploymentWatcher for each new contract deployment.

        1. Run BytecodePipeline.analyze_bytecode()
        2. Run AdversarialClassifier.classify()
        3. If score >= threshold → build alert → fire callback
        4. If adversarial + audit enabled → run AuditAgent
        """
        t0 = time.time()
        self._stats["contracts_analyzed"] += 1

        try:
            # ── Step 1: Pipeline analysis ────────────────────────────────
            pipeline_result = self._pipeline.analyze_bytecode(
                bytecode_hex,
                address=address,
                network="ethereum",
                validate=False,     # skip Anvil — too slow for real-time
                audit=False,        # audit handled separately below
            )

            if pipeline_result.get("error"):
                log.warning(
                    f"Pipeline error for {address}: {pipeline_result['error']}"
                )
                self._stats["errors"] += 1
                return

            # ── Step 2: Adversarial classification ───────────────────────
            classification = self._classifier.classify(pipeline_result)

            label = classification["classification"]
            score = classification["adversarial_score"]
            elapsed = time.time() - t0

            # Track stats
            if label == "adversarial":
                self._stats["adversarial"] += 1
            elif label == "suspicious":
                self._stats["suspicious"] += 1
            else:
                self._stats["benign"] += 1

            log.info(
                f"[{address[:12]}...] {label.upper()} "
                f"(score={score:.3f}, {classification['active_signal_count']} signals, "
                f"{elapsed:.1f}s)"
            )

            # ── Step 3: Alert if above threshold ─────────────────────────
            if score < self._min_score:
                return

            # Build context report for the alert
            context_md = ""
            try:
                from analysis.context_builder import ContextBuilder
                context_md = ContextBuilder(pipeline_result).build()
            except Exception:
                pass

            # Optional LLM audit for adversarial contracts
            audit_report = None
            if (
                label == "adversarial"
                and self._audit_agent is not None
            ):
                try:
                    audit_report = self._audit_agent.audit(pipeline_result)
                    self._stats["audit_reports"] += 1
                except Exception as exc:
                    log.warning(f"AuditAgent failed for {address}: {exc}")

            # Build the alert
            alert = self._build_alert(
                address=address,
                deployer=deployer,
                tx_hash=tx_hash,
                block_number=block_number,
                classification=classification,
                pipeline_result=pipeline_result,
                context_md=context_md,
                audit_report=audit_report,
                elapsed=elapsed,
            )

            # Fire alert callback
            self._stats["alerts_fired"] += 1

            if self._alert_cb:
                result = self._alert_cb(alert)
                if asyncio.iscoroutine(result):
                    await result
            else:
                self._default_alert(alert)

            # Save to disk if configured
            if self._save_dir:
                self._save_alert(alert)

        except Exception as exc:
            log.error(f"Classification error for {address}: {exc}")
            self._stats["errors"] += 1

    # ── Alert construction ────────────────────────────────────────────────────

    @staticmethod
    def _build_alert(
        address: str,
        deployer: str,
        tx_hash: str,
        block_number: int,
        classification: Dict[str, Any],
        pipeline_result: Dict[str, Any],
        context_md: str,
        audit_report: Optional[Dict[str, Any]],
        elapsed: float,
    ) -> Dict[str, Any]:
        """Build a structured alert dict."""

        label = classification["classification"]

        if label == "adversarial":
            alert_type = "ADVERSARIAL_DEPLOYMENT"
            severity = "CRITICAL" if classification["confidence"] == "high" else "HIGH"
        else:
            alert_type = "SUSPICIOUS_DEPLOYMENT"
            severity = "MEDIUM"

        return {
            "alert_type":             alert_type,
            "severity":               severity,
            "timestamp":              datetime.now(timezone.utc).isoformat(),

            # Contract identity
            "contract_address":       address,
            "deployer_address":       deployer,
            "deployment_tx_hash":     tx_hash,
            "deployment_block":       block_number,

            # Classification
            "adversarial_score":      classification["adversarial_score"],
            "classification":         classification["classification"],
            "confidence":             classification["confidence"],
            "active_signal_count":    classification["active_signal_count"],
            "rescue_window_advisory": classification["rescue_window_advisory"],
            "evidence_summary":       classification["evidence_summary"],
            "signals":                classification["signals"],

            # Pipeline results (summary)
            "risk_score":             pipeline_result.get("risk_score", 0.0),
            "risk_level":             pipeline_result.get("risk_level", "UNKNOWN"),
            "am_types_found":         pipeline_result.get("am_types_found", []),
            "finding_count":          len(pipeline_result.get("am_findings", [])),

            # Audit (if available)
            "audit_verdict":          (
                audit_report.get("verdict") if audit_report else None
            ),
            "audit_report":           audit_report,

            # Context (for downstream consumers / dashboards)
            "context_report_md":      context_md,

            # Metadata
            "analysis_time_seconds":  round(elapsed, 2),
        }

    # ── Default alert printer ─────────────────────────────────────────────────

    @staticmethod
    def _default_alert(alert: Dict[str, Any]) -> None:
        """Print alert to stdout with ANSI color coding."""

        def _c(code: str, text: str) -> str:
            if not sys.stdout.isatty():
                return text
            return f"\033[{code}m{text}\033[0m"

        red    = lambda t: _c("91", t)
        orange = lambda t: _c("93", t)
        green  = lambda t: _c("92", t)
        cyan   = lambda t: _c("96", t)
        bold   = lambda t: _c("1", t)
        dim    = lambda t: _c("2", t)

        severity_color = {
            "CRITICAL": red,
            "HIGH":     orange,
            "MEDIUM":   orange,
        }
        col = severity_color.get(alert["severity"], dim)

        print()
        print(col(bold(f"  ╔══ {alert['alert_type']} ══════════════════════════════════╗")))
        print(col(bold(f"  ║  Severity: {alert['severity']}")))
        print(f"  ║  Contract:  {cyan(alert['contract_address'])}")
        print(f"  ║  Deployer:  {dim(alert['deployer_address'])}")
        print(f"  ║  Block:     {alert['deployment_block']}")
        print(f"  ║  Score:     {col(bold(str(alert['adversarial_score'])))}")
        print(f"  ║  Class:     {col(bold(alert['classification'].upper()))}")
        print(f"  ║  Confidence:{alert['confidence']}")
        print(f"  ║  AM Types:  {alert['am_types_found']}")
        print(f"  ║  Advisory:  {alert['rescue_window_advisory']}")

        if alert.get("audit_verdict"):
            print(f"  ║  LLM Verdict: {red(bold(alert['audit_verdict']))}")

        print(f"  ║")
        print(f"  ║  {alert['evidence_summary'][:100]}")
        print(col(bold(f"  ╚═══════════════════════════════════════════════════════════╝")))
        print()

    # ── Alert persistence ─────────────────────────────────────────────────────

    def _save_alert(self, alert: Dict[str, Any]) -> None:
        """Save alert as JSON file to the configured directory."""
        try:
            save_dir = Path(self._save_dir)
            save_dir.mkdir(parents=True, exist_ok=True)

            addr_short = alert["contract_address"][:12]
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"alert_{ts}_{addr_short}.json"
            filepath = save_dir / filename

            # Remove context_report_md from saved JSON (too large)
            save_data = {k: v for k, v in alert.items() if k != "context_report_md"}

            filepath.write_text(
                json.dumps(save_data, indent=2, default=str),
                encoding="utf-8",
            )
            log.info(f"Alert saved: {filepath}")
        except Exception as exc:
            log.warning(f"Failed to save alert: {exc}")

    # ── One-shot analysis (non-streaming) ─────────────────────────────────────

    def classify_address(
        self,
        address: str,
        network: str = "ethereum",
    ) -> Dict[str, Any]:
        """
        One-shot: analyze a single address and return classification.
        Useful for testing, backtesting, and API integration.

        Returns the full classification dict (same as AdversarialClassifier.classify()).
        """
        self._ensure_modules()

        pipeline_result = self._pipeline.analyze_address(
            address, network=network, validate=False, audit=False,
        )

        if pipeline_result.get("error"):
            return {
                "adversarial_score": 0.0,
                "classification": "error",
                "confidence": "low",
                "error": pipeline_result["error"],
            }

        return self._classifier.classify(pipeline_result)

    def classify_bytecode(
        self,
        bytecode_hex: str,
    ) -> Dict[str, Any]:
        """
        One-shot: analyze raw bytecode and return classification.
        No network calls needed — pure local analysis.
        """
        self._ensure_modules()

        pipeline_result = self._pipeline.analyze_bytecode(
            bytecode_hex, validate=False, audit=False,
        )

        if pipeline_result.get("error"):
            return {
                "adversarial_score": 0.0,
                "classification": "error",
                "confidence": "low",
                "error": pipeline_result["error"],
            }

        return self._classifier.classify(pipeline_result)