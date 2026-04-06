#!/usr/bin/env python3
"""
scripts/demo_pipeline.py

Calyx SKANF-Lite Demo — Hackathon P3.

Demonstrates the full bytecode analysis pipeline in a single CLI command.
Suitable for live demos and as a reference for integrators.

Usage:
    # Analyze a contract by address (requires ETHERSCAN_API_KEY):
    python scripts/demo_pipeline.py --address 0x00000000003b3cc22af3ae1eac0440bcee416b40

    # Analyze raw bytecode hex:
    python scripts/demo_pipeline.py --bytecode 0x608060405234801561001057600080fd5b50...

    # With fork-EVM exploit validation (requires ETHEREUM_RPC_URL + Anvil):
    python scripts/demo_pipeline.py --address 0x... --validate

    # Save LLM context report to file:
    python scripts/demo_pipeline.py --address 0x... --save-context results/

    # Different network:
    python scripts/demo_pipeline.py --address 0x... --network polygon

Output:
    Stage-by-stage progress with findings table and final risk assessment.
    Optionally saves a full markdown context report to results/<address>.md.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ── ANSI color helpers ────────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    """Wrap text in ANSI color code (skipped if stdout is not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t: str)    -> str: return _c("91", t)
def orange(t: str) -> str: return _c("93", t)
def green(t: str)  -> str: return _c("92", t)
def cyan(t: str)   -> str: return _c("96", t)
def bold(t: str)   -> str: return _c("1",  t)
def dim(t: str)    -> str: return _c("2",  t)


_RISK_COLOR = {
    "CRITICAL": red,
    "HIGH":     orange,
    "MEDIUM":   orange,
    "LOW":      green,
    "UNKNOWN":  dim,
}

_SEV_COLOR = {
    "critical": red,
    "high":     orange,
    "medium":   orange,
    "low":      green,
}


# ── Stage printer ─────────────────────────────────────────────────────────────

def stage(n: int, name: str, detail: str = "") -> None:
    tag = cyan(f"[Stage {n}]")
    print(f"\n{tag} {bold(name)}")
    if detail:
        print(f"  {dim(detail)}")


def ok(msg: str) -> None:
    print(f"  {green('✓')} {msg}")


def warn(msg: str) -> None:
    print(f"  {orange('⚠')} {msg}")


def err(msg: str) -> None:
    print(f"  {red('✗')} {msg}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calyx SKANF-Lite — Smart Contract Security Analysis Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--address",  metavar="0x...", help="Contract address to analyze")
    group.add_argument("--bytecode", metavar="0x...", help="Raw bytecode hex to analyze")

    parser.add_argument(
        "--network", default="ethereum",
        choices=["ethereum", "polygon", "bsc", "arbitrum", "optimism"],
        help="Chain to use when fetching by address (default: ethereum)",
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="Run fork-EVM exploit validation (requires ETHEREUM_RPC_URL + Anvil)",
    )
    parser.add_argument(
        "--audit", action="store_true",
        help=(
            "Run LLM audit agent (Stage 8) — produces a natural-language security "
            "report. Requires one of: ANTHROPIC_API_KEY, GEMINI_API_KEY, "
            "GROQ_API_KEY, OPENAI_API_KEY."
        ),
    )
    parser.add_argument(
        "--save-context", metavar="DIR",
        help="Directory to save the markdown context report (created if absent)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-stage output; only print final result",
    )
    args = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────────────────────
    if not args.quiet:
        print(bold("\n╔══════════════════════════════════════════════════╗"))
        print(bold("║   Calyx  ·  SKANF-Lite  ·  EVM Security Demo    ║"))
        print(bold("╚══════════════════════════════════════════════════╝"))
        target = args.address or "(raw bytecode)"
        network = args.network if args.address else "N/A"
        print(f"  Target : {cyan(target)}")
        print(f"  Network: {network}")
        print(f"  Validate: {args.validate}")
        print(f"  Audit  : {args.audit}")
        print()

    # ── Import pipeline ───────────────────────────────────────────────────────
    try:
        from analysis.bytecode_pipeline import BytecodePipeline
    except ImportError as e:
        err(f"Import failed: {e}")
        err("Run from the project root: python scripts/demo_pipeline.py ...")
        sys.exit(1)

    pipeline = BytecodePipeline()
    t0 = time.time()

    # ── Run analysis ──────────────────────────────────────────────────────────
    if not args.quiet:
        if args.address:
            stage(0, "Fetching bytecode", f"Etherscan API → {args.address}")
        else:
            stage(0, "Parsing bytecode", f"{len(args.bytecode)} hex chars")

    try:
        if args.address:
            result = pipeline.analyze_address(
                args.address, network=args.network,
                validate=args.validate, audit=args.audit,
            )
        else:
            result = pipeline.analyze_bytecode(
                args.bytecode, validate=args.validate, audit=args.audit,
            )
            # Also build context for bytecode-only mode
            try:
                from analysis.context_builder import ContextBuilder
                result["context"] = ContextBuilder(result).build()
            except Exception:
                pass
    except Exception as exc:
        err(f"Pipeline error: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    elapsed = time.time() - t0

    if result.get("error"):
        err(f"Analysis failed: {result['error']}")
        sys.exit(1)

    # ── Per-stage summary ─────────────────────────────────────────────────────
    if not args.quiet:
        _print_stage_details(result)

    # ── Findings table ────────────────────────────────────────────────────────
    _print_findings(result)

    # ── Risk score ────────────────────────────────────────────────────────────
    _print_risk(result, elapsed)

    # ── AI Audit Report ───────────────────────────────────────────────────────
    if args.audit:
        _print_audit_report(result)

    # ── Save context report ───────────────────────────────────────────────────
    if args.save_context:
        _save_context(result, args)

    # ── Exit code ─────────────────────────────────────────────────────────────
    risk_level = result.get("risk_level", "UNKNOWN")
    sys.exit(0 if risk_level in ("LOW", "UNKNOWN") else 1)


def _print_stage_details(result: Dict[str, Any]) -> None:
    # Stage 3a: CFG deobfuscation
    cfg = result.get("cfg_deob", {})
    stage(3, "CFG Deobfuscation",
          f"{cfg.get('block_count','?')} blocks, {cfg.get('edge_count','?')} edges")
    ok(f"Resolved jumps: {cfg.get('resolved', '?')}")
    ok(f"Over-approximated: {cfg.get('approximated', '?')}")

    # Stage 3b: CFG profiling
    prof = result.get("cfg_profile", {})
    if prof:
        obs = prof.get("obfuscation_score", 0.0)
        asmt = prof.get("assessment", "N/A")
        stage(3, "CFG Profiling", f"obfuscation_score={obs:.3f}")
        ok(f"Assessment: {asmt}")

    # Stage 4: Txn analysis
    txn = result.get("txn_result", {})
    if txn:
        stage(4, "Transaction Analysis",
              f"anomaly_score={txn.get('anomaly_score', 0.0):.3f}")
        flags = txn.get("anomaly_flags", [])
        if flags:
            for fl in flags:
                warn(f"Flag: {fl}")
        else:
            ok("No anomaly flags")

    # P1: Txn-guided taint
    tgt = result.get("txn_guided_taint", {})
    if tgt and tgt.get("txn_count", 0) > 0:
        stage(4, "Txn-Guided Taint (P1)",
              f"{tgt['txn_count']} transactions analyzed")
        hot = tgt.get("hot_selectors", [])
        if hot:
            ok(f"Hot selector: {hot[0]['selector']} ({hot[0]['count']} calls, {hot[0]['pct']}%)")
        ev = tgt.get("evidence_txns", [])
        if ev:
            warn(f"{len(ev)} evidence transaction(s) match vulnerability patterns")

    # Stage 5a: Taint
    taint = result.get("taint_result", {})
    am12  = [f for f in result.get("am_findings", []) if f["type"] in ("AM1", "AM2")]
    stage(5, "Taint Analysis (AM1/AM2)",
          f"caller_guarded={taint.get('caller_guarded', False)}")
    if am12:
        warn(f"{len(am12)} AM1/AM2 finding(s)")
    else:
        ok("No AM1/AM2 findings")

    # Stage 5b: Pattern detector
    am345 = [f for f in result.get("am_findings", []) if f["type"] in ("AM3", "AM4", "AM5", "AM7", "AM8")]
    stage(5, "AM Pattern Detector (AM3–AM8)")
    if am345:
        warn(f"{len(am345)} pattern finding(s) (AM3–AM8)")
    else:
        ok("No AM3–AM8 pattern findings")

    # Stage 5c: GNN
    gnn = result.get("gnn_result", {})
    stage(5, "Bytecode GNN",
          f"prob={gnn.get('exploit_probability', 0.0):.3f}, "
          f"blocks={gnn.get('block_count', 0)}, edges={gnn.get('edge_count', 0)}")
    prob = gnn.get("exploit_probability", 0.0)
    (warn if prob > 0.5 else ok)(f"Exploit probability: {prob:.3f}")

    # Stage 7: Exploit validation
    confirmed = result.get("confirmed_exploits", [])
    if confirmed:
        stage(7, "Exploit Validation (Gap 3)")
        for ex in confirmed:
            warn(f"CONFIRMED {ex['type']} — {ex.get('eth_drained_wei', 0)} wei drained")


def _print_findings(result: Dict[str, Any]) -> None:
    findings = result.get("am_findings", [])
    confirmed_hashes = {id(f) for f in result.get("confirmed_exploits", [])}

    print()
    print(bold("── Findings ─────────────────────────────────────────"))
    if not findings:
        print(f"  {green('No vulnerabilities detected.')}")
        return

    for f in findings:
        sev  = f.get("severity", "low")
        typ  = f.get("type", "?")
        pc   = f.get("pc", "?")
        desc = f.get("description", "")[:100]
        col  = _SEV_COLOR.get(sev, dim)
        conf = " [CONFIRMED]" if f.get("confirmed") else ""
        print(f"  {col(f'[{typ}]')} {bold(sev.upper())} pc={pc}{conf}")
        print(f"    {dim(desc)}")


def _print_risk(result: Dict[str, Any], elapsed: float) -> None:
    score = result.get("risk_score", 0.0)
    level = result.get("risk_level", "UNKNOWN")
    col   = _RISK_COLOR.get(level, dim)

    print()
    print(bold("── Risk Assessment ──────────────────────────────────"))
    print(f"  Risk Level : {col(bold(level))}")
    print(f"  Risk Score : {score:.3f} / 1.000")
    bd = result.get("breakdown", {})
    if bd:
        print(f"  GNN:       {bd.get('gnn_contribution', 0.0):.3f}  "
              f"Findings: {bd.get('llm_contribution', 0.0):.3f}  "
              f"Txn: {bd.get('txn_contribution', 0.0):.3f}")
    print(f"  Time       : {elapsed:.2f}s")
    print()


def _print_audit_report(result: Dict[str, Any]) -> None:
    report = result.get("audit_report")
    audit_err = result.get("audit_error")

    print()
    print(bold("── AI Audit Report (Stage 8) ────────────────────────"))

    if not report or audit_err:
        msg = audit_err or "No audit report generated."
        # Distinguish "no API key" from actual errors
        if "No LLM provider" in str(msg):
            warn("No LLM provider configured.")
            print(f"  {dim('Set one of: ANTHROPIC_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, OPENAI_API_KEY')}")
            print(f"  {dim('Free options: Gemini Flash (GEMINI_API_KEY) or Groq Llama (GROQ_API_KEY)')}")
        else:
            err(f"Audit failed: {msg}")
        return

    provider = report.get("provider", "unknown")
    model    = report.get("model", "unknown")
    verdict  = report.get("verdict", "INCONCLUSIVE")
    triage   = report.get("triage_recommendation", "FLAG")

    verdict_col = {
        "VULNERABLE":        red,
        "LIKELY_VULNERABLE": orange,
        "CLEAN":             green,
        "INCONCLUSIVE":      dim,
    }.get(verdict, dim)

    triage_col = {
        "BLOCK":   red,
        "FLAG":    orange,
        "MONITOR": orange,
        "SAFE":    green,
    }.get(triage, dim)

    print(f"  Model   : {dim(f'{provider}/{model}')}")
    print(f"  Verdict : {verdict_col(bold(verdict))}")
    print(f"  Triage  : {triage_col(bold(triage))}")
    print()

    summary = report.get("vulnerability_summary", "")
    if summary:
        print(f"  {bold('Summary:')} {summary}")
        print()

    findings = report.get("findings", [])
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "LOW")
        col   = _RISK_COLOR.get(sev.upper(), dim)
        conf  = f.get("confidence", "?")
        title = f.get("title", f.get("type", "Finding"))
        print(f"  {col(bold(f'[{i}] {title}'))}  severity={col(sev)}  confidence={conf}")

        desc = f.get("description", "")
        if desc:
            print(f"    {dim('What:')}")
            for line in desc.split(". "):
                if line.strip():
                    print(f"      {line.strip()}.")
        exploit = f.get("exploit_scenario", "")
        if exploit:
            print(f"    {dim('Exploit:')}")
            lines = exploit if isinstance(exploit, list) else exploit.split("\n")
            for line in lines:
                if str(line).strip():
                    print(f"      {str(line).strip()}")
        rec = f.get("recommendation", "")
        if rec:
            print(f"    {green('Fix:')} {rec}")
        print()

    assessment = report.get("overall_assessment", "")
    if assessment:
        print(f"  {bold('Assessment:')}")
        for line in assessment.split(". "):
            if line.strip():
                print(f"    {line.strip()}.")
        print()

    notes = report.get("audit_notes", "")
    if notes:
        print(f"  {dim('Notes: ' + notes)}")


def _save_context(result: Dict[str, Any], args: argparse.Namespace) -> None:
    save_dir = Path(args.save_context)
    save_dir.mkdir(parents=True, exist_ok=True)

    label = args.address or "bytecode"
    label = label.replace("0x", "").replace("/", "_")[:20]
    out_path = save_dir / f"context_{label}.md"

    context = result.get("context", "")
    if not context:
        try:
            from analysis.context_builder import ContextBuilder
            context = ContextBuilder(result).build()
        except Exception as e:
            warn(f"Could not build context: {e}")
            return

    out_path.write_text(context, encoding="utf-8")
    print(f"  {green('✓')} Context report saved → {cyan(str(out_path))}")


if __name__ == "__main__":
    main()
