#!/usr/bin/env python3
"""
scripts/watch_deployments.py

Calyx Pre-Attack Detection — watch for adversarial contract deployments.

Monitors Ethereum for newly deployed contracts, runs the full SKANF pipeline
on each one, and classifies them as adversarial/suspicious/benign BEFORE any
attack transaction fires.

This is Stage 9 of the Calyx pipeline — the preventive detection layer
that transforms SKANF from forensic analysis into real-time defense.

Usage:
    # Basic: watch Ethereum mainnet, print alerts to stdout
    python scripts/watch_deployments.py

    # With LLM audit on adversarial contracts
    python scripts/watch_deployments.py --audit

    # Lower threshold for more alerts (default: 0.35)
    python scripts/watch_deployments.py --min-score 0.25

    # Save alerts to disk
    python scripts/watch_deployments.py --save-alerts results/alerts/

    # Different network
    python scripts/watch_deployments.py --network polygon

    # One-shot: classify a single address (no streaming)
    python scripts/watch_deployments.py --address 0x00000000003b3cc22af3ae1eac0440bcee416b40

    # One-shot: classify raw bytecode
    python scripts/watch_deployments.py --bytecode 0x608060405234...

Environment variables (set in .env):
    ETHERSCAN_API_KEY       Required for address and poll modes
    ANTHROPIC_API_KEY       \
    GEMINI_API_KEY           > One needed for --audit (Gemini free tier works)
    GROQ_API_KEY            /
    OPENAI_API_KEY         /
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ── ANSI color helpers ────────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

def red(t: str)    -> str: return _c("91", t)
def orange(t: str) -> str: return _c("93", t)
def green(t: str)  -> str: return _c("92", t)
def cyan(t: str)   -> str: return _c("96", t)
def bold(t: str)   -> str: return _c("1",  t)
def dim(t: str)    -> str: return _c("2",  t)


# ── One-shot classification ──────────────────────────────────────────────────

def _run_one_shot(args: argparse.Namespace) -> None:
    """Classify a single address or bytecode and print the result."""
    from analysis.deployment_pipeline import DeploymentPipeline

    dp = DeploymentPipeline(audit_adversarial=args.audit)

    print(bold("\n╔══════════════════════════════════════════════════╗"))
    print(bold("║  Calyx · Adversarial Contract Classification     ║"))
    print(bold("╚══════════════════════════════════════════════════╝"))

    t0 = time.time()

    if args.address:
        print(f"  Target:  {cyan(args.address)}")
        print(f"  Network: {args.network}")
        print(f"  Mode:    one-shot (address)")
        print()
        result = dp.classify_address(args.address, network=args.network)
    else:
        bcode_display = args.bytecode[:40] + "..." if len(args.bytecode) > 40 else args.bytecode
        print(f"  Target:  {cyan(bcode_display)}")
        print(f"  Mode:    one-shot (bytecode)")
        print()
        result = dp.classify_bytecode(args.bytecode)

    elapsed = time.time() - t0

    if result.get("error"):
        print(f"  {red('ERROR:')} {result['error']}")
        sys.exit(1)

    # Print classification
    label = result["classification"]
    score = result["adversarial_score"]
    confidence = result["confidence"]

    label_color = {
        "adversarial": red,
        "suspicious":  orange,
        "benign":      green,
        "error":       red,
    }.get(label, dim)

    print(bold("── Classification ──────────────────────────────────"))
    print(f"  Result:     {label_color(bold(label.upper()))}")
    print(f"  Score:      {score:.4f}")
    print(f"  Confidence: {confidence}")
    print(f"  Advisory:   {result.get('rescue_window_advisory', 'N/A')}")
    print(f"  Signals:    {result.get('active_signal_count', 0)} active")
    print(f"  Time:       {elapsed:.2f}s")
    print()

    # Print signal breakdown
    signals = result.get("signals", {})
    if signals:
        print(bold("── Signal Breakdown ────────────────────────────────"))
        for name, sig in sorted(signals.items(), key=lambda kv: -kv[1]["weighted"]):
            raw = sig["raw"]
            weighted = sig["weighted"]
            detail = sig["detail"][:70]
            bar_len = int(raw * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)

            if raw > 0.5:
                col = orange
            elif raw > 0.1:
                col = dim
            else:
                col = lambda t: t

            print(f"  {name:>12s}  {col(bar)}  {raw:.3f} (w={weighted:.3f})")
            print(f"               {dim(detail)}")
        print()

    # Print evidence summary
    summary = result.get("evidence_summary", "")
    if summary:
        print(bold("── Evidence Summary ────────────────────────────────"))
        print(f"  {summary}")
        print()

    # Exit code: 1 if adversarial or suspicious, 0 if benign
    sys.exit(0 if label == "benign" else 1)


# ── Streaming mode ───────────────────────────────────────────────────────────

async def _run_streaming(args: argparse.Namespace) -> None:
    """Watch for new deployments in real-time."""
    from analysis.deployment_pipeline import DeploymentPipeline

    dp = DeploymentPipeline(
        audit_adversarial=args.audit,
        min_adversarial_score=args.min_score,
        save_alerts_dir=args.save_alerts,
    )

    print(bold("\n╔══════════════════════════════════════════════════╗"))
    print(bold("║  Calyx · Pre-Attack Deployment Monitor           ║"))
    print(bold("╚══════════════════════════════════════════════════╝"))
    print(f"  Network:    {args.network}")
    print(f"  Poll:       every {args.poll_interval}s")
    print(f"  Min score:  {args.min_score}")
    print(f"  Audit:      {'on' if args.audit else 'off'}")
    print(f"  Save:       {args.save_alerts or 'disabled'}")
    print(dim("  Ctrl-C to stop\n"))

    await dp.run(
        network=args.network,
        poll_interval=args.poll_interval,
        mode="poll",
    )


# ── Argument parsing ─────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calyx Pre-Attack Detection — Adversarial Contract Classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Mode selection
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--address", metavar="0x...",
        help="One-shot: classify a single contract address",
    )
    group.add_argument(
        "--bytecode", metavar="0x...",
        help="One-shot: classify raw bytecode hex",
    )
    # If neither --address nor --bytecode is given → streaming mode

    # Common options
    parser.add_argument(
        "--network", default="ethereum",
        choices=["ethereum", "polygon", "bsc", "arbitrum", "optimism"],
        help="Chain to monitor (default: ethereum)",
    )
    parser.add_argument(
        "--audit", action="store_true",
        help="Run LLM audit on adversarial contracts (requires API key)",
    )

    # Streaming options
    parser.add_argument(
        "--poll-interval", type=int, default=15,
        help="Seconds between Etherscan polls (default: 15)",
    )
    parser.add_argument(
        "--min-score", type=float, default=0.35,
        help="Minimum adversarial score to trigger alert (default: 0.35)",
    )
    parser.add_argument(
        "--save-alerts", metavar="DIR",
        help="Directory to save alert JSON files",
    )

    # Logging
    parser.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Load .env if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    # Route to appropriate mode
    if args.address or args.bytecode:
        _run_one_shot(args)
    else:
        # Streaming mode — check prerequisites
        if not os.environ.get("ETHERSCAN_API_KEY"):
            print(red("Error: ETHERSCAN_API_KEY required for deployment monitoring."))
            print(dim("  Get a free key at https://etherscan.io/apis"))
            print(dim("  Or use --address for one-shot analysis."))
            sys.exit(1)

        try:
            asyncio.run(_run_streaming(args))
        except KeyboardInterrupt:
            print(dim("\n  Monitor stopped."))


if __name__ == "__main__":
    main()