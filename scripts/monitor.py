#!/usr/bin/env python3
"""
scripts/monitor.py

Calyx Real-Time Mempool Monitor.

Watches the Ethereum mempool for transactions targeting high-value DeFi
contracts (SKANF s 50 sensitive addresses) and runs Calyx detectors
automatically on each match.

  Fast path (always):   CalldataVerifier  -- UI manipulation check, <50ms
  Deep path (cached):   BytecodePipeline  -- full SKANF analysis, ~5s,
                                             once per unique contract address

Usage:
    python scripts/monitor.py
    python scripts/monitor.py --ws-url wss://eth-mainnet.g.alchemy.com/v2/KEY
    python scripts/monitor.py --all-contracts
    python scripts/monitor.py --no-pipeline
    python scripts/monitor.py --audit
    python scripts/monitor.py --min-eth 0.1

Environment variables (set in .env):
    MEMPOOL_WS_URL          WebSocket RPC URL (required if --ws-url not given)
    MEMPOOL_MIN_VALUE_ETH   Minimum value in ETH (default 0.0)
    MEMPOOL_PIPELINE        Set to "false" to disable deep analysis
    ETHERSCAN_API_KEY       Required for deep pipeline address analysis
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from detectors.mempool_monitor.listener import MempoolListener
from detectors.mempool_monitor.contract_cache import ContractAnalysisCache
from detectors.calldata_verifier.verifier import CalldataVerifier
from detectors.bytecode_analyzer.skanf_sensitive import (
    ERC20_TRANSFER,
    ERC20_APPROVE,
    ERC20_TRANSFER_FROM,
)


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

_RISK_COLOR = {
    "CRITICAL": red,
    "HIGH":     orange,
    "MEDIUM":   orange,
    "LOW":      green,
    "UNKNOWN":  dim,
}

_ERC20_NAMES = {
    ERC20_TRANSFER:      "transfer",
    ERC20_APPROVE:       "approve",
    ERC20_TRANSFER_FROM: "transferFrom",
}

log = logging.getLogger("calyx.monitor")


def _short(s: str, n: int = 12) -> str:
    return s[:n] + "..." + s[-4:] if len(s) > n + 4 else s


def _print_tx_header(tx: Dict[str, Any]) -> None:
    ts      = time.strftime("%H:%M:%S")
    to_addr = tx.get("to") or "(contract creation)"
    val_eth = int(tx.get("value") or "0x0", 16) / 1e18
    sel     = (tx.get("input") or "")[:10]
    fn_name = _ERC20_NAMES.get(sel.lstrip("0x"), sel or "?")
    print(
        f"\n{dim(ts)}  {bold('TX')} {_short(tx.get('hash', '?'), 16)}\n"
        f"         to={cyan(_short(to_addr))}  "
        f"value={val_eth:.4f}E  "
        f"fn={fn_name}"
    )


def _print_calldata_result(result: Dict[str, Any]) -> None:
    risk  = result.get("risk_level", "UNKNOWN")
    color = _RISK_COLOR.get(risk, dim)
    if result.get("match", True):
        print(f"  {green('OK')} Calldata OK")
    else:
        print(f"  {red('!!')} {bold('UI MANIPULATION DETECTED')}  risk={color(risk)}")
        for m in result.get("mismatches", []):
            field = m.get("field", "?").upper()
            shows = m.get("ui_shows", "?")
            real  = m.get("actually_is", "?")
            sev   = m.get("severity", "")
            print(f"      >> {field}: "
                  f"UI shows {orange(str(shows))} -> "
                  f"actually {red(str(real))}  [{sev}]")


def _print_pipeline_result(result: Dict[str, Any], address: str) -> None:
    risk      = result.get("risk_level", "UNKNOWN")
    score     = result.get("risk_score", 0.0)
    color     = _RISK_COLOR.get(risk, dim)
    types     = result.get("am_types_found", [])
    confirmed = result.get("confirmed_exploits", [])
    print(
        f"  {bold('Pipeline')} [{_short(address)}]  "
        f"risk={color(risk)}  score={score:.3f}  "
        f"findings={types or '[]'}"
    )
    if confirmed:
        print(f"  {red(bold('CONFIRMED EXPLOITS:'))} "
              f"{[c['type'] for c in confirmed]}")


class MempoolHandler:
    """Wires CalldataVerifier + ContractAnalysisCache and prints alerts."""

    def __init__(self, enable_pipeline: bool = True, audit: bool = False) -> None:
        self._verifier = CalldataVerifier()
        self._pipeline = None
        self._cache: ContractAnalysisCache | None = None
        if enable_pipeline:
            from analysis.bytecode_pipeline import BytecodePipeline
            self._pipeline = BytecodePipeline()
            self._cache    = ContractAnalysisCache(audit=audit)

    async def handle(self, tx: Dict[str, Any]) -> None:
        _print_tx_header(tx)
        calldata = tx.get("input") or tx.get("data") or "0x"
        selector = calldata[2:10] if len(calldata) >= 10 else ""
        known_fn = _ERC20_NAMES.get(selector)
        if known_fn:
            ui_display: Dict[str, str] = {
                "function": known_fn.split("(")[0],
                "to":       tx.get("to", ""),
                "amount":   "?",
            }
            cv_result = self._verifier.verify_transaction(ui_display, calldata)
        else:
            cv_result = {"match": True, "risk_level": "LOW", "mismatches": []}
        _print_calldata_result(cv_result)
        to_addr = tx.get("to")
        if self._cache is not None and to_addr:
            result = await self._cache.get_or_analyze(to_addr, self._pipeline)
            _print_pipeline_result(result, to_addr)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Calyx Real-Time Mempool Monitor")
    p.add_argument("--ws-url", default=os.getenv("MEMPOOL_WS_URL"),
                   help="WebSocket RPC URL (or set MEMPOOL_WS_URL in .env)")
    p.add_argument("--min-eth", type=float,
                   default=float(os.getenv("MEMPOOL_MIN_VALUE_ETH", "0")),
                   help="Minimum transaction value in ETH (default 0)")
    p.add_argument("--all-contracts", action="store_true",
                   help="Triage all contract calls, not just SKANF targets")
    p.add_argument("--no-pipeline", action="store_true",
                   default=(os.getenv("MEMPOOL_PIPELINE", "true").lower() == "false"),
                   help="Skip deep bytecode analysis (calldata-only mode)")
    p.add_argument("--audit", action="store_true",
                   help="Enable Stage 8 LLM audit on novel contracts")
    p.add_argument("--log-level", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(levelname)s %(name)s: %(message)s")
    if not args.ws_url:
        print(red("Error: --ws-url or MEMPOOL_WS_URL is required."))
        print(dim("  Get a free WebSocket URL at https://alchemy.com"))
        sys.exit(1)
    handler = MempoolHandler(enable_pipeline=not args.no_pipeline, audit=args.audit)
    ws_display = args.ws_url[:55] + "..." if len(args.ws_url) > 55 else args.ws_url
    print(bold("\n  Calyx Mempool Monitor"))
    print(f"  WS:       {dim(ws_display)}")
    print(f"  Mode:     {'broad (all contracts)' if args.all_contracts else 'focused (SKANF 50 DeFi targets)'}")
    print(f"  Pipeline: {'disabled' if args.no_pipeline else 'enabled (LRU cache, 1h TTL)'}")
    print(f"  Min ETH:  {args.min_eth}")
    print(f"  Audit:    {'enabled' if args.audit else 'disabled'}")
    print(dim("  Ctrl-C to stop\n"))
    listener = MempoolListener(
        ws_url=args.ws_url,
        on_tx=handler.handle,
        min_value_wei=int(args.min_eth * 1e18),
        broad_mode=args.all_contracts,
    )
    await listener.run()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print(dim("\n  Monitor stopped."))
