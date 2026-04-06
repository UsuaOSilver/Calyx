"""
data/collectors/defillama_benign_collector.py

Fetches benign contract addresses from DeFiLlama's public API.
Protocols with TVL >= threshold on Ethereum are treated as benign contracts.
Automatically excludes any address already in the exploit CSVs.

Output: data/collectors/benign_contracts.csv
  Columns: address, network, category, incident, tvl

Usage:
    PYTHONPATH=. python3 data/collectors/defillama_benign_collector.py
    PYTHONPATH=. python3 data/collectors/defillama_benign_collector.py --tvl-min 5000000 --max-protocols 1000
"""

import csv
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Set

import requests
from requests.adapters import HTTPAdapter, Retry

_REPO_ROOT = Path(__file__).resolve().parents[2]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("calyx.defillama")

OUTPUT_CSV       = _REPO_ROOT / "data" / "collectors" / "benign_contracts.csv"
EXPLOIT_CSV      = _REPO_ROOT / "data" / "collectors" / "exploit_addresses.csv"
EXPLOIT_SCRAPED  = _REPO_ROOT / "data" / "collectors" / "exploit_addresses_scraped.csv"

TVL_MIN_DEFAULT    = 1_000_000   # $1 M
MAX_PROTOCOLS      = 500
DETAIL_ENRICH_TOP  = 150         # fetch protocol detail for top N by TVL
YIELDS_TVL_MIN     = 100_000     # $100 k floor for yield pool tokens


def _make_session() -> requests.Session:
    s = requests.Session()
    s.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1)))
    s.headers.update({"User-Agent": "Calyx-Research-Bot/0.1"})
    return s


SESSION = _make_session()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_exploit_addresses() -> Set[str]:
    """Return set of all known exploit addresses (lowercase) to exclude."""
    addrs: Set[str] = set()
    for path in [EXPLOIT_CSV, EXPLOIT_SCRAPED]:
        if not path.exists():
            continue
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip().lower()
                if addr:
                    addrs.add(addr)
    log.info(f"Loaded {len(addrs)} exploit addresses to exclude")
    return addrs


def _is_valid_eth_addr(addr: str) -> bool:
    return bool(addr) and len(addr) == 42 and addr.startswith("0x")


# ── DeFiLlama API calls ───────────────────────────────────────────────────────

def fetch_protocols() -> List[Dict]:
    log.info("Fetching protocol list from DeFiLlama...")
    r = SESSION.get("https://api.llama.fi/protocols", timeout=30)
    r.raise_for_status()
    protocols = r.json()
    log.info(f"DeFiLlama returned {len(protocols)} protocols")
    return protocols


def fetch_protocol_detail(slug: str) -> Dict:
    """Fetch full protocol detail — contains per-chain contract address lists."""
    try:
        r = SESSION.get(f"https://api.llama.fi/protocol/{slug}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def fetch_yield_pool_tokens(tvl_min: float = YIELDS_TVL_MIN) -> List[Dict]:
    """
    Fetch Ethereum yield pool underlying token addresses from DeFiLlama yields API.
    Returns list of {address, source_project, tvl} dicts.
    """
    log.info("Fetching DeFiLlama yield pools...")
    try:
        r = SESSION.get("https://yields.llama.fi/pools", timeout=30)
        r.raise_for_status()
        pools = r.json()["data"]
    except Exception as e:
        log.warning(f"Yield pools fetch failed: {e}")
        return []

    eth_pools = [
        p for p in pools
        if (p.get("chain") or "").lower() == "ethereum"
        and (p.get("tvlUsd") or 0) >= tvl_min
    ]
    log.info(f"{len(eth_pools)} Ethereum pools with TVL >= ${tvl_min:,.0f}")

    seen: Set[str] = set()
    results: List[Dict] = []
    for pool in eth_pools:
        for addr in (pool.get("underlyingTokens") or []):
            addr = addr.strip().lower()
            if (
                _is_valid_eth_addr(addr)
                and addr != "0x0000000000000000000000000000000000000000"
                and addr not in seen
            ):
                seen.add(addr)
                results.append({
                    "address": addr,
                    "project": pool.get("project", "unknown"),
                    "tvl":     pool.get("tvlUsd") or 0,
                })
    log.info(f"  → {len(results)} unique underlying token addresses")
    return results


def fetch_uniswap_token_list() -> List[str]:
    """Fetch Ethereum token addresses from the Uniswap default token list."""
    log.info("Fetching Uniswap default token list...")
    try:
        r = SESSION.get("https://tokens.uniswap.org", timeout=15)
        r.raise_for_status()
        tokens = r.json().get("tokens", [])
        addrs = [
            t["address"].lower()
            for t in tokens
            if t.get("chainId") == 1 and _is_valid_eth_addr(t.get("address", ""))
        ]
        log.info(f"  → {len(addrs)} Ethereum tokens from Uniswap list")
        return addrs
    except Exception as e:
        log.warning(f"Uniswap token list fetch failed: {e}")
        return []


def fetch_1inch_token_list() -> List[str]:
    """Fetch Ethereum token addresses from the 1inch token list."""
    log.info("Fetching 1inch Ethereum token list...")
    try:
        r = SESSION.get("https://tokens.1inch.io/v1.2/1", timeout=15)
        r.raise_for_status()
        tokens = r.json()
        addrs = [
            addr.lower()
            for addr in tokens.keys()
            if _is_valid_eth_addr(addr)
        ]
        log.info(f"  → {len(addrs)} Ethereum tokens from 1inch list")
        return addrs
    except Exception as e:
        log.warning(f"1inch token list fetch failed: {e}")
        return []


def fetch_sushiswap_token_list() -> List[str]:
    """Fetch Ethereum token addresses from the SushiSwap token list (GitHub raw)."""
    log.info("Fetching SushiSwap token list...")
    url = "https://raw.githubusercontent.com/sushiswap/list/master/lists/token-lists/default-token-list/tokens/ethereum.json"
    try:
        r = SESSION.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        # GitHub raw might return list directly or wrapped
        if isinstance(data, list):
            tokens = data
        else:
            tokens = data.get("tokens", [])
        addrs = [
            t["address"].lower()
            for t in tokens
            if _is_valid_eth_addr(t.get("address", ""))
        ]
        log.info(f"  → {len(addrs)} Ethereum tokens from SushiSwap list")
        return addrs
    except Exception as e:
        log.warning(f"SushiSwap token list fetch failed: {e}")
        return []


def fetch_coingecko_token_list() -> List[str]:
    """
    Fetch Ethereum token contract addresses from CoinGecko's coin list.
    Uses the free public endpoint (no API key required, rate-limited).
    """
    log.info("Fetching CoinGecko Ethereum token list...")
    try:
        r = SESSION.get(
            "https://api.coingecko.com/api/v3/coins/list?include_platform=true",
            timeout=30,
        )
        r.raise_for_status()
        coins = r.json()
        addrs = []
        for coin in coins:
            platforms = coin.get("platforms") or {}
            addr = (platforms.get("ethereum") or "").strip().lower()
            if _is_valid_eth_addr(addr):
                addrs.append(addr)
        log.info(f"  → {len(addrs)} Ethereum tokens from CoinGecko")
        return addrs
    except Exception as e:
        log.warning(f"CoinGecko token list fetch failed: {e}")
        return []


# ── Address extraction ────────────────────────────────────────────────────────

def _extract_from_summary(protocol: Dict) -> List[str]:
    """Pull the top-level `address` field from a protocol summary entry."""
    addr = (protocol.get("address") or "").strip().lower()
    if _is_valid_eth_addr(addr):
        return [addr]
    return []


def _extract_from_detail(detail: Dict) -> List[str]:
    """
    Pull addresses from a protocol detail response.
    DeFiLlama detail pages expose addresses in several places:
      - detail["address"]
      - detail["contractAddresses"]  (list of {address, chain} dicts or plain strings)
      - detail["chains_data"]["Ethereum"]["address"]
    """
    found: List[str] = []

    # Top-level address
    addr = (detail.get("address") or "").strip().lower()
    if _is_valid_eth_addr(addr):
        found.append(addr)

    # contractAddresses list
    for entry in (detail.get("contractAddresses") or []):
        if isinstance(entry, str):
            a = entry.strip().lower()
            if _is_valid_eth_addr(a):
                found.append(a)
        elif isinstance(entry, dict):
            # {address: "0x...", chain: "Ethereum"}
            if (entry.get("chain") or "").lower() in ("ethereum", "eth", ""):
                a = (entry.get("address") or "").strip().lower()
                if _is_valid_eth_addr(a):
                    found.append(a)

    # chains_data breakdown
    chains_data = detail.get("chains_data") or {}
    eth_data = chains_data.get("Ethereum") or chains_data.get("ethereum") or {}
    a = (eth_data.get("address") or "").strip().lower()
    if _is_valid_eth_addr(a):
        found.append(a)

    return found


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(tvl_min: float = TVL_MIN_DEFAULT, max_protocols: int = MAX_PROTOCOLS) -> List[Dict]:
    exploit_addrs = _load_exploit_addresses()
    protocols = fetch_protocols()

    # Filter: must include Ethereum and meet TVL floor
    eth_protocols = [
        p for p in protocols
        if "Ethereum" in (p.get("chains") or [])
        and (p.get("tvl") or 0) >= tvl_min
    ]
    log.info(f"{len(eth_protocols)} Ethereum protocols with TVL >= ${tvl_min:,.0f}")

    # Sort by TVL descending; take top N
    eth_protocols.sort(key=lambda p: p.get("tvl") or 0, reverse=True)
    eth_protocols = eth_protocols[:max_protocols]

    results: List[Dict] = []
    seen: Set[str] = set()

    def _add(addr: str, protocol: Dict) -> None:
        addr = addr.strip().lower()
        if not _is_valid_eth_addr(addr):
            return
        if addr in exploit_addrs or addr in seen:
            return
        seen.add(addr)
        category = (protocol.get("category") or "defi").lower().replace(" ", "-")
        results.append({
            "address":  addr,
            "network":  "ethereum",
            "category": f"benign-{category}",
            "incident": f"{protocol.get('name', 'unknown')} (DeFiLlama)",
            "tvl":      protocol.get("tvl") or 0,
        })

    # Pass 1: summary-level address field
    for p in eth_protocols:
        for addr in _extract_from_summary(p):
            _add(addr, p)

    log.info(f"Pass 1 (summary): {len(results)} addresses")

    # Pass 2: protocol detail pages for top N by TVL (rate-limited)
    log.info(f"Pass 2: fetching detail pages for top {DETAIL_ENRICH_TOP} protocols...")
    before = len(results)
    for p in eth_protocols[:DETAIL_ENRICH_TOP]:
        slug = p.get("slug") or p.get("name", "").lower().replace(" ", "-")
        if not slug:
            continue
        detail = fetch_protocol_detail(slug)
        for addr in _extract_from_detail(detail):
            _add(addr, p)
        time.sleep(0.25)   # polite rate limit

    log.info(f"Pass 2 added {len(results) - before} addresses. Total: {len(results)}")

    # Pass 3: DeFiLlama yields — underlying token addresses
    before = len(results)
    yield_tokens = fetch_yield_pool_tokens()
    for tok in yield_tokens:
        addr = tok["address"]
        if addr not in exploit_addrs and addr not in seen:
            seen.add(addr)
            results.append({
                "address":  addr,
                "network":  "ethereum",
                "category": "benign-token",
                "incident": f"{tok['project']} pool token (DeFiLlama yields)",
                "tvl":      tok["tvl"],
            })
    log.info(f"Pass 3 (yields) added {len(results) - before} addresses. Total: {len(results)}")

    # Pass 4: Uniswap default token list
    before = len(results)
    for addr in fetch_uniswap_token_list():
        if addr not in exploit_addrs and addr not in seen:
            seen.add(addr)
            results.append({
                "address":  addr,
                "network":  "ethereum",
                "category": "benign-token",
                "incident": "Uniswap token list",
                "tvl":      0,
            })
    log.info(f"Pass 4 (Uniswap list) added {len(results) - before} addresses. Total: {len(results)}")

    # Pass 5: 1inch token list
    before = len(results)
    for addr in fetch_1inch_token_list():
        if addr not in exploit_addrs and addr not in seen:
            seen.add(addr)
            results.append({
                "address":  addr,
                "network":  "ethereum",
                "category": "benign-token",
                "incident": "1inch token list",
                "tvl":      0,
            })
    log.info(f"Pass 5 (1inch list) added {len(results) - before} addresses. Total: {len(results)}")

    # Pass 6: SushiSwap token list
    before = len(results)
    for addr in fetch_sushiswap_token_list():
        if addr not in exploit_addrs and addr not in seen:
            seen.add(addr)
            results.append({
                "address":  addr,
                "network":  "ethereum",
                "category": "benign-token",
                "incident": "SushiSwap token list",
                "tvl":      0,
            })
    log.info(f"Pass 6 (SushiSwap list) added {len(results) - before} addresses. Total: {len(results)}")

    # Pass 7: CoinGecko token list (largest, no API key)
    before = len(results)
    for addr in fetch_coingecko_token_list():
        if addr not in exploit_addrs and addr not in seen:
            seen.add(addr)
            results.append({
                "address":  addr,
                "network":  "ethereum",
                "category": "benign-token",
                "incident": "CoinGecko token list",
                "tvl":      0,
            })
    log.info(f"Pass 7 (CoinGecko) added {len(results) - before} addresses. Total: {len(results)}")

    # Write / append to CSV
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    existing: Set[str] = set()
    if OUTPUT_CSV.exists():
        with open(OUTPUT_CSV, newline="") as f:
            for row in csv.DictReader(f):
                existing.add((row.get("address") or "").strip().lower())

    new_rows = [r for r in results if r["address"] not in existing]

    write_header = not OUTPUT_CSV.exists() or len(existing) == 0
    with open(OUTPUT_CSV, "a", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["address", "network", "category", "incident", "tvl"]
        )
        if write_header:
            writer.writeheader()
        writer.writerows(new_rows)

    log.info(f"Wrote {len(new_rows)} new benign addresses → {OUTPUT_CSV}")
    log.info(f"Total in file: {len(existing) + len(new_rows)}")
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Calyx DeFiLlama benign contract collector")
    parser.add_argument("--tvl-min",       type=float, default=TVL_MIN_DEFAULT,
                        help="Minimum protocol TVL in USD (default: $1M)")
    parser.add_argument("--max-protocols", type=int,   default=MAX_PROTOCOLS,
                        help="Max number of protocols to process (default: 500)")
    args = parser.parse_args()

    rows = run(tvl_min=args.tvl_min, max_protocols=args.max_protocols)
    print(f"\nDone. {len(rows)} benign addresses collected.")
    print(f"Output: {OUTPUT_CSV}")
    print("\nNext step:")
    print("  PYTHONPATH=. python3 data/collectors/real_bytecode_collector.py --merge-synthetic")
