"""
data/collectors/defihacklabs_scraper.py

Scrapes ALL DeFiHackLabs POC Foundry test files from GitHub, extracts hex contract
addresses, filters to contracts-only via Etherscan, and writes exploit_addresses.csv
— ready for real_bytecode_collector.py to fetch bytecode from.

No manual address lookup needed. No hardcoded incident list.

Usage:
    cd /root/Calyx-dev && source venv/bin/activate
    # Requires ETHERSCAN_API_KEY in .env
    PYTHONPATH=. python data/collectors/defihacklabs_scraper.py

    # With GitHub token (5000 req/hr instead of 60):
    GITHUB_TOKEN=ghp_xxx PYTHONPATH=. python data/collectors/defihacklabs_scraper.py

    # Dry run — extract addresses but skip Etherscan verification:
    PYTHONPATH=. python data/collectors/defihacklabs_scraper.py --dry-run

    # Resume a previous run (skips files already in progress cache):
    PYTHONPATH=. python data/collectors/defihacklabs_scraper.py --resume

After this script:
    PYTHONPATH=. python data/collectors/real_bytecode_collector.py --merge-synthetic
    PYTHONPATH=. python3 -m models.gnn.train
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

_REPO_ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(_REPO_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(_REPO_ROOT / ".env")
except Exception:
    pass

# ── Config ────────────────────────────────────────────────────────────────────

CSV_OUT      = _REPO_ROOT / "data" / "collectors" / "exploit_addresses.csv"
PROGRESS_FILE = _REPO_ROOT / "data" / "collectors" / ".scraper_progress.json"

GITHUB_API  = "https://api.github.com"
DHL_OWNER   = "SunWeb3Sec"
DHL_REPO    = "DeFiHackLabs"
DHL_POC_DIR = "src/test"

ADDR_RE = re.compile(r"\b0x([0-9a-fA-F]{40})\b")

# Supported Etherscan networks (V2 API)
SUPPORTED_NETWORKS = {"ethereum", "bsc", "arbitrum", "optimism", "polygon"}

# Keywords that suggest a file targets a non-ethereum chain
BSC_HINTS     = {"bsc", "bnb", "binance", "pancake", "cake", "pcs"}
ARB_HINTS     = {"arbitrum", "arbi"}
OPT_HINTS     = {"optimism", "optim"}
POLYGON_HINTS = {"polygon", "matic"}

# Well-known benign protocol addresses — appear in POC files as "victim" targets
BENIGN_PROTOCOL_ADDRS: Set[str] = {
    # Uniswap
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
    "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",
    "0x1f98431c8ad98523631ae4a59f267346ea31f984",
    "0xe592427a0aece92de3edee1f18e0157c05861564",
    # Aave
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
    # Compound
    "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643",
    "0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5",
    # Curve
    "0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7",
    # Tokens
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
    # MakerDAO
    "0x35d1b3f3d7966a1dfe207aa4514c12a259a0492b",
    "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2",
    # Infrastructure
    "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",
    "0xba12222222228d8ba445958a75a0704d566bf2c8",
    "0x1111111254eeb25477b68fb85ed929f73a960582",
    # Zero / burn
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}


# ── GitHub helpers ────────────────────────────────────────────────────────────

def _gh_headers() -> Dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def get_all_poc_files() -> List[Dict]:
    """Fetch all .sol files from DeFiHackLabs src/test/ via GitHub Tree API."""
    url = f"{GITHUB_API}/repos/{DHL_OWNER}/{DHL_REPO}/git/trees/main?recursive=1"
    r = requests.get(url, headers=_gh_headers(), timeout=30)
    r.raise_for_status()
    tree = r.json().get("tree", [])
    files = [
        e for e in tree
        if e.get("type") == "blob"
        and e.get("path", "").startswith(DHL_POC_DIR)
        and e["path"].endswith(".sol")
    ]
    print(f"[GitHub] {len(files)} Solidity files found in {DHL_POC_DIR}/")
    return files


def fetch_raw(path: str) -> Optional[str]:
    """Fetch raw file content from raw.githubusercontent.com (no auth needed)."""
    url = f"https://raw.githubusercontent.com/{DHL_OWNER}/{DHL_REPO}/main/{path}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  [fetch] {path}: {e}")
        return None


# ── Network inference ─────────────────────────────────────────────────────────

def infer_network(filename: str, content: str) -> str:
    """
    Infer the most likely chain from filename + file content.
    Falls back to 'ethereum'.
    """
    text = (filename + " " + content[:2000]).lower()
    if any(h in text for h in ARB_HINTS):
        return "arbitrum"
    if any(h in text for h in OPT_HINTS):
        return "optimism"
    if any(h in text for h in POLYGON_HINTS):
        return "polygon"
    if any(h in text for h in BSC_HINTS):
        return "bsc"
    return "ethereum"


# ── Etherscan contract check ──────────────────────────────────────────────────

class KeyRotator:
    """Round-robin across multiple Etherscan API keys."""
    def __init__(self, keys: List[str]):
        self._keys = keys
        self._idx  = 0

    def next(self) -> str:
        key = self._keys[self._idx % len(self._keys)]
        self._idx += 1
        return key

    def __len__(self) -> int:
        return len(self._keys)


def is_contract(address: str, network: str, rotator: "KeyRotator") -> bool:
    from integrations.etherscan_client import EtherscanClient
    client = EtherscanClient(api_key=rotator.next(), network=network)
    result = client.get_bytecode(address)
    return result.get("is_contract", False)


# ── Progress cache ────────────────────────────────────────────────────────────

def load_progress() -> Dict:
    """Load scraper progress cache (which files have been processed)."""
    if PROGRESS_FILE.exists():
        try:
            return json.loads(PROGRESS_FILE.read_text())
        except Exception:
            pass
    return {"processed_files": [], "verified_addrs": {}}


def save_progress(progress: Dict) -> None:
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape ALL DeFiHackLabs POC files → exploit_addresses.csv"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Extract addresses but skip Etherscan contract verification")
    parser.add_argument("--resume", action="store_true",
                        help="Skip files already in progress cache")
    parser.add_argument("--max-files", type=int, default=None,
                        help="Limit to first N files (for testing)")
    parser.add_argument("--network", default=None,
                        help="Force a specific network instead of inferring")
    args = parser.parse_args()

    # Support comma-separated keys: ETHERSCAN_API_KEY=key1,key2,key3
    raw_keys = os.getenv("ETHERSCAN_API_KEY", "")
    api_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    if not api_keys and not args.dry_run:
        print("WARNING: No ETHERSCAN_API_KEY — switching to --dry-run")
        args.dry_run = True
    rotator = KeyRotator(api_keys if api_keys else [""])
    print(f"API keys loaded: {len(rotator)} key(s)")

    # Load existing CSV to avoid duplicates
    existing_addrs: Set[str] = set()
    existing_rows: List[Dict] = []
    if CSV_OUT.exists():
        with open(CSV_OUT, newline="") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip().lower()
                if addr and not addr.startswith("#"):
                    existing_addrs.add(addr)
                    existing_rows.append(row)
    print(f"Existing CSV: {len(existing_rows)} addresses already recorded")

    # Load progress cache
    progress = load_progress() if args.resume else {"processed_files": [], "verified_addrs": {}}
    processed_files: Set[str] = set(progress.get("processed_files", []))
    # verified_addrs: addr -> {"is_contract": bool, "network": str}
    verified_addrs: Dict[str, Dict] = progress.get("verified_addrs", {})

    # Fetch file list
    all_files = get_all_poc_files()
    if args.max_files:
        all_files = all_files[:args.max_files]

    # Collect all unique candidate addresses across all files
    # file_path -> (inferred_network, incident_label, [addresses])
    file_data: List[Tuple[str, str, str, List[str]]] = []

    print(f"\n[Phase 1] Fetching {len(all_files)} files and extracting addresses...")
    for i, entry in enumerate(all_files):
        path = entry["path"]
        filename = Path(path).stem

        content = fetch_raw(path)
        if content is None:
            processed_files.add(path)
            continue

        network = args.network or infer_network(filename, content)
        if network not in SUPPORTED_NETWORKS:
            network = "ethereum"

        # Extract addresses
        raw_addrs = ["0x" + a.lower() for a in ADDR_RE.findall(content)]
        candidates = [
            a for a in dict.fromkeys(raw_addrs)  # deduplicate, preserve order
            if a not in BENIGN_PROTOCOL_ADDRS
            and a not in existing_addrs
            and a.lower() not in [r.lower() for r in existing_addrs]
        ]

        # Use filename as incident label (strip date suffix patterns like _20230101)
        label = re.sub(r"_exp\d*$|_\d{8}$|_exp$", "", filename, flags=re.IGNORECASE)

        if candidates:
            file_data.append((path, network, label, candidates))

        processed_files.add(path)

        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(all_files)} files scanned, "
                  f"{sum(len(d[3]) for d in file_data)} candidates so far")
        time.sleep(0.1)  # gentle GitHub rate limiting

    # Flatten to unique addresses (an address may appear in multiple files)
    addr_to_meta: Dict[str, Tuple[str, str]] = {}  # addr -> (network, label)
    for path, network, label, candidates in file_data:
        for addr in candidates:
            if addr not in addr_to_meta:
                addr_to_meta[addr] = (network, label)

    print(f"\n[Phase 1] Complete: {len(addr_to_meta)} unique candidate addresses")

    # Phase 2: Verify each unique address via Etherscan
    print(f"\n[Phase 2] Verifying {len(addr_to_meta)} addresses via Etherscan "
          f"({'dry-run' if args.dry_run else 'live'})...")

    new_rows: List[Dict] = []
    n_contract = 0
    n_eoa = 0
    n_error = 0

    for j, (addr, (network, label)) in enumerate(addr_to_meta.items()):
        # Use cache if available
        if addr in verified_addrs:
            cached = verified_addrs[addr]
            if cached.get("is_contract"):
                new_rows.append({
                    "address":  addr,
                    "network":  cached.get("network", network),
                    "incident": label,
                    "category": "exploit",
                })
                n_contract += 1
            else:
                n_eoa += 1
            continue

        if args.dry_run:
            # Accept all candidates in dry-run
            new_rows.append({"address": addr, "network": network,
                             "incident": label, "category": "exploit"})
            verified_addrs[addr] = {"is_contract": True, "network": network}
            n_contract += 1
        else:
            # Scale delay down with more keys: 1 key=0.22s, 2 keys=0.11s, 4 keys=0.06s
            time.sleep(max(0.05, 0.22 / len(rotator)))
            try:
                ok = is_contract(addr, network, rotator)
                verified_addrs[addr] = {"is_contract": ok, "network": network}
                if ok:
                    new_rows.append({"address": addr, "network": network,
                                     "incident": label, "category": "exploit"})
                    n_contract += 1
                    print(f"  [{j+1}] CONTRACT {addr}  ({label}, {network})")
                else:
                    n_eoa += 1
            except Exception as e:
                n_error += 1
                print(f"  [{j+1}] ERROR    {addr}: {e}")

        # Save progress every 25 addresses
        if (j + 1) % 25 == 0:
            progress["processed_files"] = list(processed_files)
            progress["verified_addrs"] = verified_addrs
            save_progress(progress)
            print(f"  ... {j+1}/{len(addr_to_meta)} verified "
                  f"({n_contract} contracts, {n_eoa} EOAs, {n_error} errors)")

    # Final progress save
    progress["processed_files"] = list(processed_files)
    progress["verified_addrs"] = verified_addrs
    save_progress(progress)

    # Write merged CSV
    all_rows = existing_rows + new_rows
    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["address", "network", "incident", "category"])
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n[Done]")
    print(f"  New contracts found : {n_contract}")
    print(f"  EOAs skipped        : {n_eoa}")
    print(f"  Errors              : {n_error}")
    print(f"  Total in CSV        : {len(all_rows)}")
    print(f"  Written to          : {CSV_OUT}")
    print()
    print("Next steps:")
    print("  PYTHONPATH=. python data/collectors/real_bytecode_collector.py --merge-synthetic")
    print("  PYTHONPATH=. python3 -m models.gnn.train")


if __name__ == "__main__":
    main()
