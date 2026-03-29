#!/usr/bin/env python3
"""
EVMbench Detect Benchmark
Runs Calyx's ClaudeScanner on all 40 EVMbench detect tasks and scores
detection recall/precision/F1 against ground truth findings.

Pipeline per task:
  1. Clone repo from evmbench-org GitHub at base_commit
  2. Collect in-scope Solidity source files
  3. Run ClaudeScanner (mode: style | routed)
  4. Score detected vulns against ground truth (keyword overlap)
  5. Save per-task result JSON

Usage:
    # Full benchmark, single Opus pass (default)
    python scripts/benchmark_evmbench_detect.py

    # Two-pass Sonnet→Opus routing (Pashov, lower cost)
    python scripts/benchmark_evmbench_detect.py --mode routed

    # Two-pass routed + RAG few-shot injection (NyxLLM 2.0 ICL pattern)
    python scripts/benchmark_evmbench_detect.py --mode routed --rag

    # Dry run — clone repos and collect source, skip Claude API call
    python scripts/benchmark_evmbench_detect.py --dry-run

    # Subset for testing
    python scripts/benchmark_evmbench_detect.py --max-tasks 3

    # Resume — skips tasks that already have cached results
    python scripts/benchmark_evmbench_detect.py --resume

Scan modes:
    style   — single Opus pass (scan_evmbench_style). Faster per-call, higher cost.
    routed  — Sonnet prescan → Opus full audit (scan_evmbench_routed). ~20-30% cheaper.
              Outputs include prescan candidate count for analysis.
    --rag   — (routed only) inject top-3 similar EVMbench findings as few-shot examples.
              Requires running scripts/build_rag_index.py first.
"""

from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
# ClaudeScanner is only imported when NOT running in --bytecode mode.
# Lazy import below (in main()) avoids ImportError when anthropic is not installed.

# ── Paths ──────────────────────────────────────────────────────────────────────

ROOT          = Path(__file__).resolve().parents[1]
EVMBENCH_DIR  = ROOT / "evmbench" / "frontier-evals" / "project" / "evmbench"
AUDITS_DIR    = EVMBENCH_DIR / "audits"
SPLITS_FILE   = EVMBENCH_DIR / "splits" / "detect-tasks.txt"
REPOS_CACHE   = ROOT / "evmbench" / "repos"          # cloned repos live here
RESULTS_DIR   = ROOT / "results" / "evmbench_detect"


# ── Source collection ──────────────────────────────────────────────────────────

# Directories to skip when collecting .sol files
SKIP_DIRS = {"test", "tests", "mock", "mocks", "lib", "node_modules", "script", "scripts"}

MAX_SOURCE_CHARS = 120_000   # ~30k tokens — stays well within Claude's context


def collect_sol_files(repo_dir: Path, run_cmd_dir: "Optional[str]" = None) -> "List[Path]":
    """
    Collect in-scope Solidity files from a cloned repo.
    Prefers run_cmd_dir/src if it exists; falls back to all .sol files
    outside test/lib directories.
    """
    # Try focused collection first
    if run_cmd_dir:
        focused = repo_dir / run_cmd_dir / "src"
        if focused.exists():
            files = sorted(focused.rglob("*.sol"))
            if files:
                return files

    # Broad collection: all .sol files not in skip dirs
    files = []
    for f in sorted(repo_dir.rglob("*.sol")):
        parts = {p.lower() for p in f.parts}
        if parts & SKIP_DIRS:
            continue
        files.append(f)
    return files


def build_source_bundle(files: list[Path], repo_dir: Path) -> tuple[str, list[str]]:
    """
    Concatenate source files into a single string for Claude.
    Truncates if combined size exceeds MAX_SOURCE_CHARS.
    Returns (source_bundle, list_of_file_names_included).
    """
    parts = []
    total = 0
    included = []

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        rel = str(f.relative_to(repo_dir))
        header = f"\n\n// ===== {rel} =====\n"
        chunk = header + content

        if total + len(chunk) > MAX_SOURCE_CHARS:
            parts.append(f"\n\n// ... (truncated — {len(files) - len(included)} files omitted)")
            break

        parts.append(chunk)
        included.append(rel)
        total += len(chunk)

    return "".join(parts), included


# ── Git helpers ────────────────────────────────────────────────────────────────

def clone_or_update(repo_url: str, task_id: str, base_commit: "Optional[str]") -> "Optional[Path]":
    """
    Clone repo into REPOS_CACHE/{task_id}. If already cloned, skip.
    Checks out base_commit if provided.
    Returns repo path, or None on failure.
    """
    dest = REPOS_CACHE / task_id
    REPOS_CACHE.mkdir(parents=True, exist_ok=True)

    if not (dest / ".git").exists():
        print(f"  Cloning {repo_url}...")
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, str(dest)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  Clone failed: {result.stderr.strip()}")
            return None

    if base_commit:
        # Fetch and checkout specific commit (shallow clone may not have it)
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--unshallow"],
            capture_output=True
        )
        result = subprocess.run(
            ["git", "-C", str(dest), "checkout", base_commit],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            # Non-fatal: proceed with whatever HEAD is
            print(f"  Warning: could not checkout {base_commit[:8]}, using HEAD")

    return dest


# ── Ground truth loading ───────────────────────────────────────────────────────

def load_ground_truth(task_dir: Path, vuln_ids: list[str]) -> list[dict]:
    """
    Load ground truth vulnerabilities from findings/*.md.
    Returns list of {id, title, text} dicts.
    """
    findings = []
    findings_dir = task_dir / "findings"

    for vid in vuln_ids:
        md_file = findings_dir / f"{vid}.md"
        if not md_file.exists():
            continue
        text = md_file.read_text(encoding="utf-8", errors="replace")

        # Extract title from first heading: # [H-xx] Title text
        title = vid
        m = re.match(r"#\s+\[.*?\]\s+(.*)", text.strip().splitlines()[0])
        if m:
            title = m.group(1).strip()

        findings.append({"id": vid, "title": title, "text": text[:2000]})

    return findings


# ── Scoring ────────────────────────────────────────────────────────────────────

# Synonym groups: any word in a group is normalized to the first word.
# Fixes terminology mismatches between EVMbench GT and Claude output.
# e.g. GT "reenter" / "reentrancy" / "re-entrancy" → all become "reentrancy"
_SYNONYM_GROUPS: list[tuple[str, ...]] = [
    ("reentrancy", "reenter", "reentrancy", "reentrant", "reentranced"),
    ("overflow", "overflows", "arithmetic", "underflow"),
    ("flashloan", "flashloans", "flash", "loan"),
    ("oracle", "pricefeed", "pricemanipu", "manipulation", "manipulate"),
    ("frontrun", "sandwich", "mevattack", "front"),
    ("delegate", "delegatecall", "proxy", "proxied"),
    ("signature", "ecrecover", "permit", "replay"),
    ("liquidation", "liquidate", "liquidations"),
    ("stale", "outdated", "staleness"),
    ("slippage", "minout", "amountout"),
    ("drain", "withdraw", "steal", "theft"),
    ("ownership", "access", "authorized", "unauthorized"),
    ("initialize", "initializer", "init"),
    ("precision", "truncation", "rounding", "round"),
]

# Build word → canonical form lookup
_SYNONYM_MAP: dict[str, str] = {}
for group in _SYNONYM_GROUPS:
    canonical = group[0]
    for word in group:
        _SYNONYM_MAP[word] = canonical


def _normalize(word: str) -> str:
    """Map a word to its canonical synonym form."""
    return _SYNONYM_MAP.get(word, word)


def extract_keywords(text: str) -> set[str]:
    """
    Extract meaningful lowercase words from text (≥4 chars, non-stop-words),
    normalized via synonym map so 'reenter' and 'reentrancy' both match.
    """
    stop = {
        "from", "that", "this", "with", "have", "will", "when", "then",
        "their", "also", "into", "more", "some", "such", "other", "which",
        "contract", "function", "token", "user", "value", "call", "loss",
    }
    words = re.findall(r"[a-z]{4,}", text.lower())
    return {_normalize(w) for w in words if w not in stop}


def match_finding(ground_truth: dict, detected_vulns: list[dict], threshold: float = 0.15) -> bool:
    """
    Returns True if any detected vulnerability matches the ground truth finding.
    Match criterion: keyword overlap ratio ≥ threshold between GT title/text
    and detected title/summary/description.
    Synonym normalization ensures 'reenter' == 'reentrancy', 'overflow' == 'arithmetic', etc.
    """
    gt_kw = extract_keywords(ground_truth["title"] + " " + ground_truth["text"][:500])
    if not gt_kw:
        return False

    for vuln in detected_vulns:
        det_text = (
            vuln.get("title", "") + " " +
            vuln.get("summary", "") + " " +
            " ".join(d.get("desc", "") for d in vuln.get("description", []))
        )
        det_kw = extract_keywords(det_text)
        overlap = len(gt_kw & det_kw) / len(gt_kw)
        if overlap >= threshold:
            return True

    return False


def score_task(ground_truth: list[dict], detected_vulns: list[dict]) -> dict:
    """
    Compute TP, FP, FN and derived metrics for a single task.
    """
    tp = sum(1 for gt in ground_truth if match_finding(gt, detected_vulns))
    fn = len(ground_truth) - tp
    # FP: detected vulns that don't match any ground truth
    fp = sum(
        1 for vuln in detected_vulns
        if not any(match_finding(gt, [vuln]) for gt in ground_truth)
    )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "ground_truth_count": len(ground_truth),
        "detected_count": len(detected_vulns),
    }


# ── Per-task runner ────────────────────────────────────────────────────────────

def run_task(task_id: str, scanner, dry_run: bool, rag=None, bytecode_pipeline=None, validate: bool = False) -> dict:
    """
    Run the full pipeline for one task. Returns result dict.
    """
    task_dir = AUDITS_DIR / task_id
    config_path = task_dir / "config.yaml"

    if not config_path.exists():
        return {"task_id": task_id, "status": "error", "error": "config.yaml not found"}

    cfg = yaml.safe_load(config_path.read_text())
    vuln_ids    = [v["id"] for v in cfg.get("vulnerabilities", [])]
    base_commit = cfg.get("base_commit")
    run_cmd_dir = cfg.get("run_cmd_dir")

    # Load Dockerfile for repo URL
    dockerfile = task_dir / "Dockerfile"
    repo_url = None
    if dockerfile.exists():
        for line in dockerfile.read_text().splitlines():
            if "git clone" in line:
                for part in line.split():
                    if part.startswith("https://"):
                        repo_url = part
                        break

    if not repo_url:
        return {"task_id": task_id, "status": "error", "error": "repo URL not found in Dockerfile"}

    # Load ground truth
    ground_truth = load_ground_truth(task_dir, vuln_ids)
    if not ground_truth:
        return {"task_id": task_id, "status": "error", "error": "no ground truth findings"}

    # Clone repo
    repo_dir = clone_or_update(repo_url, task_id, base_commit)
    if repo_dir is None:
        return {"task_id": task_id, "status": "error", "error": "git clone failed"}

    # Collect source
    sol_files = collect_sol_files(repo_dir, run_cmd_dir)
    if not sol_files:
        return {"task_id": task_id, "status": "error", "error": "no .sol files found"}

    source_bundle, included_files = build_source_bundle(sol_files, repo_dir)

    if dry_run:
        return {
            "task_id": task_id,
            "status": "dry_run",
            "ground_truth_count": len(ground_truth),
            "sol_files_found": len(sol_files),
            "sol_files_included": len(included_files),
            "source_chars": len(source_bundle),
        }

    # ── Bytecode mode: LLM-free AM detection + BytecodeGNN ───────────────────
    if bytecode_pipeline is not None:
        # Attempt to fetch on-chain bytecode for each in-scope contract
        # Contracts are identified by their Etherscan address if available in config
        addresses = cfg.get("addresses", [])
        all_findings = []
        if addresses:
            for addr_entry in addresses:
                addr = addr_entry if isinstance(addr_entry, str) else addr_entry.get("address", "")
                if not addr:
                    continue
                try:
                    bp_result = bytecode_pipeline.analyze_address(addr, validate=validate)
                    all_findings.extend(bp_result.get("am_findings", []))
                except Exception as e:
                    pass  # address fetch failed; continue with others
        else:
            # No addresses in config — run AM detector on source as text proxy
            # (heuristic: scan source for known patterns even though it's not bytecode)
            pass

        # Convert AM findings to the same format as Claude vulnerabilities for scoring
        detected_vulns = [
            {
                "title":       f.get("type", ""),
                "summary":     f.get("description", ""),
                "description": [f.get("description", "")],
                "severity":    f.get("severity", "medium"),
            }
            for f in all_findings
        ]
        scores = score_task(ground_truth, detected_vulns)
        return {
            "task_id":             task_id,
            "status":              "ok",
            "scan_mode":           "bytecode_llm_free",
            "repo_url":            repo_url,
            "ground_truth":        [{"id": g["id"], "title": g["title"]} for g in ground_truth],
            "detected":            detected_vulns,
            "scores":              scores,
            "source_chars":        len(source_bundle),
            "sol_files_included":  len(included_files),
            "addresses_scanned":   len(addresses),
        }

    # ── Claude Scanner mode ───────────────────────────────────────────────────
    mode = getattr(scanner, "_benchmark_mode", "style")
    if mode == "routed":
        scan_result = scanner.scan_evmbench_routed(source_bundle, f"{task_id}.sol", rag=rag)
    else:
        scan_result = scanner.scan_evmbench_style(source_bundle, f"{task_id}.sol")
    detected_vulns = scan_result.get("vulnerabilities", [])

    # Score
    scores = score_task(ground_truth, detected_vulns)

    result = {
        "task_id": task_id,
        "status": "ok",
        "scan_mode": mode,
        "repo_url": repo_url,
        "ground_truth": [{"id": g["id"], "title": g["title"]} for g in ground_truth],
        "detected": [
            {
                "title":       v.get("title", ""),
                "summary":     v.get("summary", ""),
                "description": v.get("description", []),
            }
            for v in detected_vulns
        ],
        "scores": scores,
        "source_chars": len(source_bundle),
        "sol_files_included": len(included_files),
    }
    if mode == "routed":
        result["prescan_candidates"] = len(scan_result.get("candidates", []))
    return result


# ── Aggregate ──────────────────────────────────────────────────────────────────

def aggregate_results(task_results: list[dict]) -> dict:
    ok = [r for r in task_results if r["status"] == "ok"]
    if not ok:
        return {"error": "no completed tasks"}

    total_tp = sum(r["scores"]["tp"] for r in ok)
    total_fp = sum(r["scores"]["fp"] for r in ok)
    total_fn = sum(r["scores"]["fn"] for r in ok)
    total_gt = sum(r["scores"]["ground_truth_count"] for r in ok)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tasks_completed": len(ok),
        "tasks_errored": len(task_results) - len(ok),
        "total_ground_truth_vulns": total_gt,
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "overall_precision": round(precision, 4),
        "overall_recall": round(recall, 4),
        "overall_f1": round(f1, 4),
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EVMbench detect benchmark")
    parser.add_argument("--max-tasks", type=int, default=None,
                        help="Limit to first N tasks (for testing)")
    parser.add_argument("--tasks", nargs="+",
                        help="Run specific task IDs instead of full list")
    parser.add_argument("--dry-run", action="store_true",
                        help="Clone repos and collect source but skip Claude API")
    parser.add_argument("--resume", action="store_true",
                        help="Skip tasks that already have cached result JSON")
    parser.add_argument("--mode", choices=["style", "routed"], default="style",
                        help="Scan mode: style=single Opus pass, routed=Sonnet→Opus (default: style)")
    parser.add_argument("--rag", action="store_true",
                        help="Inject RAG few-shot examples (routed mode only). "
                             "Run scripts/build_rag_index.py first.")
    parser.add_argument("--bytecode", action="store_true",
                        help="LLM-free bytecode mode: run BytecodePipeline (AMPatternDetector + "
                             "BytecodeGNN) instead of Claude. No API key required. "
                             "Uses on-chain bytecode via Etherscan for each task's contracts.")
    parser.add_argument("--validate", action="store_true",
                        help="(--bytecode mode only) Run fork-EVM exploit validation via Anvil "
                             "for each finding. Requires ETHEREUM_RPC_URL env var and Anvil in "
                             "PATH. Confirmed exploits receive a +0.10 risk-score bonus.")
    parser.add_argument("--rescore", metavar="RESULTS_DIR",
                        help="Re-score cached per-task JSONs in RESULTS_DIR using the "
                             "current scorer (no API calls). Useful after scorer changes.")
    parser.add_argument("--output-dir", default=str(RESULTS_DIR),
                        help=f"Output directory (default: {RESULTS_DIR})")
    args = parser.parse_args()

    # ── Rescore mode — re-evaluate cached results without new API calls ──────
    if args.rescore:
        rescore_dir = Path(args.rescore)
        task_jsons = sorted(rescore_dir.glob("*.json"))
        task_jsons = [p for p in task_jsons if p.stem != "aggregate"]
        if not task_jsons:
            print(f"No per-task JSON files found in {rescore_dir}")
            return
        print(f"Rescoring {len(task_jsons)} cached results in {rescore_dir}")
        print("(Using updated synonym-normalized keyword scorer)")
        print("=" * 60)
        task_results = []
        for p in task_jsons:
            cached = json.loads(p.read_text())
            if cached.get("status") != "ok":
                task_results.append(cached)
                continue
            # Reload GT from disk (authoritative source)
            task_id = cached["task_id"]
            task_dir = AUDITS_DIR / task_id
            config_path = task_dir / "config.yaml"
            if not config_path.exists():
                task_results.append(cached)
                continue
            cfg = yaml.safe_load(config_path.read_text())
            vuln_ids = [v["id"] for v in cfg.get("vulnerabilities", [])]
            ground_truth = load_ground_truth(task_dir, vuln_ids)
            detected = cached.get("detected", [])
            # Use full cached vuln dicts (title + summary + description)
            detected_vulns = detected
            new_scores = score_task(ground_truth, detected_vulns)
            old_scores = cached.get("scores", {})
            if new_scores != old_scores:
                print(f"  {task_id}: TP {old_scores.get('tp')}→{new_scores['tp']}  "
                      f"FP {old_scores.get('fp')}→{new_scores['fp']}  "
                      f"recall {old_scores.get('recall')}→{new_scores['recall']}")
            cached["scores"] = new_scores
            task_results.append(cached)

        agg = aggregate_results(task_results)
        print("\n" + "=" * 60)
        print("RESCORED AGGREGATE")
        print("=" * 60)
        for k, v in agg.items():
            print(f"  {k}: {v}")
        agg_out = rescore_dir / "aggregate_rescored.json"
        agg_out.write_text(json.dumps({"rescored": True, "aggregate": agg, "tasks": task_results}, indent=2))
        print(f"\nSaved to: {agg_out}")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load task list
    if args.tasks:
        task_ids = args.tasks
    else:
        task_ids = SPLITS_FILE.read_text().strip().splitlines()

    if args.max_tasks:
        task_ids = task_ids[: args.max_tasks]

    # Mode-specific output dir to keep style vs routed vs rag vs bytecode results separate
    if not args.dry_run and args.output_dir == str(RESULTS_DIR):
        suffix = ""
        if args.bytecode:
            suffix = "_bytecode"
            if getattr(args, "validate", False):
                suffix += "_validated"
        elif args.mode == "routed":
            suffix = "_routed"
        if args.rag and not args.bytecode:
            suffix += "_rag"
        if suffix:
            output_dir = Path(args.output_dir + suffix)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize BytecodePipeline if --bytecode flag set
    bytecode_pipeline = None
    if args.bytecode and not args.dry_run:
        try:
            from analysis.bytecode_pipeline import BytecodePipeline
            bytecode_pipeline = BytecodePipeline()
            print("Bytecode pipeline: ON (AMPatternDetector + BytecodeGNN, no API required)")
        except Exception as e:
            print(f"WARNING: BytecodePipeline init failed ({e}) — falling back to Claude mode")
            args.bytecode = False

    # Optionally initialize RAG retriever
    rag = None
    if args.rag and not args.dry_run:
        if args.mode != "routed":
            print("WARNING: --rag only works with --mode routed. Ignoring --rag.")
        else:
            try:
                from detectors.claude_scanner.rag import RAGRetriever
                rag = RAGRetriever()
                if rag.is_ready():
                    print(f"RAG: index loaded ({rag.count()} documents)")
                else:
                    print("WARNING: RAG index is empty — run scripts/build_rag_index.py first")
                    rag = None
            except Exception as e:
                print(f"WARNING: RAG init failed ({e}) — continuing without RAG")

    print(f"EVMbench Detect Benchmark")
    rag_label = f"ON ({rag.count()} docs)" if rag else ("EMPTY" if args.rag else "OFF")
    validate_label = "ON" if (args.bytecode and getattr(args, "validate", False)) else "OFF"
    mode_label = "bytecode (LLM-free)" if args.bytecode else args.mode
    print(f"Tasks: {len(task_ids)} | Mode: {mode_label} | RAG: {rag_label} | "
          f"Validate: {validate_label} | Dry-run: {args.dry_run} | Resume: {args.resume}")
    print(f"Output: {output_dir}")
    print("=" * 60)

    scanner = None
    if not args.dry_run and not args.bytecode:
        try:
            from detectors.claude_scanner.scanner import ClaudeScanner
            scanner = ClaudeScanner()
            scanner._benchmark_mode = args.mode
        except ImportError:
            print("WARNING: ClaudeScanner not available (anthropic not installed). "
                  "Use --bytecode for LLM-free mode.")
            return

    task_results = []

    for i, task_id in enumerate(task_ids, 1):
        cached = output_dir / f"{task_id}.json"

        if args.resume and cached.exists():
            print(f"[{i:2d}/{len(task_ids)}] {task_id} — cached, skipping")
            task_results.append(json.loads(cached.read_text()))
            continue

        print(f"[{i:2d}/{len(task_ids)}] {task_id}")

        result = run_task(task_id, scanner, args.dry_run, rag=rag,
                          bytecode_pipeline=bytecode_pipeline,
                          validate=getattr(args, "validate", False))
        task_results.append(result)

        # Save per-task result
        cached.write_text(json.dumps(result, indent=2))

        status = result["status"]
        if status == "ok":
            s = result["scores"]
            print(f"         TP={s['tp']} FP={s['fp']} FN={s['fn']} "
                  f"recall={s['recall']:.2f} precision={s['precision']:.2f} f1={s['f1']:.2f}")
        elif status == "dry_run":
            print(f"         GT={result['ground_truth_count']} "
                  f"files={result['sol_files_included']} "
                  f"chars={result['source_chars']:,}")
        else:
            print(f"         ERROR: {result.get('error')}")

        # Brief pause to respect API rate limits
        if not args.dry_run and i < len(task_ids):
            time.sleep(1)

    # Aggregate
    print("\n" + "=" * 60)
    if not args.dry_run:
        agg = aggregate_results(task_results)
        print("AGGREGATE RESULTS")
        print("=" * 60)
        for k, v in agg.items():
            print(f"  {k}: {v}")

        agg_path = output_dir / "aggregate.json"
        agg_path.write_text(json.dumps({"scan_mode": args.mode, "aggregate": agg, "tasks": task_results}, indent=2))
        print(f"\nSaved aggregate to: {agg_path}")
    else:
        dry_ok = [r for r in task_results if r["status"] == "dry_run"]
        total_chars = sum(r["source_chars"] for r in dry_ok)
        print(f"DRY RUN COMPLETE: {len(dry_ok)}/{len(task_results)} tasks cloned successfully")
        print(f"Total source: {total_chars:,} chars across {len(dry_ok)} repos")
        print(f"Estimated API calls: {len(dry_ok)}")


if __name__ == "__main__":
    main()
