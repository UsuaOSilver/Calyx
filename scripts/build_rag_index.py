"""
scripts/build_rag_index.py

One-time script to build the RAG index from EVMbench ground-truth findings.

Scans evmbench/frontier-evals/project/evmbench/audits/ for H-*.md files,
embeds them with sentence-transformers all-MiniLM-L6-v2, and stores them in
a local ChromaDB collection at data/rag_index/evmbench/.

Usage:
    cd calyx && source venv/bin/activate
    python scripts/build_rag_index.py

    # Custom paths:
    python scripts/build_rag_index.py --audits-dir /path/to/audits --index-dir data/rag_index/evmbench

    # Check existing index:
    python scripts/build_rag_index.py --check
"""

import argparse
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(_REPO_ROOT / ".env")
except ImportError:
    pass

_DEFAULT_AUDITS = _REPO_ROOT / "evmbench" / "frontier-evals" / "project" / "evmbench" / "audits"
_DEFAULT_INDEX  = _REPO_ROOT / "data" / "rag_index" / "evmbench"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build RAG index from EVMbench findings")
    parser.add_argument("--audits-dir", default=str(_DEFAULT_AUDITS),
                        help="Path to EVMbench audits/ directory")
    parser.add_argument("--index-dir", default=str(_DEFAULT_INDEX),
                        help="Path to store ChromaDB index")
    parser.add_argument("--check", action="store_true",
                        help="Check existing index and exit")
    args = parser.parse_args()

    from detectors.claude_scanner.rag import RAGRetriever

    rag = RAGRetriever(index_path=args.index_dir)

    if args.check:
        count = rag.count()
        counts = rag.count_by_type()
        print(f"Index at {args.index_dir}")
        print(f"Documents: {count}  "
              f"(ground_truth={counts['ground_truth']}  "
              f"gold_audit={counts['gold_audit']}  "
              f"negatives={counts['negative']})")
        if count > 0:
            print("Status: READY")
            examples = rag.retrieve("reentrancy vulnerability in withdraw", k=2)
            print(f"\nSample retrieval ('reentrancy vulnerability in withdraw'):")
            for ex in examples:
                print(f"  [{ex['similarity']:.3f}] {ex['task_id']}/{ex['vuln_id']} "
                      f"({ex.get('doc_type','?')}): {ex['title'][:55]}")
        else:
            print("Status: EMPTY — run without --check to build")
        return

    audits_dir = Path(args.audits_dir)
    if not audits_dir.exists():
        print(f"ERROR: audits-dir not found: {audits_dir}")
        print("Make sure EVMbench is cloned at evmbench/frontier-evals/")
        sys.exit(1)

    print(f"Building RAG index from: {audits_dir}")
    print(f"Index destination:       {args.index_dir}")
    print()

    t0 = time.time()
    stats = rag.build_index(findings_root=audits_dir)
    elapsed = time.time() - t0

    by_type = stats.get("by_type", {})
    print(f"Results:")
    print(f"  Total found:         {stats['total_found']}")
    print(f"  Newly indexed:       {stats['indexed']}")
    print(f"    ground_truth:      {by_type.get('ground_truth', 0)}")
    print(f"    gold_audit chunks: {by_type.get('gold_audit', 0)}")
    print(f"    negatives:         {by_type.get('negative', 0)}")
    print(f"  Skipped (existing):  {stats['skipped']}")
    print(f"  Errors:              {len(stats['errors'])}")
    print(f"  Elapsed:             {elapsed:.1f}s")

    if stats["errors"]:
        print("\nErrors:")
        for err in stats["errors"][:5]:
            print(f"  {err['file']}: {err['error']}")

    total = rag.count()
    counts = rag.count_by_type()
    print(f"\nTotal documents in index: {total}")
    print(f"  ground_truth: {counts['ground_truth']}  |  "
          f"gold_audit: {counts['gold_audit']}  |  "
          f"negatives: {counts['negative']}")

    if total > 0:
        print("\nSample retrieval ('reentrancy vulnerability in withdraw'):")
        examples = rag.retrieve("reentrancy vulnerability in withdraw", k=3)
        for ex in examples:
            print(f"  [{ex['similarity']:.3f}] {ex['task_id']}/{ex['vuln_id']} "
                  f"({ex.get('doc_type','?')}): {ex['title'][:55]}")
        print("\nSample negatives ('reentrancy false positive'):")
        negs = rag.retrieve_negatives("reentrancy false positive", k=2)
        for ex in negs:
            print(f"  [{ex['similarity']:.3f}] {ex['task_id']}/{ex['vuln_id']} "
                  f"(negative): {ex['title'][:55]}")
        print("\nIndex is READY for use with --rag flag in benchmark.")
    else:
        print("\nWARNING: Index appears empty after build.")


if __name__ == "__main__":
    main()
