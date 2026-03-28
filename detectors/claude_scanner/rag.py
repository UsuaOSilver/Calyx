"""
detectors/claude_scanner/rag.py

RAG knowledge base for ClaudeScanner using ChromaDB + sentence-transformers.

Indexes three source types from EVMbench:
  1. ground_truth  — individual H-*.md findings (authoritative, per-vulnerability)
  2. gold_audit    — gold_audit.md files chunked by finding (complete write-ups with
                     attacker steps, PoC, and mitigations)
  3. negative      — incorrect/high/ and incorrect/low/ distractor findings (plausible
                     but wrong — used to suppress false positives)

At scan time, retrieve() returns positive examples (ground_truth + gold_audit) as
few-shot context for the audit prompt.  retrieve_negatives() returns distractor
examples so the scanner can explicitly warn itself against similar false calls.

Based on:
  - NyxLLM 2.0 (Ruhr, 2025): ICL pattern for vulnerability detection
  - RAG-LLM (SF State, 2024): vector store for contract analysis

Usage:
    from detectors.claude_scanner.rag import RAGRetriever

    rag = RAGRetriever()

    # Build index once (or call from scripts/build_rag_index.py)
    stats = rag.build_index(findings_root="evmbench/frontier-evals/project/evmbench/audits")

    # Retrieve positive examples at scan time
    examples = rag.retrieve("reentrancy vulnerability in withdraw function", k=3)
    # [{"title": "Reentrancy in ...", "text": "...", "task_id": "T001",
    #   "doc_type": "gold_audit", "similarity": 0.87}]

    # Retrieve negative examples (false-positive distractors)
    negatives = rag.retrieve_negatives("reentrancy vulnerability in withdraw function", k=2)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
_DEFAULT_INDEX = (
    Path(__file__).resolve().parents[2] / "data" / "rag_index" / "evmbench"
)

# Body truncation limit — keeps embeddings fast without losing the key details.
_BODY_LIMIT = 1200


class RAGRetriever:
    """
    Local ChromaDB-backed retriever for EVMbench vulnerability findings.

    Lifecycle:
      1. build_index()      — one-time scan of audits/ → embed → store
      2. retrieve()         — embed query → cosine search → top-k positive examples
      3. retrieve_negatives()— embed query → cosine search → top-k distractor examples

    Document types stored in metadata["doc_type"]:
      "ground_truth" — individual H-*.md files
      "gold_audit"   — chunks from gold_audit.md (one chunk per finding)
      "negative"     — incorrect/high/ and incorrect/low/ distractors

    Thread-safety: ChromaDB client is not thread-safe; use one instance per thread.
    """

    COLLECTION_NAME = "evmbench_findings"

    def __init__(self, index_path: Path | str = _DEFAULT_INDEX) -> None:
        self._index_path = Path(index_path)
        self._collection = None  # lazy-loaded
        self._model = None       # lazy-loaded

    # ── Private helpers ─────────────────────────────────────────────────────

    def _get_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(EMBEDDING_MODEL)
                log.info(f"Loaded embedding model: {EMBEDDING_MODEL}")
            except ImportError as e:
                raise ImportError(
                    "sentence-transformers is required for RAG: pip install sentence-transformers"
                ) from e
        return self._model

    def _get_collection(self):
        if self._collection is None:
            try:
                # pysqlite3-binary ships a newer sqlite3 (>= 3.35.0) required by chromadb.
                # Monkey-patch before importing chromadb so it uses the bundled version.
                try:
                    import pysqlite3 as _pysqlite3
                    import sys as _sys
                    _sys.modules["sqlite3"] = _pysqlite3
                except ImportError:
                    pass  # system sqlite3 may be new enough
                import chromadb
            except ImportError as e:
                raise ImportError(
                    "chromadb is required for RAG: pip install chromadb pysqlite3-binary"
                ) from e
            self._index_path.mkdir(parents=True, exist_ok=True)
            settings = chromadb.Settings(anonymized_telemetry=False)
            client = chromadb.PersistentClient(
                path=str(self._index_path), settings=settings
            )
            self._collection = client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    @staticmethod
    def _parse_finding_file(path: Path) -> dict[str, str]:
        """
        Parse an EVMbench H-*.md finding file.

        Returns {"title", "body", "vuln_id", "task_id", "doc_type"}
        """
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        title = ""
        for line in lines:
            stripped = line.strip()
            if stripped:
                title = re.sub(r"^#+\s*", "", stripped)
                break

        vuln_id = path.stem
        # task_id: walk back up to the segment above 'findings/'
        # works for both audits/{task_id}/findings/H-01.md
        # and audits/{task_id}/findings/incorrect/high/H-01.md
        rev_parts = list(reversed(path.parts))
        try:
            findings_rev_idx = rev_parts.index("findings")
            task_id = rev_parts[findings_rev_idx + 1]
        except (ValueError, IndexError):
            task_id = path.parents[1].name  # fallback

        # Determine doc_type from path — incorrect/ subdirs are negatives
        if "incorrect" in path.parts:
            doc_type = "negative"
        else:
            doc_type = "ground_truth"

        return {
            "title":    title,
            "body":     text[:_BODY_LIMIT],
            "vuln_id":  vuln_id,
            "task_id":  task_id,
            "doc_type": doc_type,
        }

    @staticmethod
    def _parse_gold_audit(path: Path) -> list[dict[str, str]]:
        """
        Split a gold_audit.md file into per-finding chunks.

        gold_audit.md files contain multiple findings separated by ## [H-XX] headings.
        Each chunk is indexed as a separate "gold_audit" document with the full
        write-up (description, attack steps, PoC, mitigation) up to _BODY_LIMIT chars.

        Returns list of {"title", "body", "vuln_id", "task_id", "doc_type"}
        """
        text = path.read_text(encoding="utf-8", errors="replace")
        # task_id: audits/{task_id}/findings/gold_audit.md
        task_id = path.parents[1].name

        # Split on ## [H-XX] heading boundaries (keep the heading with each chunk)
        raw_chunks = re.split(r"(?=^## \[H-\d+\])", text, flags=re.MULTILINE)

        results = []
        for chunk in raw_chunks:
            chunk = chunk.strip()
            if not chunk or not re.match(r"^## \[H-\d+\]", chunk):
                continue

            first_line = chunk.splitlines()[0]
            title = re.sub(r"^##\s*", "", first_line).strip()
            m = re.search(r"\[(H-\d+)\]", title)
            vuln_id = m.group(1) if m else "H-??"

            results.append({
                "title":    title,
                "body":     chunk[:_BODY_LIMIT],
                "vuln_id":  vuln_id,
                "task_id":  task_id,
                "doc_type": "gold_audit",
            })

        return results

    # ── Public API ───────────────────────────────────────────────────────────

    def build_index(self, findings_root: str | Path) -> dict[str, Any]:
        """
        Scan findings_root for all indexable files and add them to ChromaDB.

        Sources indexed:
          - H-*.md in findings/        → doc_type=ground_truth
          - gold_audit.md in findings/ → doc_type=gold_audit (chunked per finding)
          - H-*.md in incorrect/       → doc_type=negative

        Idempotent: skips documents already in the collection by doc_id.

        Args:
            findings_root: Path to EVMbench audits/ directory.

        Returns:
            {"indexed": int, "skipped": int, "total_found": int, "errors": list,
             "by_type": {"ground_truth": int, "gold_audit": int, "negative": int}}
        """
        root = Path(findings_root)
        if not root.exists():
            raise FileNotFoundError(f"findings_root not found: {root}")

        collection = self._get_collection()
        model = self._get_model()

        existing = set(collection.get()["ids"])

        docs, embeddings, metadatas, ids = [], [], [], []
        errors = []
        skipped = 0
        by_type: dict[str, int] = {"ground_truth": 0, "gold_audit": 0, "negative": 0}

        # ── 1. Individual H-*.md files (ground_truth + negative) ────────────
        for path in root.rglob("H-*.md"):
            try:
                parsed = self._parse_finding_file(path)
                # gold_audit.md files are handled separately below
                # For negatives, include the confidence subdir (high/low) in the ID
                # to avoid collisions between incorrect/high/H-01 and incorrect/low/H-01
                if parsed["doc_type"] == "negative":
                    subdir = path.parent.name  # "high" or "low"
                    doc_id = f"{parsed['task_id']}__{parsed['doc_type']}__{subdir}__{parsed['vuln_id']}"
                else:
                    doc_id = f"{parsed['task_id']}__{parsed['doc_type']}__{parsed['vuln_id']}"
                # Backward compat: also check old-style id (no doc_type prefix)
                old_id = f"{parsed['task_id']}__{parsed['vuln_id']}"

                if doc_id in existing or old_id in existing:
                    skipped += 1
                    continue

                embed_text = f"{parsed['title']} {parsed['body']}"
                docs.append(parsed["body"])
                embeddings.append(model.encode(embed_text[:4000]).tolist())
                metadatas.append({
                    "title":    parsed["title"],
                    "vuln_id":  parsed["vuln_id"],
                    "task_id":  parsed["task_id"],
                    "doc_type": parsed["doc_type"],
                })
                ids.append(doc_id)
                by_type[parsed["doc_type"]] = by_type.get(parsed["doc_type"], 0) + 1

            except Exception as e:
                errors.append({"file": str(path), "error": str(e)})
                log.warning(f"Failed to parse {path}: {e}")

        # ── 2. gold_audit.md files (one per audit, chunked per finding) ──────
        for path in root.rglob("gold_audit.md"):
            try:
                chunks = self._parse_gold_audit(path)
                for parsed in chunks:
                    doc_id = f"{parsed['task_id']}__gold_audit__{parsed['vuln_id']}"
                    if doc_id in existing:
                        skipped += 1
                        continue

                    embed_text = f"{parsed['title']} {parsed['body']}"
                    docs.append(parsed["body"])
                    embeddings.append(model.encode(embed_text[:4000]).tolist())
                    metadatas.append({
                        "title":    parsed["title"],
                        "vuln_id":  parsed["vuln_id"],
                        "task_id":  parsed["task_id"],
                        "doc_type": "gold_audit",
                    })
                    ids.append(doc_id)
                    by_type["gold_audit"] += 1

            except Exception as e:
                errors.append({"file": str(path), "error": str(e)})
                log.warning(f"Failed to parse gold_audit {path}: {e}")

        # ── Batch upsert ─────────────────────────────────────────────────────
        BATCH = 64
        for i in range(0, len(ids), BATCH):
            collection.add(
                documents=docs[i:i+BATCH],
                embeddings=embeddings[i:i+BATCH],
                metadatas=metadatas[i:i+BATCH],
                ids=ids[i:i+BATCH],
            )

        result = {
            "indexed":     len(ids),
            "skipped":     skipped,
            "total_found": len(ids) + skipped,
            "errors":      errors,
            "by_type":     by_type,
        }
        log.info(f"RAG index built: {result}")
        return result

    def retrieve(self, query_text: str, k: int = 3) -> list[dict[str, Any]]:
        """
        Retrieve top-k positive findings (ground_truth + gold_audit) for query_text.

        Negative examples (incorrect/) are excluded — use retrieve_negatives() for those.

        Args:
            query_text: Source code snippet or vulnerability description.
            k:          Number of examples to return.

        Returns:
            List of dicts: [{"title", "text", "task_id", "vuln_id", "doc_type", "similarity"}]
            Empty list if index is empty or retrieval fails.
        """
        collection = self._get_collection()
        if collection.count() == 0:
            log.warning("RAG collection is empty — call build_index() first")
            return []

        model = self._get_model()
        try:
            query_vec = model.encode(query_text[:4000]).tolist()
            # Filter to positive doc types only; fall back to no filter if the
            # collection predates doc_type metadata (backward compatibility).
            try:
                results = collection.query(
                    query_embeddings=[query_vec],
                    n_results=min(k, collection.count()),
                    where={"doc_type": {"$in": ["ground_truth", "gold_audit"]}},
                    include=["documents", "metadatas", "distances"],
                )
            except Exception:
                # Old index without doc_type — query without filter
                results = collection.query(
                    query_embeddings=[query_vec],
                    n_results=min(k, collection.count()),
                    include=["documents", "metadatas", "distances"],
                )
        except Exception as e:
            log.error(f"RAG retrieve error: {e}")
            return []

        return self._format_results(results)

    def retrieve_negatives(self, query_text: str, k: int = 2) -> list[dict[str, Any]]:
        """
        Retrieve top-k distractor findings (incorrect/ files) for query_text.

        These are plausible-but-wrong vulnerability reports. Injecting them into the
        scanner prompt as "previous false positives" helps suppress similar false calls.

        Args:
            query_text: Source code snippet or vulnerability description.
            k:          Number of negative examples to return.

        Returns:
            List of dicts: [{"title", "text", "task_id", "vuln_id", "doc_type", "similarity"}]
            Empty list if no negatives are indexed or retrieval fails.
        """
        collection = self._get_collection()
        if collection.count() == 0:
            return []

        model = self._get_model()
        try:
            query_vec = model.encode(query_text[:4000]).tolist()
            neg_count = self._count_by_type("negative")
            if neg_count == 0:
                return []
            results = collection.query(
                query_embeddings=[query_vec],
                n_results=min(k, neg_count),
                where={"doc_type": "negative"},
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            log.error(f"RAG retrieve_negatives error: {e}")
            return []

        return self._format_results(results)

    def count(self) -> int:
        """Return total number of documents in the index."""
        return self._get_collection().count()

    def count_by_type(self) -> dict[str, int]:
        """Return document counts split by doc_type."""
        return {
            "ground_truth": self._count_by_type("ground_truth"),
            "gold_audit":   self._count_by_type("gold_audit"),
            "negative":     self._count_by_type("negative"),
        }

    def is_ready(self) -> bool:
        """True if the index has been built and contains documents."""
        try:
            return self.count() > 0
        except Exception:
            return False

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _count_by_type(self, doc_type: str) -> int:
        try:
            collection = self._get_collection()
            result = collection.get(where={"doc_type": doc_type})
            return len(result["ids"])
        except Exception:
            return 0

    @staticmethod
    def _format_results(results: dict) -> list[dict[str, Any]]:
        hits = []
        docs      = results["documents"][0]
        metas     = results["metadatas"][0]
        distances = results["distances"][0]  # cosine distance [0, 2]

        for doc, meta, dist in zip(docs, metas, distances):
            similarity = round(1.0 - dist / 2.0, 4)  # convert to [0, 1]
            hits.append({
                "title":      meta.get("title", ""),
                "text":       doc,
                "task_id":    meta.get("task_id", ""),
                "vuln_id":    meta.get("vuln_id", ""),
                "doc_type":   meta.get("doc_type", "ground_truth"),
                "similarity": similarity,
            })

        return hits
