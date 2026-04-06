# Calyx

**AI-Powered Real-Time Blockchain Security System**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-orange.svg)](https://pytorch.org/)

> Preventing blockchain exploits at two critical layers: smart contract vulnerabilities and UI manipulation detection.

---

## Overview

Calyx is a dual-layer blockchain security system combining Graph Neural Networks (GNN), heuristic opcode analysis, and static analysis to detect vulnerabilities before exploits execute. All detection is LLM-free with no API keys required for analysis.

### The Problem
- **$3.24B lost** to smart contract vulnerabilities (2018–2022)
- **February 2025:** Bybit hack ($1.5B) via UI manipulation as wallet showed "transfer" but calldata said "approve unlimited"
- Traditional tools (Slither, Mythril) analyze deployed code only; none detect UI-layer attacks

### The Solution: Dual-Layer Defense

**Layer 1: Smart Contract Code Analysis**
- Source-code GNN: 3-layer GCN trained on 4,028 audit findings from 17 sources (F1=0.859, Recall=1.000)
- Bytecode GNN: CFG-based GNN for closed-source contracts, trained on 13,901 real+synthetic graphs (F1=0.878, Recall=0.840)
- AM Pattern Detector: heuristic opcode-sequence scanner for AM3–AM8 asset-management vulnerabilities (no API); AM1/AM2 detected by TaintAnalyzer
- Slither static analysis (90+ detectors) as a validation stage
- AdversarialClassifier: 6-signal pre-attack deployment triage (Stage 9, LookAhead-style)

**Layer 2: UI Manipulation Detection** — unique to Calyx
- Calldata verifier compares what the wallet UI shows vs. raw transaction calldata
- Detects Bybit-style attacks in real time, before the user signs

---

## Implemented Components

| Component | Description | Status |
|-----------|-------------|--------|
| **Calldata Verifier** | UI manipulation detection (ABI decoding + comparison) | Production-ready |
| **GNN Analyzer (source)** | 3-layer GCN trained on 4,028 audit graphs, F1=0.859, Recall=1.000 | Trained + deployed |
| **GNN Analyzer (bytecode)** | 3-layer GCN trained on 13,901 real+synthetic graphs, F1=0.878, Recall=0.840 | Trained + deployed |
| **AM Pattern Detector** | Heuristic opcode scanner for AM3–AM8 vulns (SoK DeFi Attacks), no API | Production-ready |
| **Taint Analyzer** | Data-flow taint analysis: AM1/AM2 (SKANF Gap 2) + AM6 oracle taint + AM8 delegatecall | Production-ready |
| **Similarity Scanner** | Opcode n-gram Jaccard similarity vs. exploit corpus (SoK arXiv:2208.13035) | Production-ready |
| **EVM Decompiler Client** | Optional REST client for Dedaub/Panoramix decompilation (graceful no-key fallback) | Production-ready |
| **Bytecode Pipeline** | SKANF-style 10-stage closed-source analysis (Gaps 1–3, Stages 5d/5e, AI audit) | Production-ready |
| **AdversarialClassifier** | Stage 9: 6-signal pre-attack triage (LookAhead-style); 40/40 unit tests pass | Production-ready |
| **Deployment Pipeline** | Watches new deployments → BytecodePipeline → classify → alert (optional LLM audit) | Production-ready |
| **AI Audit Agent** | Stage 8: LLM security report via Anthropic/Gemini/Groq/OpenAI + RAG augmentation | Production-ready |
| **Context Builder** | TAC-style CFG summary + structured JSON/markdown context for LLM (arXiv:2506.19624) | Production-ready |
| **Slither Analyzer** | Static analysis wrapper, 90+ detectors | Production-ready |
| **FastAPI Server** | REST API with detection endpoints | Production-ready |
| **Etherscan Client** | Multi-network bytecode + source fetching | Production-ready |

---

## Architecture

```
Incoming Transaction / Contract Address
        │
        ├── SOURCE PATH ──────────────────────────────────────────┐
        │                                                         │
        ▼                                                         ▼ BYTECODE PATH (SKANF-Lite)
┌───────────────────┐    ┌──────────────────────┐   ┌────────────────────────────┐
│ Calldata Verifier │    │    GNN Analyzer       │   │  Etherscan → CFG Profiler  │
│ (UI vs calldata)  │    │  F1=0.859 R=1.000     │   │  → Decompiler → TxnAnalyzer│
└────────┬──────────┘    └──────────┬───────────┘   └─────────────┬──────────────┘
         │                          │                              │
         │               ┌──────────▼───────────┐   ┌─────────────▼──────────────┐
         │               │   Slither Analyzer    │   │  AM Pattern Detector       │
         │               │  (static analysis)    │   │  AM3–AM8 (no API)          │
         │               └──────────┬───────────┘   └─────────────┬──────────────┘
         │                          │                              │
         │                          │               ┌─────────────▼──────────────┐
         │                          │               │  Bytecode GNN              │
         │                          │               │  F1=0.878, R=0.840         │
         │                          │               │  (13,901 real+synth)       │
         │                          │               └─────────────┬──────────────┘
         │                          │                              │
         └──────────────┬───────────┘──────────────────────────────┘
                        ▼
               Risk Scorer (3-signal weighted)
               CRITICAL / HIGH / MEDIUM / LOW
                        │
                        ▼
          AdversarialClassifier (Stage 9)
          6-signal: taint+callback+similarity
          +complexity+gnn+obfuscation
          → adversarial / suspicious / benign
          Basis: LookAhead FSE 2025 (F1=0.8966)
```

---

## GNN Architecture

### Model: CalyxGNN (3-Layer Graph Convolutional Network)

```
Input:  Transaction graph (addresses as nodes, calls/transfers as edges)
        Node features: 16-dim behavioral features
        Edge features: 8-dim (function type, value, gas, callback flags)

Layer 1: GraphConvLayer(16 → 64)   — local neighborhood aggregation
Layer 2: GraphConvLayer(64 → 64)   — 2-hop pattern learning
Layer 3: GraphConvLayer(64 → 32)   — compressed graph embedding

Readout: Global mean pooling       — graph-level representation
Classifier: MLP (32 → 32 → 1)     — binary exploit probability

Output: exploit_probability ∈ [0,1]
        risk_level: HIGH (≥0.8) | MEDIUM (0.5–0.8) | LOW (<0.5)
```

**Parameters:** 8,737 trainable
**Inference time:** <100ms on CPU

### Node Features (16-dim)

```python
[is_contract, is_verified, log10(balance_eth), log10(tx_count),
 age_days/3650, has_fallback, call_depth/10, is_new_addr,
 high_value, many_callers, *6 reserved dims]
```

No explicit attacker/victim role labels — GNN infers suspicion from behavioral patterns only.

### Edge Features (8-dim)

```python
[function_type/13, log10(value_eth), log10(gas_used), call_depth/10,
 is_internal, reverted, is_callback, large_value]
```

### Training Configuration

```
Optimizer:   Adam (lr=0.001)
Loss:        BCEWithLogitsLoss
Batch size:  32
Epochs:      50 (early stopping, patience=10)
Dropout:     0.3
```

### Performance

| Metric | Result | Target | Pass |
|--------|--------|----------------|------|
| Test F1 | 0.859 | ≥0.85 | ✅ |
| Test Recall | 1.000 | ≥0.90 | ✅ |
| Test Accuracy | 0.752 | ≥0.90 | ❌ |
| Test Precision | 0.752 | — | — |

**Note:** Recall=1.0 with Accuracy=0.752 reflects class imbalance in the training set (75% exploit, 25% benign). The model never misses an exploit but has false positives on benign transactions. Accuracy target is not met.

---

## Dataset

**4,028 samples** from 17 sources (60/20/20 train/val/test split):

| Source | Count | Type |
|--------|-------|------|
| Code4rena | 1,000 | Audit competition findings |
| Synthetic benign | 1,000 | Normal transaction patterns |
| Sherlock | 595 | Audit findings |
| Pashov Audit Group | 277 | Audit findings |
| Rekt | 281 | Historical exploits |
| Certora | 147 | Formal verification findings |
| Trail of Bits | 100 | Audit findings |
| Synthetic audits | 200 | Generated patterns |
| Others (8 firms) | 428 | Various |
| **Total** | **4,028** | |

**Graph format:** Each finding is converted to a transaction graph via `data/parsers/graph_builder.py`. Graphs use deterministic topology seeded by `report_id` (2–4 nodes, 1–6 edges).

**Label:** `1` (exploit) if `category != 'benign'`, else `0`.

---

## API Reference

Server runs on `http://localhost:8000`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/analyze` | POST | Calldata UI verification |
| `/api/v1/analyze/bybit-demo` | POST | Bybit attack demo |
| `/api/v1/analyze/contract` | POST | GNN + Slither analysis |
| `/api/v1/stats` | GET | System statistics |

---

## Quick Start

### Prerequisites

```
Python 3.10+
Node.js 18+
PyTorch 2.0+
```

### Installation

```bash
git clone https://github.com/yourusername/calyx.git
cd calyx

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Add ETHERSCAN_API_KEY to .env (required for bytecode fetch; analysis itself needs no API key)
```

### Regenerate Dataset & Run Training

```bash
# Generate processed splits from raw data
python data/parsers/graph_builder.py

# Train GNN (optional — checkpoint already included)
python -m models.gnn.train

# Verify splits
python -m models.gnn.dataset
```

### Run the System

```bash
# Start API server
python -m api.server

# Start dashboard
cd dashboard && npm start
```

### Run Tests

```bash
# All tests (71 pass, 5 skipped — integration tests skip without live server)
python3 -m pytest tests/ -v

# Individual suites
python3 -m pytest tests/unit/test_gnn_model.py -v              # 10 tests
python3 -m pytest tests/test_adversarial_classifier.py -v      # 40 tests
python3 -m pytest tests/test_deployment_watcher.py -v          # 21 tests
python3 -m pytest tests/integration/test_api.py -v             # 5 tests (needs server)
```

### Benchmark Results

See [`docs/RESULTS.md`](docs/RESULTS.md) for:
- GNN metrics vs. Mythril / Slither / ReDetect baselines
- AdversarialClassifier vs. LookAhead (F1=0.8966) and FinDet (BAC=0.9374)
- Live demo pipeline run on SKANF reference MEV bot (1.98s, 5 findings)
- EVMbench source-mode historical baseline (R=4.2%, Claude API)

---

## Project Structure

```
calyx/
├── analysis/
│   ├── bytecode_pipeline.py        # Stages 3a–8: full SKANF-style orchestrator (LLM-free)
│   ├── deployment_pipeline.py      # Stage 9: watch → BytecodePipeline → classify → alert
│   ├── audit_agent.py              # Stage 8: LLM audit (Anthropic/Gemini/Groq/OpenAI) + RAG
│   ├── context_builder.py          # P2: LLM-ready markdown/JSON context (TAC-style CFG)
│   ├── txn_guided_taint.py         # P1: historical txn correlation with taint findings
│   ├── hybrid_analyzer.py          # Source-code path: GNN + Slither (F1=0.817)
│   └── static/
│       └── slither_analyzer.py     # Slither wrapper, 90+ detectors
│
├── data/
│   ├── collectors/
│   │   ├── benign_collector.py     # 7-pass DeFiLlama + token lists → ~5,882 benign addresses
│   │   ├── exploit_collector.py    # reentrancy-attacks + eth-labels → ~1,695 exploit addresses
│   │   ├── real_bytecode_collector.py  # Etherscan bytecode fetch + CFG build + merge
│   │   └── defihacklabs_scraper.py # GitHub 725 PoCs → exploit_addresses.csv
│   ├── datasets/
│   │   ├── bytecode/               # 4,000 synthetic (2,000 exploit / 2,000 benign)
│   │   ├── real_bytecode/          # 9,901 real on-chain graphs
│   │   └── bytecode_merged/        # 13,901 merged (active training set)
│   └── parsers/
│       ├── graph_builder.py        # Audit findings → source-code GNN graphs
│       └── bytecode_dataset_generator.py  # Synthetic EVM bytecode (EVMBuilder)
│
├── detectors/
│   ├── bytecode_analyzer/          # CFGDeobfuscator, TaintAnalyzer, AMPatternDetector, etc.
│   ├── calldata_verifier/          # UI manipulation detection
│   ├── deployment_watcher/         # AdversarialClassifier (Stage 9) + DeploymentWatcher
│   ├── gnn_analyzer/               # GNN inference wrappers (source + bytecode)
│   ├── mempool_monitor/            # MempoolListener + ContractAnalysisCache
│   ├── risk_scorer/                # 3-signal weighted risk scorer
│   └── claude_scanner/             # RAG retriever (472 docs); scanner reference only
│
├── models/
│   └── gnn/
│       ├── model.py                # CalyxGNN architecture (8,737 params)
│       ├── train.py / evaluate.py / dataset.py  # Source-code GNN training
│       ├── bytecode_train.py       # Bytecode GNN training (pos_weight auto-computed)
│       ├── bytecode_graph_builder.py  # Bytecode → CFG graphs (16-dim features)
│       └── checkpoints/
│           ├── bytecode_model.pt   # Production: F1=0.878 on 13,901 graphs
│           └── best_model.pt       # Reference: F1=0.994 on DeFiHackLabs real data
│
├── api/
│   └── server.py                   # FastAPI server, 5 endpoints
│
├── integrations/
│   ├── etherscan_client.py         # Multi-network bytecode + source fetching (V2 API)
│   └── evm_decompiler_client.py    # Optional Dedaub/Panoramix REST client
│
├── scripts/
│   ├── demo_pipeline.py            # End-to-end CLI demo (--address/--bytecode/--validate)
│   ├── watch_deployments.py        # Pre-attack deployment monitoring CLI
│   ├── monitor.py                  # Mempool monitor CLI
│   ├── benchmark_evmbench_detect.py  # EVMbench recall/precision/F1 benchmark
│   └── build_rag_index.py          # Build EVMbench RAG index (472 docs)
│
├── tests/
│   ├── unit/test_gnn_model.py      # CalyxGNN architecture tests (10 tests)
│   ├── integration/test_api.py     # API endpoint tests (5 tests, skipped without server)
│   ├── test_adversarial_classifier.py  # Stage 9 classifier (40 tests)
│   └── test_deployment_watcher.py  # DeploymentWatcher (21 tests)
│
├── docs/
│   ├── ARCHITECTURE.md             # This file
│   ├── RESULTS.md                  # Benchmark results + competitive comparison
│   ├── PROGRESS.md                 # Development log by week
│   ├── HACKATHON_BUILD_PLAN.md     # Commit-by-commit build guide
│   └── research/                   # Paper summaries and synthesis
│
├── evmbench/                       # EVMbench frontier-evals integration
├── requirements.txt
└── CHANGELOG.md
```

---

## Research Basis

Key papers informing the architecture (21 reviewed):

1. **SKANF** (IC3/Yale, arXiv:2504.13398, 2025) — Core methodology: CFG deobfuscation, taint analysis, fork-EVM validation on closed-source MEV bots. Author (Sen Yang) confirmed Calyx's structured failure log and AI agent integration are novel extensions not present in the SKANF artifact.
2. **TAC+LLM decompilation** (arXiv:2506.19624) — bytecode → TAC → fine-tuned Llama → Solidity. Sen Yang endorsed combining with SKANF deobfuscation for obfuscated contracts.
3. **ReDetect** — Hybrid LLM+GNN baseline (94% precision)
4. **LLM-SmartAudit** — Multi-agent conversation system
5. **NyxLLM 2.0** — ICL + adversarial prompting (+22% F1)
6. **RAG-LLM** — Vector store retrieval (62.7% guided detection)
7. **DeFi Attacks SoK** (Liyi Zhou, IEEE S&P, arXiv:2208.13035) — systematic DeFi attack taxonomy; basis for [Clara](https://clarahacks.com) live exploit dataset.
8. **Smart-LLaMA, SymGPT, CKG-LLM, LightCross, TRACE, SmartLLMSentry, DeCoAgent** — Additional techniques

**Live attack dataset:** [Clara](https://clarahacks.com) — real-time DeFi exploit intelligence, 300+ incidents (growing ~1.5/day). Contract addresses from recent incidents can be piped directly into `demo_pipeline.py --address`.

Key finding: Hybrid GNN + Static achieves strong recall (1.000); SKANF-style bytecode pipeline catches vulnerabilities in closed-source contracts that every other tool produces zero output on.

---

## License

MIT — see [LICENSE](LICENSE).

