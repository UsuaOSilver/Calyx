# Calyx — System Architecture

**Last updated: 2026-03-27 (v0.5.3)**

> **Note:** Claude Scanner (Anthropic API) is **not implemented** — no API credits available.
> Both source-code and bytecode paths use fully LLM-free detection.
> Stage 8 (AuditAgent) uses free-tier Gemini/Groq. Stage 9 (AdversarialClassifier) is LLM-free.

---

## Overview

Calyx is a smart contract security analysis system built for the SJSU CSCI 490
capstone (due May 8, 2026). It combines three complementary detection layers into a unified
pipeline and implements a full SKANF-style bytecode analysis path for closed-source contracts
(Gap 1: CFG deobfuscation, Gap 2: static taint analysis, Gap 3: fork-EVM exploit validation).
All detection is LLM-free — no external API keys required for analysis.

---

## Pipeline Diagram

```
INPUT
  ├── Contract address  (source unavailable)
  └── Solidity source   (source available)
         │
         ├─────────────────────────────────────────────────┐
         │                                                 │
   SOURCE PATH                                    BYTECODE PATH (SKANF-style)
         │                                                 │
         ▼                                                 ▼
┌──────────────────────┐                    ┌──────────────────────────┐
│  Calldata Verifier   │                    │  Etherscan V2 API        │
│  verifier.py         │                    │  etherscan_client.py     │
│  · ABI decode        │                    │  → raw bytecode hex      │
│  · UI vs calldata    │                    └────────────┬─────────────┘
│  · Bybit-style phish │                                 │
└─────────┬────────────┘                    ┌────────────▼─────────────┐
          │                                 │  CFG Profiler            │
          ▼                                 │  cfg_profiler.py         │
┌──────────────────────┐                    │  · indirect jump count   │
│  GNN Analyzer        │                    │  · obfuscation_score     │
│  gnn_analyzer/       │                    └────────────┬─────────────┘
│  CalyxGNN 3-layer    │                                 │
│  GCN, 8,737 params   │                    ┌────────────▼─────────────┐
│  best_model.pt       │                    │  Decompiler              │
│  F1=0.859 R=1.000    │                    │  decompiler.py           │
│  → gnn_score [0,1]   │                    │  · panoramix pseudocode  │
└─────────┬────────────┘                    │  · disassembly fallback  │
          │                                 └────────────┬─────────────┘
          ▼                                              │
┌──────────────────────┐                    ┌────────────▼─────────────┐
│  Slither Analyzer    │                    │  Txn Analyzer            │
│  slither_analyzer.py │                    │  txn_analyzer.py         │
│  · GNN HIGH → runs   │                    │  · AM1–AM5 anomaly flags │
│  · Validates signal  │                    │  · anomaly_score [0,1]   │
└─────────┬────────────┘                    └────────────┬─────────────┘
          │                                              │
          │                                 ┌────────────▼─────────────┐
          │                                 │  AM Pattern Det.         │
          │                                 │  AMPatternDetector       │
          │                                 │  · AM3 tx.origin guard   │
          │                                 │  · AM4 approve+xferFrom  │
          │                                 │  · AM5 callback no check │
          │                                 │  (AM1/AM2 → TaintAnalyzer│
          │                                 │   No API required)       │
          │                                 └────────────┬─────────────┘
          │                                              │
          │                                 ┌────────────▼─────────────┐
          │                                 │  Bytecode GNN            │
          │                                 │  BytecodeGNNAnalyzer     │
          │                                 │  · CFG graphs from       │
          │                                 │    basic blocks          │
          │                                 │  · bytecode_model.pt     │
          │                                 │    F1=0.878, R=0.840     │
          │                                 │    (13,901 real+synth)   │
          │                                 │  → gnn_score [0,1]       │
          │                                 └────────────┬─────────────┘
          │                                              │
          ▼                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CFG Deobfuscator (Stage 3a — Gap 1)                               │
│  cfg_deobfuscator.py                                                │
│  · constant-fold JUMP targets from block's push/arithmetic chain   │
│  · over-approximate indirect jumps → connect to all JUMPDESTs      │
│  → complete CFG (resolved + approximated edges, no missing paths)  │
└─────────────────────────────────────────────────────┬───────────────┘
                                                      │
          ▼                                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Taint Analyzer (Stage 5a — Gap 2)                                 │
│  taint_analyzer.py                                                  │
│  · linear stack simulation: tags calldata/value/origin/caller      │
│  · taint propagates through arithmetic, bitwise, MLOAD/SLOAD       │
│  · parallel stack_val tracks raw PUSH constants for ERC-20 check   │
│  · CALL with tainted 'to' → AM1  |  tainted 'value' → AM2         │
│  · CALLER+EQ+JUMPI guard suppresses AM1                            │
│  · AM1 annotated: erc20_sensitive + sensitive_token_addr           │
│  → AM1/AM2 findings with taint_source + SKANF sensitivity fields   │
└─────────────────────────────────────────────────────┬───────────────┘
                                                      │
          ▼                                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Risk Scorer (Stage 6)                                              │
│  risk_scorer/scorer.py                                              │
│                                                                     │
│  risk_score = 0.30 × gnn_score                                     │
│             + 0.55 × findings_sub  (taint + pattern findings)      │
│             + 0.15 × txn_anomaly_score                             │
│                                                                     │
│  findings_sub = min(1.0, Σ (severity_weight + confirmed_bonus))    │
│    HIGH=0.25  MEDIUM=0.10  LOW=0.03  confirmed_bonus=+0.10        │
│                                                                     │
│  → risk_score [0.0, 1.0]                                           │
│  → risk_level  CRITICAL/HIGH/MEDIUM/LOW                            │
└─────────────────────────────────────────────────────┬───────────────┘
                                                      │
                           ┌──────────────────────────▼───────────────┐
                           │  Exploit Validator (Stage 7 — Gap 3)     │
                           │  exploit_validator.py                     │
                           │  · optional: gated by ETHEREUM_RPC_URL   │
                           │  · Anvil forks mainnet at latest block    │
                           │  · erc20_sensitive AM1 → full ERC-20 call│
                           │    (SKANF aeg.py: sel+dest+amount)        │
                           │  · generic AM1 → attacker addr word       │
                           │  · `cast send` → measure ETH delta        │
                           │  → confirmed + eth_drained_wei            │
                           │  → failure_reason when not confirmed      │
                           │  → re-score with confirmed_bonus +0.10    │
                           └──────────────────────┬───────────────────┘
                                                  │
                           ┌──────────────────────▼───────────────────┐
                           │  AdversarialClassifier (Stage 9)          │
                           │  deployment_watcher/classifier.py         │
                           │  · taint signal      0.30 weight          │
                           │  · callback signal   0.15 weight          │
                           │  · similarity signal 0.15 weight          │
                           │  · complexity signal 0.15 weight          │
                           │  · gnn signal        0.15 weight          │
                           │  · obfuscation signal 0.10 weight         │
                           │  Threshold: ≥0.55 adversarial             │
                           │            ≥0.35 suspicious               │
                           │  Basis: LookAhead FSE 2025 (F1=0.8966)   │
                           │         SoK: 56% attacks non-atomic,      │
                           │         avg rescue window = 1h ±4.1h      │
                           │  → adversarial_score, classification      │
                           │  → rescue_window_advisory, evidence       │
                           └──────────────────────────────────────────┘
```

---

## Component Status

### Built and Real

| Component | File | Status | Key Metric |
|---|---|---|---|
| Calldata Verifier | `detectors/calldata_verifier/verifier.py` | PRODUCTION | 8/8 tests pass |
| GNN Model | `models/gnn/model.py` | REAL | F1=0.994, Recall=0.987 |
| GNN Analyzer | `detectors/gnn_analyzer/analyzer.py` | REAL | Wired to bytecode_model.pt |
| Slither Wrapper | `analysis/static/slither_analyzer.py` | REAL | Hybrid Recall=1.000 |
| Hybrid Analyzer | `analysis/hybrid_analyzer.py` | REAL | F1=0.817 |
| Etherscan Client | `integrations/etherscan_client.py` | REAL | V2 API, 5 networks |
| CFG Profiler | `detectors/bytecode_analyzer/cfg_profiler.py` | REAL | Tested on MEV bot |
| AM Pattern Detector | `detectors/bytecode_analyzer/cfg_profiler.AMPatternDetector` | REAL | AM3–AM8 (AM7: permissionless SSTORE; AM8: SLOAD→DELEGATECALL pattern; SoK arXiv:2208.13035) |
| Txn Analyzer | `detectors/bytecode_analyzer/txn_analyzer.py` | REAL | AM1–AM5 flags |
| Decompiler | `detectors/bytecode_analyzer/decompiler.py` | REAL | 15s timeout, fallback |
| Bytecode Graph Builder | `models/gnn/bytecode_graph_builder.py` | REAL | CFG graphs from bytecode |
| Bytecode GNN Analyzer | `detectors/gnn_analyzer/bytecode_analyzer.py` | REAL | bytecode_model.pt |
| Bytecode GNN (trained) | `models/checkpoints/bytecode_model.pt` | REAL | F1=0.878, Recall=0.840, Precision=0.920 on 13,901 real+synthetic graphs (6-chain, mean+max pooling) |
| CFG Deobfuscator | `detectors/bytecode_analyzer/cfg_deobfuscator.py` | REAL | Gap 1: constant-fold + over-approx |
| Taint Analyzer | `detectors/bytecode_analyzer/taint_analyzer.py` | REAL | Gap 2: AM1/AM2 + AM6 oracle taint (RETURNDATACOPY→SSTORE) + AM8 storage-derived DELEGATECALL |
| SKANF Sensitive Constants | `detectors/bytecode_analyzer/skanf_sensitive.py` | REAL | 50 ETH+BSC DeFi addrs, 3 ERC-20 selectors |
| Exploit Validator | `detectors/bytecode_analyzer/exploit_validator.py` | REAL | Gap 3: Anvil fork-EVM; ERC-20 calldata |
| AI Audit Agent | `analysis/audit_agent.py` | REAL | Stage 8: LLM audit (Anthropic/Gemini/Groq/OpenAI); RAG auto-loads EVMbench index (472 docs, NyxLLM 2.0 ICL pattern) |
| Txn-Guided Taint | `analysis/txn_guided_taint.py` | REAL | Hot selectors, AM1/AM2 evidence txns |
| Context Builder | `analysis/context_builder.py` | REAL | LLM-ready markdown + JSON + TAC-style CFG summary (T1, arXiv:2506.19624) |
| Similarity Scanner | `detectors/bytecode_analyzer/similarity_scanner.py` | REAL | n-gram Jaccard vs. exploit corpus; AM1/AM4/AM5/AM6/AM8 families (SoK arXiv:2208.13035) |
| EVM Decompiler Client | `integrations/evm_decompiler_client.py` | REAL | Optional Dedaub/Panoramix REST client; graceful no-key fallback (arXiv:2506.19624) |
| CFG Function Split | `cfg_profiler.CFGProfiler.split_by_selector` | REAL | Per-function entry points by 4-byte selector (T2, arXiv:2506.19624) |
| Demo CLI | `scripts/demo_pipeline.py` | REAL | `--address/--bytecode/--validate/--quiet` |
| Bytecode Pipeline | `analysis/bytecode_pipeline.py` | REAL | LLM-free, Stages 3a–8 (10 stages including 5d similarity + 5e complexity, both live as of 2026-03-27) |
| AdversarialClassifier | `detectors/deployment_watcher/classifier.py` | REAL | Stage 9: 6-signal weighted; 40/40 unit tests pass; basis: LookAhead FSE 2025 |
| Deployment Watcher | `detectors/deployment_watcher/watcher.py` | REAL | Etherscan block poll, CREATE/CREATE2 detection; 21/21 unit tests pass |
| Deployment Pipeline | `analysis/deployment_pipeline.py` | REAL | Stage 9 orchestrator: watch → BytecodePipeline → classify → alert |
| RAG Retriever | `detectors/claude_scanner/rag.py` | REAL | EVMbench index: 472 docs (118 ground_truth + 120 gold_audit + 234 negatives); auto-wired to AuditAgent |
| Risk Scorer | `detectors/risk_scorer/scorer.py` | REAL | 3-signal weighted + confirmed bonus |
| FastAPI Server | `api/server.py` | PRODUCTION | 5 endpoints (no LLM) |

### Not Available / Out of Scope

| Component | File | Reason |
|---|---|---|
| Claude Scanner | `detectors/claude_scanner/scanner.py` | **No API credits** — not implemented |
| Prompt Templates | `detectors/claude_scanner/prompts.py` | Superseded by LLM-free detection |
| Multi-Agent | `detectors/claude_scanner/multi_agent.py` | Not in capstone scope |
| Mempool Monitor | `detectors/mempool_monitor/` | Built (MempoolListener + ContractAnalysisCache); requires MEMPOOL_WS_URL to run live |
| EigenLayer / Privy / Gnosis / Dune | `integrations/*/` | Not in capstone scope |

---

## Scanning Modes

### Source-Code

| Method | API | Use when |
|---|---|---|
| GNN Analyzer → Slither | **None** | Default — detect anomalous contracts, validate with static analysis |

> Claude Scanner source-code scan methods (`scan_evmbench_style`, `scan_evmbench_routed`, `scan_contract`) are **not available** — no Anthropic API credits.

### Bytecode (closed-source, SKANF-style)

| Method | API | Use when |
|---|---|---|
| `BytecodePipeline.analyze_bytecode()` | **None** | Default — fully LLM-free: AM detector + bytecode GNN |
| `BytecodePipeline.analyze_address()` | Etherscan only | Contract address input — fetches bytecode then runs pipeline |

Benchmark flag: `python scripts/benchmark_evmbench_detect.py --bytecode` — runs `BytecodePipeline` on selected tasks (no API required).

---

## GNN Details

**CalyxGNN** — 3-layer Graph Convolutional Network

- 8,737 parameters; checkpoint: `models/checkpoints/best_model.pt` (122KB)
- Dataset: 4,028 samples from 17 sources (2,416 train / 805 val / 807 test)
- 75% exploit-labeled → model maximizes recall, acceptable for security use case

**Active checkpoint: `bytecode_model.pt`** — production model used in `BytecodePipeline`

| Metric | Value | Target | |
|---|---|---|---|
| F1 | **0.878** | ≥ 0.85 | ✅ |
| Recall | **0.840** | ≥ 0.90 | ❌ |
| Precision | **0.920** | — | — |

> Retrained 2026-04-01 on `data/datasets/bytecode_merged/` — 13,901 graphs:
> - 4,000 synthetic (EVMBuilder, 9 vuln categories)
> - 7,947 real benign (ETH + BSC + Arbitrum + Optimism + Polygon + Base)
> - 5,954 real exploit (DeFiHackLabs PoCs + Dune drain + Solodit + BSC drain via public RPC)
> pos_weight = 1.335 (n_benign / n_exploit); architecture: mean+max pooling readout (upgraded from mean-only)

**Secondary checkpoint: `best_model.pt`** — trained on DeFiHackLabs-only real data (5,598 graphs)

| Metric | Value |
|---|---|
| Val F1 | 0.994 |
| Val Recall | 1.000 |

> Higher metrics because train and eval share the same real-data distribution.
> Not used in production — `bytecode_model.pt` is the active checkpoint.

---

## Calyx vs Full SKANF

| Capability | Full SKANF (IC3/Yale) | Calyx (v0.5.0) |
|---|---|---|
| Bytecode fetch | ✅ | ✅ Etherscan V2 |
| CFG deobfuscation | ✅ branch table injection | ✅ constant-fold + over-approx (CFGDeobfuscator) |
| Decompilation | ❌ raw bytecode | ✅ panoramix + disassembly fallback |
| Historical txn seeding | ✅ seeds concolic engine | ✅ TxnAnalyzer anomaly flags + TxnGuidedTaintAnalyzer |
| Taint / sensitivity check | ✅ SMT solver (Yices2 via Greed) | ✅ linear stack simulation (TaintAnalyzer) |
| ERC-20 sensitivity filter | ✅ 50 addrs + 3 selectors | ✅ skanf_sensitive.py (exact same constants) |
| Concolic execution | ✅ custom EVM + Manticore | ❌ out of scope (6+ months) |
| Exploit generation | ✅ fork-EVM (ethpwn) | ✅ Anvil fork-EVM (ExploitValidator, Gap 3) |
| Exploit calldata | ✅ full ERC-20 call (aeg.py) | ✅ matches aeg.py: sel+dest+amount via erc20_calldata() |
| Structured failure log | ❌ (author confirmed: "we do not include this part") | ✅ 7 machine-readable `failure_reason` codes — Calyx-only extension |
| LLM auditing | ❌ | ✅ Stage 8: `AuditAgent` — Anthropic/Gemini/Groq/OpenAI; RAG augmentation (NyxLLM 2.0 ICL pattern); author-endorsed direction |
| Pre-attack deployment detection | ❌ (explicit future direction) | ✅ Stage 9: `AdversarialClassifier` + `DeploymentWatcher`; LookAhead-style 6-signal weighted classifier; only tool combining deobfuscation + taint + GNN + similarity |

Live result (2026-03-04): MEV bot `0x00000000003b3cc22af3ae1eac0440bcee416b40`
- 3 findings: AM1 CRITICAL, AM2 HIGH, AM5 CRITICAL
- AM1/AM2 detected by TaintAnalyzer (static taint); AM6/AM8 also by TaintAnalyzer (SoK extensions)
- AM3/AM4/AM5/AM7/AM8 (pattern-level) by AMPatternDetector; AM7/AM8 added from SoK DeFi Attacks (arXiv:2208.13035)
- Original live scan used Claude API — now fully reproduced LLM-free via BytecodePipeline

---

## Benchmark Results

### EVMbench Source-Code Scan (2026-03-04, historical — Claude API, now deprecated)

`python scripts/benchmark_evmbench_detect.py --mode routed` — 40/40 tasks, 0 errors

| Metric | Value |
|---|---|
| Recall | **4.2%** |
| Precision | 3.5% |
| F1 | 3.8% |
| TP / FP / FN | 5 / 138 / 115 |
| Total GT vulns | 120 across 40 tasks |

> This run used the Claude API (no longer available). Retained as a historical baseline.
> Current analysis path uses AMPatternDetector + BytecodeGNN (LLM-free, `--bytecode` flag).

### GNN vs Slither (2026-02-13)

| Metric | Value |
|---|---|
| Speed advantage | 794× faster than Slither |
| Throughput | ~100,000 contracts/minute |
| Hybrid F1 | 0.817 |
| Hybrid Recall | 1.000 |

---

## Research Basis

Full summaries: `docs/research/RESEARCH_SYNTHESIS_SKANF.md`

| Paper / Source | Adopted in |
|---|---|
| SKANF (IC3/Yale, arXiv:2504.13398, 2025) | `cfg_deobfuscator.py`, `taint_analyzer.py`, `exploit_validator.py`, `skanf_sensitive.py` (exact address/selector constants from Docker image), `txn_analyzer.py`, `AMPatternDetector` |
| MAD (CMU/Mysten, 2025) | `decompiler.py` panoramix + reflection fallback |
| ReDetect (Sichuan, 2025) | GNN→Slither validation loop (`hybrid_analyzer.py`) |
| LLMSmartSec (IEEE, 2024) | CFG annotation approach (informing bytecode graph design) |
| NyxLLM 2.0 (Ruhr, 2025) | ICL retrieval concept (informing `BytecodeGraphBuilder` feature design) |
| RAG-LLM (SF State, 2024) | Vector retrieval concept (background) |
| TAC+LLM decompilation (arXiv:2506.19624, 2025) | Future direction: SKANF deobfuscation → TAC → fine-tuned LLM → human-readable Solidity. Author endorsed combining with Calyx's CFG deobfuscation (Discord 2026-03-18). |
| SoK DeFi Attacks (Liyi Zhou et al., IEEE S&P 2023, arXiv:2208.13035) | `similarity_scanner.py` (n-gram Jaccard, 80% threshold); AM6/AM7/AM8 taxonomy extensions; 56% non-atomic attack finding motivates Stage 9 |
| LookAhead (FSE 2025) | `AdversarialClassifier` signal weights and thresholds (F1=0.8966 baseline; Calyx adds deobfuscation advantage) |
| FinDet (2025, arXiv:2509.18934) | BAC=0.9374 stretch target for `AdversarialClassifier` |
| SKANF author Discord Q&A (Sen Yang, Mar 2026) | Failure-reason codes confirmed as Calyx-only innovation; AI agent direction explicitly endorsed; Alchemy confirmed as archive RPC; Clara dataset recommended for testing. |

---

## Author-Endorsed Future Directions

From Sen Yang (SKANF author) Discord Q&A, March 2026:

**1. Extend SKANF to other analysis tools**
> "Can we also apply the idea of SKANF into other existing analysis tools? For example, Mythril and another famous Rust-based EVM-aided smart contract [tool]."
- Candidate tools: Mythril, Manticore, Slither (bytecode mode)
- Calyx bridge: `CFGDeobfuscator` output could be fed directly into Mythril's CFG input

**2. SKANF + AI agents**
> "It would be especially interesting to see whether such extensions help AI agents solve problems that they were previously unable to solve."
- Calyx Stage 8 (`AuditAgent`) is the direct answer: SKANF pipeline packages obfuscated-contract analysis as LLM-ready context
- Validated by Dedaub (2026-03-11): AI-powered decompilation still fails on obfuscated contracts — SKANF deobfuscation remains necessary pre-processing

**3. TAC intermediate representation for LLM training**
> "For obfuscated contract code, can we provide source code, or at least a human-readable representation, that models can learn from? SKANF can provide better control-flow information, but making that information readable still needs more exploration."
- Paper: arXiv:2506.19624 — bytecode → TAC → fine-tuned LLaMA 3.2 → Solidity
- Extension: apply Calyx's `CFGDeobfuscator` (Gap 1) before the TAC lifting step

**4. Beyond MEV bots**
> "In our paper, we use MEV bots as one example, but it would be interesting to see whether the same approach can be applied to other targets as well."
- Near-term: DeFi protocols, bridge contracts, factory-deployed proxies

---

## External Attack Datasets

| Dataset | Source | Size | Use for Calyx |
|---|---|---|---|
| SKANF MEV bot corpus | Google Drive artifact (private repos) | 6,554 MEV bots, 1,030 vulnerable | Ground truth for bytecode pipeline tuning |
| Clara | [clarahacks.com](https://clarahacks.com) | 300+ incidents (growing ~1.5/day as of Mar 2026) | Live DeFi exploit feed; contract addresses for `demo_pipeline.py` |
| Rekt | rekt.news | 281 historical exploits | Used in CalyxGNN training dataset |
| DeFi Attacks SoK | arXiv:2208.13035 (Liyi Zhou, IEEE S&P) | Systematic taxonomy | Classification framework background |
