# System Architecture

## Pipeline Overview

```
INPUT: Contract address or raw bytecode hex
           |
           v
Stage 0:  Etherscan V2 API -> raw bytecode hex
Stage 3a: CFGDeobfuscator  -> complete CFG (constant-fold + over-approx)  [SKANF Gap 1]
Stage 3b: CFGProfiler      -> obfuscation_score + split_by_selector() [T2]
Stage 3c: EVMDecompilerClient -> optional Solidity approximation [T3, skipped if no key]
Stage 4:  TxnAnalyzer      -> anomaly_score from historical transactions
Stage 5a: TaintAnalyzer    -> AM1/AM2 (Gap 2) + AM6 oracle taint + AM8 delegatecall [SoK]
Stage 5b: AMPatternDetector-> AM3–AM8 heuristic findings [SoK arXiv:2208.13035]
Stage 5c: BytecodeGNNAnalyzer -> exploit_probability from CFG graph
Stage 5d: SimilarityScanner -> n-gram Jaccard vs. exploit corpus [SoK S1]
Stage 6:  RiskScorer       -> unified risk_score [0,1] + risk_level
Stage 7:  ExploitValidator -> fork-EVM proof-of-exploit via Anvil         [SKANF Gap 3]
Stage 7b: ContextBuilder   -> TAC-style CFG summary + LLM-ready context [T1, arXiv:2506.19624]
Stage 8:  AuditAgent       -> LLM security report (optional)
           |
           v
OUTPUT: risk_level (CRITICAL/HIGH/MEDIUM/LOW), am_findings, audit_report
```

## Research Basis

Built on **SKANF** (Sen Yang, IC3/Yale, arXiv:2504.13398):
- Gap 1: CFG deobfuscation — `detectors/bytecode_analyzer/cfg_deobfuscator.py`
- Gap 2: Static taint analysis — `detectors/bytecode_analyzer/taint_analyzer.py`
- Gap 3: Fork-EVM exploit validation — `detectors/bytecode_analyzer/exploit_validator.py`
- SKANF constants: exact 50 ETH + 50 BSC DeFi addresses, 3 ERC-20 selectors — `detectors/bytecode_analyzer/skanf_sensitive.py`

## Calyx vs Full SKANF

| Capability | Full SKANF | Calyx |
|---|---|---|
| CFG deobfuscation | branch table injection | constant-fold + over-approximation |
| Taint analysis | SMT solver (Yices2 via Greed) | linear stack simulation |
| Exploit generation | ethpwn + fork-EVM | Anvil fork-EVM |
| ERC-20 calldata | aeg.py | erc20_calldata() — exact match |
| Structured failure log | not included | 7 machine-readable reason codes |
| LLM auditing | not included | Stage 8 — AuditAgent (4 providers) |
| Attack model coverage | AM1–AM5 | AM1–AM8 (AM6/AM7/AM8 from SoK DeFi Attacks arXiv:2208.13035) |
| Bytecode similarity | not included | SimilarityScanner — n-gram Jaccard vs. exploit corpus |
| Function-level analysis | not included | split_by_selector() — per-function vulnerability attribution |
| TAC-style context | not included | ContextBuilder._section_tac_summary() (arXiv:2506.19624) |
| Decompiler integration | not included | EVMDecompilerClient — optional, graceful fallback |

## Risk Scorer Formula

```
risk_score = 0.30 x gnn_score
           + 0.55 x findings_sub
           + 0.15 x txn_anomaly_score

findings_sub = min(1.0, sum of severity_weights)
  HIGH=0.25   MEDIUM=0.10   LOW=0.03
  confirmed_bonus=+0.10 per Anvil-validated finding

CRITICAL >= 0.75   HIGH >= 0.50   MEDIUM >= 0.25   LOW >= 0.0
```

## File Map

| Stage | File | Description |
|---|---|---|
| 0 | `integrations/etherscan_client.py` | V2 bytecode fetch, txn list |
| 3a | `detectors/bytecode_analyzer/cfg_deobfuscator.py` | Gap 1 |
| 3b | `detectors/bytecode_analyzer/cfg_profiler.py` | Obfuscation score |
| 4 | `detectors/bytecode_analyzer/txn_analyzer.py` | Anomaly flags |
| 3c | `integrations/evm_decompiler_client.py` | Optional decompiler (T3); skipped if no key |
| 5a | `detectors/bytecode_analyzer/taint_analyzer.py` | Gap 2: AM1/AM2 + AM6 oracle + AM8 delegatecall |
| 5b | `detectors/bytecode_analyzer/cfg_profiler.AMPatternDetector` | AM3–AM8 heuristics (SoK) |
| 5c | `detectors/gnn_analyzer/bytecode_analyzer.py` | GNN inference |
| 5d | `detectors/bytecode_analyzer/similarity_scanner.py` | n-gram Jaccard exploit similarity (SoK S1) |
| 6 | `detectors/risk_scorer/scorer.py` | Weighted score |
| 7 | `detectors/bytecode_analyzer/exploit_validator.py` | Gap 3, Anvil |
| 7b | `analysis/context_builder.py` | TAC summary + LLM-ready context (T1, arXiv:2506.19624) |
| 8 | `analysis/audit_agent.py` | LLM audit |
| - | `analysis/bytecode_pipeline.py` | Orchestrator |
| - | `analysis/txn_guided_taint.py` | P1: evidence correlation |
| - | `scripts/demo_pipeline.py` | P3: demo CLI |
