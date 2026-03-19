# Calyx

**Bytecode security analysis for closed-source EVM contracts** — no Solidity source required.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> Built for the IC3 / Shape Rotator Accelerator Hackathon, 2026.

---

## The Problem

MEV bots, obfuscated DeFi protocols, and factory-deployed contracts hold
billions in value and are invisible to every existing security tool such as Slither,
Mythril, Manticore, and all LLM-based auditors require Solidity source code.

## How It Works

Implementing the three core gaps from the SKANF paper (Sen Yang, IC3/Yale 2025):

    Stage 0:  Fetch raw bytecode (Etherscan V2 API, 5 networks)
    Stage 3a: CFG deobfuscation — resolve indirect JUMP targets          [Gap 1]
    Stage 3b: CFG profiling — obfuscation score
    Stage 4:  Transaction anomaly detection — historical on-chain evidence
    Stage 5a: Static taint analysis — AM1/AM2 (Gap 2) + AM6 oracle taint + AM8 delegatecall
    Stage 5b: Pattern detector — AM3–AM8 heuristics (SoK DeFi Attacks arXiv:2208.13035)
    Stage 5d: Similarity scanner — n-gram Jaccard vs. exploit corpus (SoK S1)
    Stage 5c: Bytecode GNN — CFG graph neural network scoring
    Stage 6:  Risk scorer — 0.30×GNN + 0.55×findings + 0.15×txn
    Stage 7:  Fork-EVM exploit validation via Anvil                       [Gap 3]
    Stage 8:  LLM audit agent — human-readable security report (optional)

Stage numbering follows the SKANF paper's pipeline. Stages 1–2 (decompilation
and concolic pre-processing) are out of scope — bytecode analysis starts at 3.
Stage 5 splits into three independent detectors (5a/5b/5c) rather than one.

## Quick Start

    pip install -r requirements.txt
    cp .env.example .env
    # Add ETHERSCAN_API_KEY and one LLM key (GEMINI_API_KEY is free)

    python scripts/demo_pipeline.py \
      --address 0x00000000003b3cc22af3ae1eac0440bcee416b40 \
      --audit

## License

MIT
