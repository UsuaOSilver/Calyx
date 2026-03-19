# Calyx

**AI-Powered Security Auditor for Closed-Source EVM Contracts**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> Built for the IC3 / Shape Rotator Accelerator Hackathon, 2026.

---

## The Problem

**$100B+ is locked in unverified EVM contracts that no existing security tool can analyze.**

Slither, Mythril, Manticore, and every LLM-based auditor share one fatal assumption:
Solidity source code is available. For closed-source contracts, MEV bots, obfuscated
DeFi protocols, deployed-and-deleted factories, these tools produce zero output.

The consequence is a massive blind spot. Attackers target exactly these unverified contracts
because defenders have no tools. A single MEV bot with an exploitable CALL routing bug
can lose $600k in a single transaction. No auditor sees it coming.

## The Solution

Calyx implements **SKANF-style bytecode analysis** (Sen Yang, IC3/Yale 2025,
arXiv:2504.13398) extended with an **LLM audit agent** that produces human-readable
security reports on contracts that no other tool can touch.

No source code required. No decompiler required. Pure bytecode in, security report out.

## Pipeline (8 stages)

    Stage 0:  Bytecode fetch (Etherscan V2 API, 5 networks)
    Stage 3a: CFG deobfuscation - resolve indirect JUMP targets (SKANF Gap 1)
    Stage 3b: CFG profiling - obfuscation score
    Stage 4:  Transaction anomaly analysis - historical on-chain evidence
    Stage 5a: Static taint analysis - AM1/AM2 detection (SKANF Gap 2)
    Stage 5b: AM pattern detector - AM3/AM4/AM5 heuristic detection
    Stage 5c: Bytecode GNN - CFG graph neural network exploit scoring
    Stage 6:  Risk scorer - 3-signal weighted combination
    Stage 7:  Fork-EVM exploit validation via Anvil (SKANF Gap 3)
    Stage 8:  LLM audit agent - human-readable security report

## Research Basis

Built on **SKANF** (Sen Yang, IC3/Yale, arXiv:2504.13398):
- Gap 1: CFG deobfuscation via indirect jump resolution
- Gap 2: Static taint tracking (calldata to CALL sinks)
- Gap 3: Fork-EVM proof-of-exploit via Anvil

## Quick Start

    pip install -r requirements.txt
    cp .env.example .env
    # Add ETHERSCAN_API_KEY + one LLM key (GEMINI_API_KEY is free)

    python scripts/demo_pipeline.py \
      --address 0x00000000003b3cc22af3ae1eac0440bcee416b40 \
      --audit

## License

MIT
