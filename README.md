# Calyx

Exploring bytecode-level security analysis for closed-source EVM contracts.

---

## The Problem

Most EVM security tools — Slither, Mythril, Manticore, LLM auditors — assume
Solidity source is available. But the contracts attackers target most are exactly
the ones *without* source: MEV bots, obfuscated DeFi protocols, factory-deployed
contracts. For these, every existing tool produces zero output.

## The Approach

Reading: **SKANF** (Sen Yang, IC3/Yale, 2025, arXiv:2504.13398) — the first paper
that directly analyzes obfuscated EVM bytecode for exploitable patterns without
requiring source code.

Core ideas from the paper:
- Recover a complete control-flow graph from raw bytecode (even with indirect jumps)
- Track attacker-controlled values (calldata, ETH value) through the EVM stack to CALL sinks
- Confirm exploitability against a live mainnet fork

Three concrete gaps the paper addresses:
- **Gap 1**: Resolving indirect JUMP targets to build a complete CFG
- **Gap 2**: Static taint analysis to detect when the attacker controls fund flows
- **Gap 3**: Fork-EVM proof-of-exploit to confirm a real vulnerability

Goal: implement these gaps and extend with an LLM audit layer.

## Status

Work in progress — setting up project structure.

## License

MIT
