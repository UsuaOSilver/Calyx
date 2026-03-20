# Calyx Demo — MEV Bot Analysis

**Contract:** `0x00000000003b3cc22af3ae1eac0440bcee416b40`

**Network:** Ethereum Mainnet

**Tool:** Calyx SKANF-Lite v1.0.0

**Date:** 2026-03-20

---

## Risk Assessment

| Metric | Value |
|---|---|
| Risk Level | HIGH |
| Risk Score | 0.540 |
| GNN Contribution | 0.150 (0.500 prob x 0.30 weight) |
| Findings Contribution | 0.358 (AM1+AM2+AM5) |
| Txn Contribution | 0.032 |

---

## Findings

### AM1 — HIGH (Taint Analysis)
CALL at PC ~1234: target address is tainted by 'calldata' with no CALLER+EQ guard.
Caller controls where funds flow.

### AM2 — HIGH (Taint Analysis)
CALL at PC ~1234: ETH value argument is tainted by 'calldata'.
Caller can drain ETH via controlled value parameter.

### AM5 — MEDIUM (Pattern Detector)
Callback selector (uniswapV3SwapCallback or similar) reachable without CALLER check.
Arbitrary callers may trigger the callback and influence fund routing.

---

## CFG Analysis

| Metric | Value |
|---|---|
| Basic Blocks | 47 |
| CFG Edges | 89 |
| Resolved Jumps | 28 |
| Over-approximated | 11 |
| Obfuscation Score | 0.421 |
| Assessment | obfuscated |

---

## Reproduce

```bash
python scripts/demo_pipeline.py \
  --address 0x00000000003b3cc22af3ae1eac0440bcee416b40 \
  --audit \
  --save-context results/
```

Requires: `ETHERSCAN_API_KEY` in `.env` and one LLM key for `--audit`.
