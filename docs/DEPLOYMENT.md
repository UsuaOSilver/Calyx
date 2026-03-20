# Deployment Guide

## Quick Start (Local)

```bash
git clone https://github.com/UsuaOSilver/Calyx
cd calyx
pip install -r requirements.txt
cp .env.example .env
# Fill in ETHERSCAN_API_KEY (required for address mode)
# Fill in one LLM key for --audit (GEMINI_API_KEY is free)

python scripts/demo_pipeline.py \
  --address 0x00000000003b3cc22af3ae1eac0440bcee416b40 \
  --audit
```

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ETHERSCAN_API_KEY` | Yes for address mode | Bytecode fetch + txn history |
| `ETHEREUM_RPC_URL` | No | Stage 7 fork-EVM validation |
| `ANTHROPIC_API_KEY` | No (one LLM key for --audit) | Claude audit agent |
| `GEMINI_API_KEY` | No | Gemini 2.0 Flash (free tier) |
| `GROQ_API_KEY` | No | Groq/Llama (free tier) |
| `OPENAI_API_KEY` | No | GPT-4o |

`ETHEREUM_RPC_URL` is optional. Stage 7 is silently skipped when unset.

## RPC Providers for Stage 7 (--validate)

| Provider | Free plan | Archive node |
|---|---|---|
| Alchemy (recommended) | 300M CU/month | Yes |
| Infura | 100k req/day | Paid only |
| Self-hosted Reth | — | Yes |

The SKANF author confirmed (Discord 2026-03-10) that Alchemy works as a
drop-in alternative to a self-hosted Reth archive node.

## Docker

```bash
docker build -t calyx .
docker run \
  -e ETHERSCAN_API_KEY=your_key \
  -e GEMINI_API_KEY=your_key \
  calyx \
  python scripts/demo_pipeline.py \
    --address 0x00000000003b3cc22af3ae1eac0440bcee416b40 --audit
```

## API Server

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
# POST /analyze/address  {"address": "0x...", "network": "ethereum", "audit": true}
# POST /analyze/bytecode {"bytecode": "0x608060...", "audit": false}
# GET  /health
```

## AWS / Kubernetes / Railway

See full production deployment examples (ECS, k8s manifests, Railway CLI)
in the project README at https://github.com/UsuaOSilver/Calyx.
