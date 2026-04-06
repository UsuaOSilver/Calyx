"""
Calyx API Server

Exposes BytecodePipeline over HTTP via FastAPI.

Endpoints:
  GET  /health          — liveness check
  GET  /stats           — analysis counters
  POST /analyze         — analyze by address or raw bytecode
  POST /analyze/address — analyze by contract address (convenience alias)

Usage:
  uvicorn api.server:app --host 0.0.0.0 --port 8000
"""

import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

log = logging.getLogger(__name__)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="Calyx API",
    description="Bytecode-level EVM smart contract security analysis — LLM-free core, optional AI audit.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if CORS_ORIGINS == ["*"] else CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATS: Dict[str, Any] = {
    "total_analyzed": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "uptime_start": datetime.utcnow().isoformat() + "Z",
}

# Lazy-loaded pipeline — instantiated on first request to avoid blocking startup
_pipeline = None


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        from analysis.bytecode_pipeline import BytecodePipeline
        _pipeline = BytecodePipeline()
        log.info("BytecodePipeline initialized")
    return _pipeline


# ── Request / response models ─────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    address:  Optional[str] = Field(None, description="Contract address (0x…). Requires ETHERSCAN_API_KEY.")
    bytecode: Optional[str] = Field(None, description="Raw bytecode hex (0x…). No API key needed.")
    network:  str           = Field("ethereum", description="Chain name (ethereum, polygon, bsc, …)")
    validate: bool          = Field(False, description="Run fork-EVM exploit confirmation (needs Anvil + ETHEREUM_RPC_URL)")
    audit:    bool          = Field(False, description="Run AI audit report via LLM (needs one LLM API key)")


class AddressRequest(BaseModel):
    address:  str  = Field(..., description="Contract address (0x…)")
    network:  str  = Field("ethereum")
    validate: bool = Field(False)
    audit:    bool = Field(False)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status":   "healthy",
        "pipeline": "BytecodePipeline",
        "uptime":   _STATS["uptime_start"],
        "version":  "1.0.0",
    }


@app.get("/stats")
async def stats():
    total = _STATS["total_analyzed"]
    return {
        **_STATS,
        "critical_rate": _STATS["critical"] / max(total, 1),
    }


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    """
    Analyze a smart contract by address or raw bytecode.

    Provide exactly one of `address` or `bytecode`.
    """
    if not req.address and not req.bytecode:
        raise HTTPException(status_code=400, detail="Provide either 'address' or 'bytecode'.")
    if req.address and req.bytecode:
        raise HTTPException(status_code=400, detail="Provide only one of 'address' or 'bytecode', not both.")

    t0 = time.time()
    pipeline = _get_pipeline()

    try:
        if req.address:
            result = pipeline.analyze_address(
                req.address,
                network=req.network,
                validate=req.validate,
                audit=req.audit,
            )
        else:
            result = pipeline.analyze_bytecode(
                req.bytecode,
                network=req.network,
                validate=req.validate,
                audit=req.audit,
            )
    except Exception as exc:
        log.error("Pipeline error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    elapsed = round(time.time() - t0, 3)
    result["elapsed_seconds"] = elapsed

    # Update stats
    _STATS["total_analyzed"] += 1
    level = result.get("risk_level", "UNKNOWN").lower()
    if level in _STATS:
        _STATS[level] += 1

    return result


@app.post("/analyze/address")
async def analyze_address(req: AddressRequest):
    """Convenience alias — analyze by contract address."""
    return await analyze(
        AnalyzeRequest(
            address=req.address,
            network=req.network,
            validate=req.validate,
            audit=req.audit,
        )
    )


@app.get("/")
async def root():
    return {
        "name":      "Calyx API",
        "version":   "1.0.0",
        "docs":      "/docs",
        "endpoints": {
            "health":          "GET  /health",
            "stats":           "GET  /stats",
            "analyze":         "POST /analyze",
            "analyze_address": "POST /analyze/address",
        },
    }
