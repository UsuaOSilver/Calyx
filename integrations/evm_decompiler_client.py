"""
integrations/evm_decompiler_client.py

EVMDecompilerClient -- Optional external decompiler integration (T3).

Wraps external EVM decompilation services (Dedaub, Panoramix, or any
compatible REST API) as an optional Stage 3b in the bytecode pipeline.
Falls back gracefully when DECOMPILER_API_KEY is absent.

Motivation: TAC+LLM paper (arXiv:2506.19624) + Sen Yang endorsement:
"SKANF can provide better control-flow information, but making that
information readable still needs more exploration."

Configure in .env:
  DECOMPILER_API_KEY=...   (optional)
  DECOMPILER_API_URL=...   (default: Dedaub-compatible endpoint)
  DECOMPILER_TIMEOUT=30

Usage:
    from integrations.evm_decompiler_client import EVMDecompilerClient
    client = EVMDecompilerClient()
    result = client.decompile(bytecode_hex)
    # result["available"], ["source"], ["provider"], ["confidence"], ["error"]
"""

from __future__ import annotations
import os
from typing import Any, Dict, Optional

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

_DEFAULT_TIMEOUT = 30
_DEFAULT_URL = "https://api.dedaub.com/api/decompile"


class EVMDecompilerClient:
    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None,
                 timeout: int = _DEFAULT_TIMEOUT, provider: str = "dedaub") -> None:
        self._api_key  = api_key  or os.environ.get("DECOMPILER_API_KEY", "")
        self._api_url  = api_url  or os.environ.get("DECOMPILER_API_URL", _DEFAULT_URL)
        self._timeout  = int(os.environ.get("DECOMPILER_TIMEOUT", timeout))
        self._provider = provider

    @property
    def available(self) -> bool:
        return bool(self._api_key) and _REQUESTS_AVAILABLE

    def decompile(self, bytecode_hex: str) -> Dict[str, Any]:
        if not self.available:
            reason = "requests not installed" if not _REQUESTS_AVAILABLE else "no API key configured"
            return self._unavailable(reason)
        hex_str = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
        if not hex_str.strip():
            return self._unavailable("empty bytecode")
        try:
            return self._call_api(hex_str)
        except Exception as exc:
            return {"available": True, "source": None, "provider": self._provider,
                    "confidence": 0.0, "raw": None, "error": f"{type(exc).__name__}: {exc}"}

    def _call_api(self, hex_str: str) -> Dict[str, Any]:
        resp = _requests.post(
            self._api_url,
            json={"bytecode": hex_str, "optimization": True},
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            timeout=self._timeout,
        )
        if resp.status_code == 401:
            return self._unavailable("unauthorized (check DECOMPILER_API_KEY)")
        if resp.status_code == 429:
            return self._unavailable("rate limited -- retry later")
        resp.raise_for_status()
        return self._parse_response(resp.json())

    def _parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        source = data.get("source") or data.get("decompiled") or data.get("code")
        return {"available": True, "source": source, "provider": self._provider,
                "confidence": round(float(data.get("confidence", 0.5)), 3),
                "raw": data, "error": None if source else "provider returned no source"}

    def _unavailable(self, reason: str) -> Dict[str, Any]:
        return {"available": False, "source": None, "provider": self._provider,
                "confidence": 0.0, "raw": None, "error": reason}
