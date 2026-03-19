"""
tests/conftest.py

Shared pytest configuration: custom markers and fixtures used across the suite.
"""

from __future__ import annotations

import os
import pytest


# ---------------------------------------------------------------------------
# Custom markers
# ---------------------------------------------------------------------------


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: tests that hit live external APIs (Etherscan, Alchemy RPC). "
        "Skipped when ETHERSCAN_API_KEY is not set.",
    )
    config.addinivalue_line(
        "markers",
        "requires_anvil: tests that start a real Anvil (fork-EVM) process. "
        "Skipped when ETHEREUM_RPC_URL is not set or anvil is not on PATH.",
    )


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


def _has_etherscan_key() -> bool:
    return bool(os.environ.get("ETHERSCAN_API_KEY"))


def _has_rpc_url() -> bool:
    return bool(os.environ.get("ETHEREUM_RPC_URL"))


def _has_anvil() -> bool:
    import subprocess
    try:
        r = subprocess.run(
            ["anvil", "--version"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Apply skip logic at collection time so reasons appear in -v output
def pytest_collection_modifyitems(config, items):
    skip_integration = pytest.mark.skip(
        reason="Set ETHERSCAN_API_KEY to run integration tests"
    )
    skip_anvil = pytest.mark.skip(
        reason="Set ETHEREUM_RPC_URL and install Anvil (foundry) to run anvil tests"
    )
    for item in items:
        if "integration" in item.keywords and not _has_etherscan_key():
            item.add_marker(skip_integration)
        if "requires_anvil" in item.keywords and (
            not _has_rpc_url() or not _has_anvil()
        ):
            item.add_marker(skip_anvil)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def known_mev_bot_address() -> str:
    """Known MEV bot with documented AM1/AM2/AM5 patterns."""
    return "0x00000000003b3cc22af3ae1eac0440bcee416b40"


@pytest.fixture(scope="session")
def known_clean_address() -> str:
    """Canonical USDC contract — no exploit patterns expected."""
    return "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


@pytest.fixture(scope="session")
def sample_am1_finding() -> dict:
    return {
        "type": "AM1",
        "severity": "high",
        "pc": 0,
        "description": "Calldata-controlled CALL target",
        "taint_source": "calldata",
    }


@pytest.fixture(scope="session")
def sample_am2_finding() -> dict:
    return {
        "type": "AM2",
        "severity": "high",
        "pc": 4,
        "description": "Calldata-controlled ETH value",
        "taint_source": "calldata",
    }


@pytest.fixture(scope="session")
def sample_pipeline_result() -> dict:
    """Realistic pipeline output fixture for downstream consumer tests."""
    return {
        "risk_score": 0.72,
        "risk_level": "HIGH",
        "am_findings": [
            {
                "type": "AM1",
                "severity": "high",
                "pc": 0,
                "description": "Calldata-controlled CALL target",
                "taint_source": "calldata",
            }
        ],
        "am_types_found": ["AM1"],
        "confirmed_exploits": [],
        "error": None,
        "cfg_deob": {
            "resolved": 3,
            "approximated": 1,
            "block_count": 4,
            "edge_count": 5,
        },
        "obfuscation_score": 0.25,
        "gnn_score": 0.5,
        "transactions": [],
    }
