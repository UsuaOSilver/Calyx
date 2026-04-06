"""
data/collectors/real_bytecode_collector.py

Collects real on-chain contract bytecode, builds CFG graphs, and writes
labeled JSONL files to data/datasets/real_bytecode/.

Two address sources:
  1. Hardcoded benign contracts (well-known mainnet DeFi protocols, label=0)
  2. data/collectors/exploit_addresses.csv  (label=1, you populate from
     DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs)

CSV format (one row per contract):
    address,network,incident,category
    0x1234...,ethereum,Euler Finance 2023,flash-loan

Pipeline:
  EtherscanClient.get_bytecode()  →  BytecodeGraphBuilder.build_graph()
  →  data/datasets/real_bytecode/{train,val,test}.jsonl

Cache:
  Fetched bytecode is cached at data/collectors/bytecode_cache.jsonl so
  interrupted runs can resume without re-fetching.

Usage:
    cd /root/Calyx-dev && source venv/bin/activate
    export ETHERSCAN_API_KEY=<your_key>
    PYTHONPATH=. python data/collectors/real_bytecode_collector.py
    # Merge with synthetic dataset afterwards:
    PYTHONPATH=. python data/collectors/real_bytecode_collector.py --merge-synthetic
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(_REPO_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(_REPO_ROOT / ".env")
except ImportError:
    pass

from integrations.etherscan_client import EtherscanClient
from models.gnn.bytecode_graph_builder import BytecodeGraphBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("calyx.collector")

# ── Output paths ──────────────────────────────────────────────────────────────

OUT_DIR    = _REPO_ROOT / "data" / "datasets" / "real_bytecode"
CACHE_FILE = _REPO_ROOT / "data" / "collectors" / "bytecode_cache.jsonl"
CSV_FILE         = _REPO_ROOT / "data" / "collectors" / "exploit_addresses.csv"
CSV_FILE_SCRAPED = _REPO_ROOT / "data" / "collectors" / "exploit_addresses_scraped.csv"
BENIGN_CSV       = _REPO_ROOT / "data" / "collectors" / "benign_contracts.csv"
SYNTH_DIR  = _REPO_ROOT / "data" / "datasets" / "bytecode"

# ── Hardcoded benign contracts (label=0) ──────────────────────────────────────
# Well-known, verified mainnet DeFi protocol contracts.
# All are widely cited in public documentation and audits.

BENIGN_CONTRACTS = [
    # ── Stablecoins ───────────────────────────────────────────────────────────
    {"address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "USDC"},
    {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "USDT"},
    {"address": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "DAI"},
    {"address": "0x853d955aCEf822Db058eb8505911ED77F175b99e", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "FRAX"},
    {"address": "0x5f98805A4E8be255a32880FDeC7F6728C6568bA0", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "LUSD"},
    {"address": "0x4Fabb145d64652a948d72533023f6E7A623C7C53", "network": "ethereum", "category": "erc20-stablecoin",  "incident": "BUSD"},
    # ── Wrapped / ETH derivatives ─────────────────────────────────────────────
    {"address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "network": "ethereum", "category": "erc20-wrapped",    "incident": "WETH"},
    {"address": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "network": "ethereum", "category": "erc20-wrapped",    "incident": "WBTC"},
    {"address": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "network": "ethereum", "category": "liquid-staking",    "incident": "stETH-Lido"},
    {"address": "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", "network": "ethereum", "category": "liquid-staking",    "incident": "wstETH-Lido"},
    {"address": "0xae78736Cd615f374D3085123A210448E74Fc6393", "network": "ethereum", "category": "liquid-staking",    "incident": "rETH-RocketPool"},
    {"address": "0x5E8422345238F34275888049021821E8E08CAa1f", "network": "ethereum", "category": "liquid-staking",    "incident": "frxETH-Frax"},
    {"address": "0xac3E018457B222d93114458476f3E3416Abbe38F", "network": "ethereum", "category": "liquid-staking",    "incident": "sfrxETH-Frax"},
    # ── Uniswap ───────────────────────────────────────────────────────────────
    {"address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "network": "ethereum", "category": "dex-router",       "incident": "UniswapV2Router02"},
    {"address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "network": "ethereum", "category": "dex-factory",      "incident": "UniswapV2Factory"},
    {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "network": "ethereum", "category": "dex-factory",      "incident": "UniswapV3Factory"},
    {"address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "network": "ethereum", "category": "dex-router",       "incident": "UniswapV3Router"},
    {"address": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "network": "ethereum", "category": "dex-router",       "incident": "UniswapV3SwapRouter02"},
    {"address": "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "network": "ethereum", "category": "dex-positions",    "incident": "UniswapV3NonfungiblePositionManager"},
    # ── Curve ─────────────────────────────────────────────────────────────────
    {"address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "network": "ethereum", "category": "dex-pool",         "incident": "Curve3Pool"},
    {"address": "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46", "network": "ethereum", "category": "dex-pool",         "incident": "CurveTriCrypto2"},
    {"address": "0xD533a949740bb3306d119CC777fa900bA034cd52", "network": "ethereum", "category": "erc20-governance",  "incident": "CRV-Token"},
    {"address": "0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB", "network": "ethereum", "category": "governance",        "incident": "CurveGaugeController"},
    # ── Balancer ──────────────────────────────────────────────────────────────
    {"address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8", "network": "ethereum", "category": "dex-vault",         "incident": "BalancerV2Vault"},
    {"address": "0xba100000625a3754423978a60c9317c58a424e3D", "network": "ethereum", "category": "erc20-governance",  "incident": "BAL-Token"},
    # ── 1inch ─────────────────────────────────────────────────────────────────
    {"address": "0x1111111254EEB25477B68fb85Ed929f73A960582", "network": "ethereum", "category": "dex-aggregator",    "incident": "1inchV5"},
    # ── Aave ──────────────────────────────────────────────────────────────────
    {"address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "network": "ethereum", "category": "lending-pool",     "incident": "AaveV2LendingPool"},
    {"address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "network": "ethereum", "category": "lending-pool",     "incident": "AaveV3Pool"},
    {"address": "0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9E", "network": "ethereum", "category": "lending-infra",    "incident": "AaveV3AddressesProvider"},
    # ── Compound ──────────────────────────────────────────────────────────────
    {"address": "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643", "network": "ethereum", "category": "lending-ctoken",   "incident": "CompoundcDAI"},
    {"address": "0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5", "network": "ethereum", "category": "lending-ctoken",   "incident": "CompoundcETH"},
    {"address": "0xc3d688B66703497DAA19211EEdff47f25384cdc3", "network": "ethereum", "category": "lending-pool",     "incident": "CompoundV3cUSDC"},
    {"address": "0xc00e94Cb662C3520282E6f5717214004A7f26888", "network": "ethereum", "category": "erc20-governance",  "incident": "COMP-Token"},
    # ── MakerDAO / Sky ────────────────────────────────────────────────────────
    {"address": "0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B", "network": "ethereum", "category": "cdp-manager",      "incident": "MakerDAOVat"},
    {"address": "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", "network": "ethereum", "category": "erc20-governance",  "incident": "MakerMKR"},
    {"address": "0x19c0976f590D67707E62397C87829d896Dc0f1F", "network": "ethereum", "category": "cdp-manager",       "incident": "MakerDAOJug"},
    {"address": "0x197E90f9FAD81970bA7976f33CbD77088E5D7cf7", "network": "ethereum", "category": "cdp-manager",       "incident": "MakerDAOPot"},
    # ── Liquity ───────────────────────────────────────────────────────────────
    {"address": "0x24179CD81c9e782A4096035f7eC97fB8B783e007", "network": "ethereum", "category": "cdp-manager",       "incident": "LiquityBorrowerOps"},
    {"address": "0xA39739EF8b0231DbFA0DcdA07d7e29faAbCf4bb2", "network": "ethereum", "category": "cdp-manager",       "incident": "LiquityTroveManager"},
    {"address": "0x66017D22b0f8556afDd19FC67041899Eb65a21bb", "network": "ethereum", "category": "stability-pool",    "incident": "LiquityStabilityPool"},
    {"address": "0x6DEA81C8171D0bA574754EF6F8b412F2Ed88c54D", "network": "ethereum", "category": "erc20-governance",  "incident": "LQTY-Token"},
    # ── Convex Finance ────────────────────────────────────────────────────────
    {"address": "0xF403C135812408BFbE8713b5A23a04b3D48AAE31", "network": "ethereum", "category": "yield-booster",     "incident": "ConvexBooster"},
    {"address": "0x62B9c7356A2Dc64a1969e19C23e4f579F9810Aa7", "network": "ethereum", "category": "erc20-governance",  "incident": "cvxCRV-Token"},
    {"address": "0x72a19342e8F1838460eBFCCEf09F6585e32db86E", "network": "ethereum", "category": "yield-locker",      "incident": "ConvexCRVLocker"},
    # ── Yearn Finance ─────────────────────────────────────────────────────────
    {"address": "0xdA816459F1AB5631232FE5e97a05BBBb94970c95", "network": "ethereum", "category": "yield-vault",       "incident": "YearnDAIVaultV2"},
    {"address": "0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE", "network": "ethereum", "category": "yield-vault",       "incident": "YearnUSDCVaultV2"},
    {"address": "0xa258C4606Ca8206D8aA700cE2143D7db854D168c", "network": "ethereum", "category": "yield-vault",       "incident": "YearnWETHVaultV2"},
    {"address": "0x50c1a2eA0a861A967D9d0FFE2AE4012c2E053804", "network": "ethereum", "category": "yield-registry",    "incident": "YearnRegistry"},
    # ── Frax Finance ──────────────────────────────────────────────────────────
    {"address": "0x3432B6A60D23Ca0dFCa7761B7ab56459D9C964D0", "network": "ethereum", "category": "erc20-governance",  "incident": "FXS-Token"},
    {"address": "0xDD3f50F8A6CafbE9b31a427582963f465E745AF8", "network": "ethereum", "category": "liquid-staking",    "incident": "RocketPoolDeposit"},
    # ── Synthetix ─────────────────────────────────────────────────────────────
    {"address": "0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F", "network": "ethereum", "category": "erc20-governance",  "incident": "SNX-Token"},
    {"address": "0x4E3b31eB0E5CB73641EE1E65E7dCEFe520bA3ef2", "network": "ethereum", "category": "protocol-infra",    "incident": "SynthetixAddressResolver"},
    # ── Chainlink ─────────────────────────────────────────────────────────────
    {"address": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "network": "ethereum", "category": "oracle",           "incident": "ChainlinkETH-USD"},
    {"address": "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c", "network": "ethereum", "category": "oracle",           "incident": "ChainlinkBTC-USD"},
    {"address": "0x514910771AF9Ca656af840dff83E8264EcF986CA", "network": "ethereum", "category": "erc20-utility",     "incident": "LINK-Token"},
    # ── Governance / DAO infrastructure ──────────────────────────────────────
    {"address": "0xc0Da02939E1441F497fd74F78cE7Decb17B66529", "network": "ethereum", "category": "governance",        "incident": "CompoundGovernorBravo"},
    {"address": "0x408ED6354d4973f66138C91495F2f2FCbd8724C3", "network": "ethereum", "category": "governance",        "incident": "UniswapGovernor"},
    # ── ENS ───────────────────────────────────────────────────────────────────
    {"address": "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e", "network": "ethereum", "category": "naming-service",    "incident": "ENSRegistry"},
    {"address": "0x253553366Da8546fC250F225fe3d25d0C782303b", "network": "ethereum", "category": "naming-service",    "incident": "ENSETHRegistrarController"},
    # ── Gnosis Safe ───────────────────────────────────────────────────────────
    {"address": "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", "network": "ethereum", "category": "multisig",          "incident": "GnosisSafeV130"},
    {"address": "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2", "network": "ethereum", "category": "multisig",          "incident": "GnosisSafeProxyFactory"},
    # ── OpenSea ───────────────────────────────────────────────────────────────
    {"address": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "network": "ethereum", "category": "marketplace",       "incident": "OpenSeaSeaport15"},
    # ── Layer 2 canonical bridges ─────────────────────────────────────────────
    {"address": "0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a", "network": "ethereum", "category": "bridge",            "incident": "ArbitrumBridge"},
    {"address": "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1", "network": "ethereum", "category": "bridge",            "incident": "OptimismL1Bridge"},
    {"address": "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf", "network": "ethereum", "category": "bridge",            "incident": "PolygonERC20Bridge"},
    # ── ERC-20 governance / utility tokens ───────────────────────────────────
    {"address": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "network": "ethereum", "category": "erc20-governance",  "incident": "UNI-Token"},
    {"address": "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", "network": "ethereum", "category": "erc20-governance",  "incident": "AAVE-Token"},
    {"address": "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32", "network": "ethereum", "category": "erc20-governance",  "incident": "LDO-Token"},
    {"address": "0xD33526068D116cE69F19A9ee46F0bd304F21A51f", "network": "ethereum", "category": "erc20-utility",     "incident": "RPL-Token"},
    {"address": "0xc944E90C64B2c07662A292be6244BDf05Cda44a7", "network": "ethereum", "category": "erc20-utility",     "incident": "GRT-Token"},
    {"address": "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0", "network": "ethereum", "category": "erc20-utility",     "incident": "MATIC-Token"},
    {"address": "0x0F5D2fB29fb7d3CFeE444a200298f468908cC942", "network": "ethereum", "category": "erc20-utility",     "incident": "MANA-Token"},
    {"address": "0x4d224452801ACEd8B2F0aebE155379bb5D594381", "network": "ethereum", "category": "erc20-utility",     "incident": "APE-Token"},
    {"address": "0xBe9895146f7AF43049ca1c1AE358B0541Ea49704", "network": "ethereum", "category": "liquid-staking",    "incident": "cbETH-Coinbase"},
    {"address": "0xf951E335afb289353dc249e82926178EaC7DEd78", "network": "ethereum", "category": "liquid-staking",    "incident": "swETH-Swell"},
    # ── Uniswap V2 major pairs ────────────────────────────────────────────────
    {"address": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc", "network": "ethereum", "category": "dex-pool",         "incident": "UniV2-USDC-WETH"},
    {"address": "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852", "network": "ethereum", "category": "dex-pool",         "incident": "UniV2-USDT-WETH"},
    {"address": "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940", "network": "ethereum", "category": "dex-pool",         "incident": "UniV2-WBTC-WETH"},
    {"address": "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11", "network": "ethereum", "category": "dex-pool",         "incident": "UniV2-DAI-WETH"},
    {"address": "0xd3d2E2692501A5c9Ca623199D38826e513033a17", "network": "ethereum", "category": "dex-pool",         "incident": "UniV2-UNI-WETH"},
    # ── Uniswap V3 major pools ────────────────────────────────────────────────
    {"address": "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640", "network": "ethereum", "category": "dex-pool",         "incident": "UniV3-USDC-WETH-005"},
    {"address": "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD", "network": "ethereum", "category": "dex-pool",         "incident": "UniV3-WBTC-WETH-03"},
    {"address": "0x4e68Ccd3E89f51C3074ca5072bbAC773960dFa36", "network": "ethereum", "category": "dex-pool",         "incident": "UniV3-WETH-USDT-03"},
    {"address": "0x5777d92f208679DB4b9778590Fa3CAB3aC9e2168", "network": "ethereum", "category": "dex-pool",         "incident": "UniV3-DAI-USDC-001"},
    {"address": "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8", "network": "ethereum", "category": "dex-pool",         "incident": "UniV3-USDC-WETH-03"},
    # ── Curve additional pools ────────────────────────────────────────────────
    {"address": "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022", "network": "ethereum", "category": "dex-pool",         "incident": "CurveStETH-ETH"},
    {"address": "0xd632f22692FaC7611d2AA1C0D552930D43CAEd3B", "network": "ethereum", "category": "dex-pool",         "incident": "CurveFRAX-3CRV"},
    {"address": "0xDcEF968d416a41Cdac0ED8702fAC8128A64241A2", "network": "ethereum", "category": "dex-pool",         "incident": "CurveFRAX-USDC"},
    {"address": "0xEd279fDD11cA84bEef15AF5D39BB4d4bEE23F0cA", "network": "ethereum", "category": "dex-pool",         "incident": "CurveLUSD-3CRV"},
    {"address": "0x43b4FdFD4Ff969587185cDB6f0BD875c5Fc83f8c", "network": "ethereum", "category": "dex-pool",         "incident": "CurveAlUSD-3CRV"},
    # ── Aave aTokens / debt tokens ────────────────────────────────────────────
    {"address": "0xBcca60bB61934080951369a648Fb03DF4F96263C", "network": "ethereum", "category": "lending-atoken",   "incident": "AaveV2-aUSDC"},
    {"address": "0x030bA81f1c18d280636F32af80b9AAd02Cf0854e", "network": "ethereum", "category": "lending-atoken",   "incident": "AaveV2-aWETH"},
    {"address": "0x3Ed3B47Dd13EC9a98b44e6204A523E766B225811", "network": "ethereum", "category": "lending-atoken",   "incident": "AaveV2-aUSDT"},
    # ── Compound additional cTokens ───────────────────────────────────────────
    {"address": "0x35A18000230DA775CAc24873d00Ff85BccdeD550", "network": "ethereum", "category": "lending-ctoken",   "incident": "CompoundcUNI"},
    {"address": "0x70e36f6BF80a52b3B46b3aF8e106CC0ed743E8e4", "network": "ethereum", "category": "lending-ctoken",   "incident": "CompoundcCOMP"},
    # ── NFT contracts ─────────────────────────────────────────────────────────
    {"address": "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", "network": "ethereum", "category": "nft",              "incident": "CryptoPunks"},
    {"address": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", "network": "ethereum", "category": "nft",              "incident": "BAYC"},
    {"address": "0xED5AF388653567Af2F388E6224dC7C4b3241C544", "network": "ethereum", "category": "nft",              "incident": "Azuki"},
    {"address": "0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03", "network": "ethereum", "category": "nft",              "incident": "Nouns"},
    {"address": "0x60E4d786628Fea6478F785A6d7e704777c86a7c6", "network": "ethereum", "category": "nft",              "incident": "MAYC"},
    {"address": "0x23581767a106ae21c074b2276D25e5C3e136a68b", "network": "ethereum", "category": "nft",              "incident": "Moonbirds"},
    {"address": "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e", "network": "ethereum", "category": "nft",              "incident": "Doodles"},
    {"address": "0x49cF6f5d44E70224e2E23fDcdd2C053F30aDA28B", "network": "ethereum", "category": "nft",              "incident": "CloneX"},
    {"address": "0x1CB1A5e65610AEFF2551A50f76a87a7d3fB649C6", "network": "ethereum", "category": "nft",              "incident": "CrypToadz"},
    # ── ERC-4626 yield vaults ─────────────────────────────────────────────────
    {"address": "0x83F20F44975D03b1b09e64809B757c47f942BEeA", "network": "ethereum", "category": "yield-vault",       "incident": "sDAI-MakerDAO"},
    {"address": "0xac3E018457B222d93114458476f3E3416Abbe38F", "network": "ethereum", "category": "yield-vault",       "incident": "sfrxETH-ERC4626"},
    # ── Infrastructure / tooling ──────────────────────────────────────────────
    {"address": "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789", "network": "ethereum", "category": "protocol-infra",   "incident": "ERC4337-EntryPoint"},
    {"address": "0x000000000022D473030F116dDEE9F6B43aC78BA3", "network": "ethereum", "category": "protocol-infra",   "incident": "Permit2-Uniswap"},
    {"address": "0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f", "network": "ethereum", "category": "protocol-infra",   "incident": "ArbitrumInbox"},
    # ── Staking infrastructure ────────────────────────────────────────────────
    {"address": "0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1", "network": "ethereum", "category": "liquid-staking",   "incident": "LidoWithdrawalQueue"},
    {"address": "0x1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46", "network": "ethereum", "category": "protocol-infra",   "incident": "RocketPoolStorage"},
    {"address": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A", "network": "ethereum", "category": "protocol-infra",   "incident": "EigenLayerStrategyManager"},
    # ── Cross-chain / messaging ───────────────────────────────────────────────
    {"address": "0x8731d54E9D02c286767d56ac03e8037C07e01e98", "network": "ethereum", "category": "bridge",            "incident": "StargateRouter"},
    {"address": "0xb8901acB165ed027E32754E0FFe830802919727f", "network": "ethereum", "category": "bridge",            "incident": "HopETHBridge"},
    {"address": "0x4750c43867EF5F89869132ecEA405570f9D0a3b", "network": "ethereum", "category": "bridge",            "incident": "AcrossHubPool"},
    # ── Governance / timelocks ────────────────────────────────────────────────
    {"address": "0x6d903f6003cca6255D85CcA4D3B5E5146dC33925", "network": "ethereum", "category": "governance",        "incident": "CompoundTimelockV1"},
    {"address": "0x1a9C8182C09F50C8318d769245beA52c32BE35BC", "network": "ethereum", "category": "governance",        "incident": "UniswapTimelock"},
    {"address": "0xBE8E3e3618f7474a8724a6B8f88c72e85F3b4501", "network": "ethereum", "category": "governance",        "incident": "CompoundProxyAdmin"},
    # ── DEX aggregators ───────────────────────────────────────────────────────
    {"address": "0xDef1C0ded9bec7F1a1670819833240f027b25EfF", "network": "ethereum", "category": "dex-aggregator",    "incident": "0xExchangeProxy"},
    {"address": "0x74de5d4FCbf63E00296fd95d33236B9794016631", "network": "ethereum", "category": "dex-aggregator",    "incident": "MetaAggregationRouterV2"},
    # ── Safe ecosystem ────────────────────────────────────────────────────────
    {"address": "0x41675C099F32341bf84BFc5382aF534df5C7461a", "network": "ethereum", "category": "multisig",          "incident": "GnosisSafeV141"},
    {"address": "0x9641d764fc13c8B624c04430C7356C1C7C8102e2", "network": "ethereum", "category": "multisig",          "incident": "GnosisSafeModuleRegistry"},

    # ════════════════════════════════════════════════════════════════════════════
    # Arbitrum One benign contracts
    # ════════════════════════════════════════════════════════════════════════════
    # ── Tokens ───────────────────────────────────────────────────────────────
    {"address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "network": "arbitrum", "category": "erc20-wrapped",    "incident": "WETH-Arbitrum"},
    {"address": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "network": "arbitrum", "category": "erc20-stablecoin",  "incident": "USDC-Arbitrum"},
    {"address": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "network": "arbitrum", "category": "erc20-stablecoin",  "incident": "USDT-Arbitrum"},
    {"address": "0x912CE59144191C1204E64559FE8253a0e49E6548", "network": "arbitrum", "category": "erc20-governance",  "incident": "ARB-Token"},
    # ── GMX V2 ───────────────────────────────────────────────────────────────
    {"address": "0x7452c558d45f8afC8c83dAe62C3f8A5BE19c71f6", "network": "arbitrum", "category": "dex-router",       "incident": "GMX-V2-Router"},
    {"address": "0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a", "network": "arbitrum", "category": "erc20-governance",  "incident": "GMX-Token"},
    # ── Camelot DEX ──────────────────────────────────────────────────────────
    {"address": "0xc873fEcbd354f5A56E00E710B90EF4201db2448d", "network": "arbitrum", "category": "dex-router",       "incident": "CamelotV2Router"},
    {"address": "0x6EcCab422D763aC031210895C81787E87B43A652", "network": "arbitrum", "category": "dex-factory",      "incident": "CamelotV2Factory"},
    # ── Aave V3 on Arbitrum ───────────────────────────────────────────────────
    {"address": "0x794a61358D6845594F94dc1DB02A252b5b4814aD", "network": "arbitrum", "category": "lending-pool",     "incident": "AaveV3Pool-Arbitrum"},
    # ── Uniswap V3 on Arbitrum ────────────────────────────────────────────────
    {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "network": "arbitrum", "category": "dex-factory",      "incident": "UniswapV3Factory-Arbitrum"},
    {"address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "network": "arbitrum", "category": "dex-router",       "incident": "UniswapV3Router-Arbitrum"},
    # ── Pendle Finance ────────────────────────────────────────────────────────
    {"address": "0x0c880f6761F1af8d9Aa9C466984b80DAb9a8c9e8", "network": "arbitrum", "category": "yield-vault",       "incident": "PendleRouter-Arbitrum"},
    # ── Chainlink on Arbitrum ─────────────────────────────────────────────────
    {"address": "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612", "network": "arbitrum", "category": "oracle",           "incident": "ChainlinkETH-USD-Arbitrum"},
    # ── Gnosis Safe on Arbitrum ───────────────────────────────────────────────
    {"address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E", "network": "arbitrum", "category": "multisig",          "incident": "GnosisSafeL2-Arbitrum"},

    # ════════════════════════════════════════════════════════════════════════════
    # Optimism benign contracts
    # ════════════════════════════════════════════════════════════════════════════
    # ── Tokens ───────────────────────────────────────────────────────────────
    {"address": "0x4200000000000000000000000000000000000006", "network": "optimism", "category": "erc20-wrapped",    "incident": "WETH-Optimism"},
    {"address": "0x4200000000000000000000000000000000000042", "network": "optimism", "category": "erc20-governance",  "incident": "OP-Token"},
    {"address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "network": "optimism", "category": "erc20-stablecoin",  "incident": "USDC-Optimism"},
    {"address": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", "network": "optimism", "category": "erc20-stablecoin",  "incident": "USDT-Optimism"},
    # ── Velodrome V2 ──────────────────────────────────────────────────────────
    {"address": "0xa062aE8A9c5e11aaA026fc2670B0D65cCc8B2858", "network": "optimism", "category": "dex-router",       "incident": "VelodromeV2Router"},
    {"address": "0xF1046053aa5682b4F9a81b5481394DA16BE5FF5a", "network": "optimism", "category": "dex-factory",      "incident": "VelodromeV2Factory"},
    # ── Aave V3 on Optimism ───────────────────────────────────────────────────
    {"address": "0x794a61358D6845594F94dc1DB02A252b5b4814aD", "network": "optimism", "category": "lending-pool",     "incident": "AaveV3Pool-Optimism"},
    # ── Synthetix on Optimism ─────────────────────────────────────────────────
    {"address": "0x8700dAec35aF8Ff88c16BdF0418774303a7c96F8", "network": "optimism", "category": "erc20-governance",  "incident": "SNX-Optimism"},
    {"address": "0x1f814091bF9F4F59D4a15C7a4feBacE6285AF2F8", "network": "optimism", "category": "protocol-infra",   "incident": "SynthetixSystemStatus-Optimism"},
    # ── Uniswap V3 on Optimism ────────────────────────────────────────────────
    {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "network": "optimism", "category": "dex-factory",      "incident": "UniswapV3Factory-Optimism"},
    # ── Chainlink on Optimism ─────────────────────────────────────────────────
    {"address": "0x13e3Ee699D1909E989722E753853AE30b17e08c5", "network": "optimism", "category": "oracle",           "incident": "ChainlinkETH-USD-Optimism"},
    # ── Gnosis Safe on Optimism ───────────────────────────────────────────────
    {"address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E", "network": "optimism", "category": "multisig",          "incident": "GnosisSafeL2-Optimism"},

    # ════════════════════════════════════════════════════════════════════════════
    # Polygon (PoS) benign contracts
    # ════════════════════════════════════════════════════════════════════════════
    # ── Tokens ───────────────────────────────────────────────────────────────
    {"address": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "network": "polygon", "category": "erc20-wrapped",    "incident": "WMATIC"},
    {"address": "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", "network": "polygon", "category": "erc20-wrapped",    "incident": "WETH-Polygon"},
    {"address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "network": "polygon", "category": "erc20-stablecoin",  "incident": "USDC-Polygon"},
    {"address": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "network": "polygon", "category": "erc20-stablecoin",  "incident": "USDT-Polygon"},
    {"address": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "network": "polygon", "category": "erc20-stablecoin",  "incident": "DAI-Polygon"},
    # ── QuickSwap ─────────────────────────────────────────────────────────────
    {"address": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff", "network": "polygon", "category": "dex-router",       "incident": "QuickSwapV2Router"},
    {"address": "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32", "network": "polygon", "category": "dex-factory",      "incident": "QuickSwapV2Factory"},
    # ── Aave V3 on Polygon ────────────────────────────────────────────────────
    {"address": "0x794a61358D6845594F94dc1DB02A252b5b4814aD", "network": "polygon", "category": "lending-pool",     "incident": "AaveV3Pool-Polygon"},
    # ── Uniswap V3 on Polygon ─────────────────────────────────────────────────
    {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "network": "polygon", "category": "dex-factory",      "incident": "UniswapV3Factory-Polygon"},
    # ── Chainlink on Polygon ──────────────────────────────────────────────────
    {"address": "0xAB594600376Ec9fD91F8e885dADF0CE036862dE0", "network": "polygon", "category": "oracle",           "incident": "ChainlinkMATIC-USD-Polygon"},
    # ── Gnosis Safe on Polygon ────────────────────────────────────────────────
    {"address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E", "network": "polygon", "category": "multisig",          "incident": "GnosisSafeL2-Polygon"},

    # ════════════════════════════════════════════════════════════════════════════
    # Base benign contracts
    # ════════════════════════════════════════════════════════════════════════════
    # ── Tokens ───────────────────────────────────────────────────────────────
    {"address": "0x4200000000000000000000000000000000000006", "network": "base", "category": "erc20-wrapped",    "incident": "WETH-Base"},
    {"address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "network": "base", "category": "erc20-stablecoin",  "incident": "USDC-Base"},
    {"address": "0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22", "network": "base", "category": "liquid-staking",    "incident": "cbETH-Base"},
    # ── Aerodrome (dominant Base DEX) ─────────────────────────────────────────
    {"address": "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43", "network": "base", "category": "dex-router",       "incident": "AerodromeV2Router"},
    {"address": "0x420DD381b31aEf6683db6B902084cB0FFECe40Da", "network": "base", "category": "dex-factory",      "incident": "AerodromeV2Factory"},
    {"address": "0x940181a94A35A4569E4529A3CDfB74e38FD98631", "network": "base", "category": "erc20-governance",  "incident": "AERO-Token"},
    # ── Uniswap V3 on Base ────────────────────────────────────────────────────
    {"address": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD", "network": "base", "category": "dex-factory",      "incident": "UniswapV3Factory-Base"},
    {"address": "0x2626664c2603336E57B271c5C0b26F421741e481", "network": "base", "category": "dex-router",       "incident": "UniswapV3Router-Base"},
    # ── Aave V3 on Base ───────────────────────────────────────────────────────
    {"address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "network": "base", "category": "lending-pool",     "incident": "AaveV3Pool-Base"},
    # ── Chainlink on Base ─────────────────────────────────────────────────────
    {"address": "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70", "network": "base", "category": "oracle",           "incident": "ChainlinkETH-USD-Base"},
    # ── Gnosis Safe on Base ───────────────────────────────────────────────────
    {"address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E", "network": "base", "category": "multisig",          "incident": "GnosisSafeL2-Base"},

    # ════════════════════════════════════════════════════════════════════════════
    # BSC (BNB Chain) benign contracts — mirrors ETH set for balanced training
    # ════════════════════════════════════════════════════════════════════════════
    # ── BNB / Stablecoins ─────────────────────────────────────────────────────
    {"address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "network": "bsc", "category": "erc20-wrapped",    "incident": "WBNB"},
    {"address": "0x55d398326f99059fF775485246999027B3197955", "network": "bsc", "category": "erc20-stablecoin",  "incident": "BSC-USDT"},
    {"address": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "network": "bsc", "category": "erc20-stablecoin",  "incident": "BSC-USDC"},
    {"address": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", "network": "bsc", "category": "erc20-stablecoin",  "incident": "BUSD-BSC"},
    {"address": "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", "network": "bsc", "category": "erc20-stablecoin",  "incident": "DAI-BSC"},
    # ── PancakeSwap V2 ────────────────────────────────────────────────────────
    {"address": "0x10ED43C718714eb63d5aA57B78B54704E256024E", "network": "bsc", "category": "dex-router",       "incident": "PancakeSwapV2Router"},
    {"address": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73", "network": "bsc", "category": "dex-factory",      "incident": "PancakeSwapV2Factory"},
    {"address": "0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16", "network": "bsc", "category": "dex-pool",         "incident": "PancakeV2-WBNB-BUSD"},
    {"address": "0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE", "network": "bsc", "category": "dex-pool",         "incident": "PancakeV2-WBNB-USDT"},
    # ── PancakeSwap V3 ────────────────────────────────────────────────────────
    {"address": "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4", "network": "bsc", "category": "dex-router",       "incident": "PancakeSwapV3Router"},
    {"address": "0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865", "network": "bsc", "category": "dex-factory",      "incident": "PancakeSwapV3Factory"},
    # ── CAKE governance token ─────────────────────────────────────────────────
    {"address": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", "network": "bsc", "category": "erc20-governance",  "incident": "CAKE-Token"},
    # ── Venus Protocol (BSC lending) ──────────────────────────────────────────
    {"address": "0xfD36E2c2a6789Db23113685031d7F16329158384", "network": "bsc", "category": "lending-pool",     "incident": "VenusComptroller"},
    {"address": "0xA07c5b74C9B40447a954e1466938b865b6BBea36", "network": "bsc", "category": "lending-ctoken",   "incident": "vBNB-Venus"},
    {"address": "0xecA88125a5ADbe82614ffC12D0DB554E2e2867C8", "network": "bsc", "category": "lending-ctoken",   "incident": "vUSDC-Venus"},
    {"address": "0xfD5840Cd36d94D7229439859C0112a4185BC0255", "network": "bsc", "category": "lending-ctoken",   "incident": "vUSDT-Venus"},
    {"address": "0x95c78222B3D6e262426483D42CfA53685A67Ab9D", "network": "bsc", "category": "lending-ctoken",   "incident": "vBUSD-Venus"},
    # ── Biswap DEX ────────────────────────────────────────────────────────────
    {"address": "0x3a6d8cA21D1CF76F653A67577FA0D27453350dD8", "network": "bsc", "category": "dex-router",       "incident": "BiswapRouter"},
    {"address": "0x858E3312ed3A876947EA49d572A7C42DE08af7EE", "network": "bsc", "category": "dex-factory",      "incident": "BiswapFactory"},
    # ── Alpaca Finance (BSC yield) ────────────────────────────────────────────
    {"address": "0xA625AB01B08ce023B2a342Dbb12a16f2C8489A8F", "network": "bsc", "category": "yield-vault",       "incident": "AlpacaFairLaunch"},
    {"address": "0x8F0528cE5eF7B51152A59745bEfDD91D97091d2F", "network": "bsc", "category": "erc20-governance",  "incident": "ALPACA-Token"},
    # ── BSC bridges / infrastructure ──────────────────────────────────────────
    {"address": "0x0000000000000000000000000000000000001004", "network": "bsc", "category": "protocol-infra",   "incident": "BSC-StakingSystem"},
    {"address": "0x986b5E1e1755e3C2440e960477f25201B0a8bbD4", "network": "bsc", "category": "oracle",           "incident": "ChainlinkBNB-USD-BSC"},
    # ── Gnosis Safe on BSC ────────────────────────────────────────────────────
    {"address": "0x3E5c63644E683549055b9Be8653de26E0B4CD36E", "network": "bsc", "category": "multisig",          "incident": "GnosisSafeL2-BSC"},
    {"address": "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2", "network": "bsc", "category": "multisig",          "incident": "GnosisSafeProxyFactory-BSC"},
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_cache() -> Dict[str, str]:
    """Load address→bytecode_hex cache from disk."""
    cache: Dict[str, str] = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    cache[entry["address"].lower()] = entry["bytecode"]
    return cache


def save_to_cache(address: str, bytecode: str) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "a") as f:
        f.write(json.dumps({"address": address.lower(), "bytecode": bytecode}) + "\n")


def load_exploit_csv() -> List[Dict[str, str]]:
    """
    Load exploit addresses from both:
      - data/collectors/exploit_addresses.csv  (handcrafted DeFiHackLabs list)
      - data/collectors/exploit_addresses_scraped.csv  (auto-scraped by scraper.py)

    Deduplicates on address (lowercase). Returns [] if neither file exists.
    """
    seen: set = set()
    rows: List[Dict[str, str]] = []

    def _read_csv(path: Path) -> None:
        if not path.exists():
            return
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = (row.get("address") or "").strip().lower()
                if not addr or addr.startswith("#") or addr == "address":
                    continue
                if addr in seen:
                    continue
                seen.add(addr)
                rows.append({
                    "address":  addr,
                    "network":  (row.get("network")  or "ethereum").strip() or "ethereum",
                    "incident": (row.get("incident") or "unknown").strip(),
                    "category": (row.get("category") or "exploit").strip(),
                })
        log.info(f"Loaded {len(seen)} exploit addresses (cumulative) from {path}")

    _read_csv(CSV_FILE)
    _read_csv(CSV_FILE_SCRAPED)

    if not rows:
        log.warning(
            "No exploit CSV found. Create exploit_addresses.csv or run scraper.py first."
        )
    return rows


def load_benign_csv() -> List[Dict[str, str]]:
    """
    Load benign addresses from data/collectors/benign_addresses.csv
    (populated by benign_collector.py).
    Returns [] if the file doesn't exist.
    """
    if not BENIGN_CSV.exists():
        log.info("benign_addresses.csv not found — skipping CSV benign enrichment")
        return []

    rows: List[Dict[str, str]] = []
    with open(BENIGN_CSV, newline="") as f:
        for row in csv.DictReader(f):
            addr = (row.get("address") or "").strip().lower()
            if not addr or not addr.startswith("0x") or len(addr) != 42:
                continue
            rows.append({
                "address":  addr,
                "network":  (row.get("network")  or "ethereum").strip() or "ethereum",
                "incident": (row.get("incident") or "benign-defi").strip(),
                "category": (row.get("category") or "benign").strip(),
            })
    log.info(f"Loaded {len(rows)} benign addresses from {BENIGN_CSV}")
    return rows


def fetch_bytecode(
    address: str,
    network: str,
    cache: Dict[str, str],
    rate_delay: float,
) -> Optional[str]:
    """
    Return bytecode hex for address (from cache or Etherscan).
    Returns None on failure or EOA.
    """
    key = address.lower()
    if key in cache:
        bc = cache[key]
        return bc if bc != "0x" else None

    client = EtherscanClient(network=network)
    time.sleep(rate_delay)
    result = client.get_bytecode(address)

    if not result["success"]:
        log.warning(f"  Failed {address}: {result.get('error')}")
        save_to_cache(address, "0x")   # cache the failure
        return None

    if not result["is_contract"]:
        log.warning(f"  {address} is an EOA — skipping")
        save_to_cache(address, "0x")
        return None

    bc = result["bytecode"]
    save_to_cache(address, bc)
    return bc


def build_graph(
    address: str,
    bytecode: str,
    label: int,
    category: str,
    incident: str,
    network: str,
) -> Optional[Dict[str, Any]]:
    builder = BytecodeGraphBuilder()
    try:
        graph = builder.build_graph(
            bytecode_hex=bytecode,
            graph_id=f"{incident.lower().replace(' ', '_')}_{address[:8]}",
            label=label,
            category=category,
            metadata={"address": address, "network": network, "incident": incident,
                      "source": "on-chain"},
        )
        if graph["num_nodes"] < 2:
            log.debug(f"  {address}: too small ({graph['num_nodes']} nodes) — skipping")
            return None
        return graph
    except Exception as e:
        log.warning(f"  build_graph failed for {address}: {e}")
        return None


def split_and_save(
    graphs: List[Dict[str, Any]],
    out_dir: Path,
    train_frac: float = 0.70,
    val_frac:   float = 0.15,
) -> Dict[str, int]:
    random.shuffle(graphs)
    n = len(graphs)
    n_train = int(n * train_frac)
    n_val   = int(n * val_frac)

    splits = {
        "train": graphs[:n_train],
        "val":   graphs[n_train:n_train + n_val],
        "test":  graphs[n_train + n_val:],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    for split_name, split_graphs in splits.items():
        path = out_dir / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for g in split_graphs:
                f.write(json.dumps(g) + "\n")
        counts[split_name] = len(split_graphs)

    return counts


def merge_with_synthetic(real_dir: Path, synth_dir: Path, out_dir: Path) -> None:
    """Combine real + synthetic graphs, re-split, and write to out_dir."""
    all_graphs: List[Dict[str, Any]] = []
    for split in ("train", "val", "test"):
        for src in (real_dir, synth_dir):
            path = src / f"{split}.jsonl"
            if path.exists():
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            all_graphs.append(json.loads(line))

    log.info(f"Merging {len(all_graphs)} graphs (real + synthetic) → {out_dir}")
    counts = split_and_save(all_graphs, out_dir)
    log.info(f"  Merged splits: {counts}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Collect real on-chain bytecode for GNN training")
    parser.add_argument("--rate-delay", type=float, default=0.25,
                        help="Seconds between Etherscan requests (default: 0.25 = ~4 req/s)")
    parser.add_argument("--merge-synthetic", action="store_true",
                        help="After collecting, merge with synthetic dataset in data/datasets/bytecode/")
    parser.add_argument("--out-dir", default=str(OUT_DIR),
                        help="Output directory for real_bytecode dataset")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)

    log.info("=" * 60)
    log.info("Calyx Real Bytecode Collector")
    log.info("=" * 60)

    cache = load_cache()
    log.info(f"Cache loaded: {len(cache)} entries")

    exploit_rows = load_exploit_csv()
    benign_csv_rows = load_benign_csv()

    # Build work list
    work: List[Dict[str, Any]] = []
    seen_benign: set = set()
    for row in BENIGN_CONTRACTS:
        seen_benign.add(row["address"].lower())
        work.append({**row, "label": 0})
    for row in benign_csv_rows:
        if row["address"].lower() not in seen_benign:
            seen_benign.add(row["address"].lower())
            work.append({**row, "label": 0})
    for row in exploit_rows:
        work.append({**row, "label": 1})

    log.info(f"Contracts to fetch: {len(work)}  ({sum(1 for w in work if w['label']==0)} benign, "
             f"{sum(1 for w in work if w['label']==1)} exploit)")
    log.info("")

    graphs: List[Dict[str, Any]] = []
    n_ok = n_fail = n_skip = 0

    for i, entry in enumerate(work):
        addr     = entry["address"]
        network  = entry.get("network", "ethereum")
        label    = entry["label"]
        category = entry.get("category", "unknown")
        incident = entry.get("incident", "unknown")

        tag = "BENIGN" if label == 0 else "EXPLOIT"
        log.info(f"[{i+1}/{len(work)}] {tag} {incident} ({addr[:10]}...)")

        bytecode = fetch_bytecode(addr, network, cache, args.rate_delay)
        if bytecode is None:
            n_fail += 1
            continue

        graph = build_graph(addr, bytecode, label, category, incident, network)
        if graph is None:
            n_skip += 1
            continue

        graphs.append(graph)
        n_ok += 1
        log.info(f"  OK — {graph['num_nodes']} nodes, {graph['num_edges']} edges")

    log.info("")
    log.info(f"Collection done: {n_ok} graphs, {n_fail} fetch failures, {n_skip} skipped (too small)")

    if not graphs:
        log.error("No graphs collected — check ETHERSCAN_API_KEY and network connectivity")
        return

    # Class breakdown
    n_exploit = sum(1 for g in graphs if g["label"] == 1)
    n_benign  = sum(1 for g in graphs if g["label"] == 0)
    log.info(f"Labels: {n_benign} benign, {n_exploit} exploit")

    # Split and save
    counts = split_and_save(graphs, out_dir)
    log.info(f"Saved to {out_dir}: {counts}")

    # Save stats
    stats = {
        "total": len(graphs),
        "benign": n_benign,
        "exploit": n_exploit,
        "splits": counts,
        "source": "on-chain",
        "cache_entries": len(load_cache()),
    }
    (out_dir / "dataset_stats.json").write_text(json.dumps(stats, indent=2))

    if args.merge_synthetic:
        merged_dir = _REPO_ROOT / "data" / "datasets" / "bytecode_merged"
        merge_with_synthetic(out_dir, SYNTH_DIR, merged_dir)
        log.info(f"Merged dataset written to {merged_dir}")
        log.info("To retrain on merged data:")
        log.info(f"  PYTHONPATH=. python3 -m models.gnn.train  # update BYTECODE_DIR in train.py to {merged_dir}")

    log.info("")
    log.info("Next steps:")
    log.info("  1. Add more exploit addresses to data/collectors/exploit_addresses.csv")
    log.info("     Source: https://github.com/SunWeb3Sec/DeFiHackLabs")
    log.info("  2. Run with --merge-synthetic to combine with template data")
    log.info("  3. Retrain: PYTHONPATH=. python3 -m models.gnn.train")


if __name__ == "__main__":
    main()
