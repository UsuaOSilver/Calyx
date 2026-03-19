"""
detectors/bytecode_analyzer/skanf_sensitive.py

SKANF sensitive address and function-signature constants.

Sourced directly from the SKANF Docker image (dockerofsyang/skanf):
  /opt/skanf/constants/address.json    — 50 ETH + 50 BSC mainnet DeFi tokens
  /opt/skanf/constants/signature.json  — 3 ERC-20 transfer function selectors

Usage:
    from detectors.bytecode_analyzer.skanf_sensitive import (
        SENSITIVE_ADDRESSES_ETH,
        SENSITIVE_SIGNATURES,
        ERC20_TRANSFER,
        ERC20_APPROVE,
        ERC20_TRANSFER_FROM,
        is_sensitive_call,
        erc20_calldata,
    )
"""

from __future__ import annotations
from typing import Optional

# ── ERC-20 function selectors (4-byte ABI encoding) ────────────────────────

ERC20_TRANSFER      = "a9059cbb"  # transfer(address,uint256)
ERC20_APPROVE       = "095ea7b3"  # approve(address,uint256)
ERC20_TRANSFER_FROM = "23b872dd"  # transferFrom(address,address,uint256)

SENSITIVE_SIGNATURES: frozenset = frozenset({
    ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM,
    f"0x{ERC20_TRANSFER}", f"0x{ERC20_APPROVE}", f"0x{ERC20_TRANSFER_FROM}",
})

# ── Known DeFi token addresses — ETH mainnet ───────────────────────────────
# Source: SKANF /opt/skanf/constants/address.json (ETH list)

SENSITIVE_ADDRESSES_ETH: frozenset = frozenset({
    addr.lower() for addr in [
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",  # BNB
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",  # stETH
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",  # WBTC
        "0x514910771AF9Ca656af840dff83E8264EcF986CA",  # LINK
        "0x2AF5D2aD76741191D15Dfe7bF6aC92d4Bd912Ca3",  # BUSD (legacy)
        "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",  # SHIB
        "0x582d872A1B094FC48F5DE31D3B73F2D9bE47def1",  # TON
        "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",  # wstETH
        "0xdC035D45d973E3EC169d2276DDab16f1e407384F",  # USDS
        "0x21c2c96Dbfa137E23946143c71AC8330F9B44001",
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
        "0x54D2252757e1672EEaD234D27B1270728fF90581",
        "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3",  # USDe
        "0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee",  # weETH
        "0x6982508145454Ce325dDbE47a25d4ec3d2311933",  # PEPE
        "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf",  # cbBTC
        "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",  # UNI
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
        "0x75231F58b43240C9718Dd58B4967c5114342a86c",  # OKB
        "0x85F17Cf997934a597031b2E18a9aB6ebD4B9f6a4",
        "0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3",
        "0x418708dD507A2F0Cac24d31c60B350315F4C8009",
        "0xE66747a101bFF2dBA3697199DCcE5b743b454759",  # GT
        "0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD",
        "0xBc65ad17c5C0a2A4D159fa5a503f4992c7B545FE",
        "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9",  # AAVE
        "0x4da27a545c0c5B758a6BA100e3a049001de870f5",  # stkAAVE
        "0x7712c34205737192402172409a8F7ccef8aA2AEc",
        "0x6a9DA2D710BB9B700acde7Cb81F10F1fF8C89041",
        "0xA0b73E1Ff0B80914AB6fe0444E65848C4C34450b",  # CRO
        "0x3c3a81e81dc49A522A592e7622A7E711c06bf354",
        "0x6De037ef9aD2725EB40118Bb1702EBb27e4Aeb24",
        "0xD850942eF8811f2A866692A623011bDE52a462C1",  # VEN
        "0x455e53CBB86018Ac2B8092FdCd39d8444aFFC3F6",
        "0x9D39A5DE30e57443BfF2A8307A4256c8797A3497",
        "0xaea46A60368A7bD060eec7DF8CBa43b7EF41Ad85",
        "0x57e114B691Db790C35207b2e685D4A43181e6061",
        "0x8236a87084f8B84306f72007F36F2618A5634494",
        "0x6e1A19F235bE7ED8E3369eF73b196C07257494DE",
        "0x8D983cb9388EaC77af0474fA441C4815500Cb7BB",  # USDG
        "0x519ddEff5d142Fc177d95F24952eF3D2EDe530BC",
        "0xB50721BCf8d664c30412Cfbc6cf7a15145234ad1",  # ARB
        "0x163f8C2467924be0ae7B5347228CABF260318753",  # WLD
        "0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409",  # FDUSD
        "0x4aeF9BD3fBb09d8f374436D9ec25711A1Be9BaCb",
        "0xF5e11df1ebCf78b6b6D26E04FF19cD786a1e81dC",
        "0xf34960d9d60be18cC1D5Afc1A6F012A723a28811",  # KCS
        "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2",  # MKR
    ]
})

SENSITIVE_ADDRESSES_BSC: frozenset = frozenset({
    addr.lower() for addr in [
        "0x2170Ed0880ac9A755fd29B2688956BD959F933F8",  # ETH (BSC)
        "0x55d398326f99059fF775485246999027B3197955",  # USDT (BSC)
        "0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE",  # XRP (BSC)
        "0x3E14602186DD9dE538F729547B3918D24c823546",
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",  # WBNB
        "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",  # USDC (BSC)
        "0x8965349fb649A33a30cbFDa057D8eC2C48AbE2A2",
        "0xbA2aE424d960c26247Dd6c32edC70B295c744C43",  # DOGE (BSC)
        "0x3EE2200Efb3400fAbB9AacF31297cBdD1d435D47",  # ADA (BSC)
        "0xCE7de646e7208a4Ef112cb6ed5038FA6cC6b12e3",  # TRX (BSC)
        "0x0555E30da8f98308EdB960aa94C0Db47230d2B9c",
        "0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD",  # LINK (BSC)
        "0x1CE0c2827e2eF14D5C4f29a091d735A204794041",
        "0x43C934A845205F0b514417d757d7235B8f53f1B9",
        "0x2859e4544C4bB03966803b044A93563Bd2D0DD4D",  # SHIB (BSC)
        "0x76A797A59Ba2C17726896976B7B3747BfD1d220f",  # TON (BSC)
        "0x8fF795a6F4D97E7887C79beA79aba5cc76444aDf",  # BCH (BSC)
        "0x7083609fCE4d1d8Dc0C979AAb8c869Ea2C873402",  # DOT (BSC)
        "0x4338665CBB7B2485A8855A139b75D5e34AB0DB94",  # LTC (BSC)
        "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c",  # BTCB
        "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3",  # DAI (BSC)
        "0x5d3a1Ff2b6BAb83b63cd9AD0787074081a52ef34",  # USDe (BSC)
        "0x25d887Ce7a35172C62FeBFD67a1856F20FaEbB00",  # PEPE (BSC)
        "0xBf5140A22578168FD562DCcF235E5D43A02ce9B1",  # UNI (BSC)
        "0x031b41e504677879370e9DBcF937283A8691Fa7f",
        "0x1Fa4a73a3F0133f0025378af00236f3aBDEE5D63",
        "0x3d6545b08693daE087E957cb1180ee38B9e3c25E",
        "0xfb6115445Bff7b52FeB98650C87f44907E58f802",
        "0x8595F9dA7b868b1822194fAEd312235E43007b49",
        "0x6FDcdfef7c496407cCb0cEC90f9C5Aaa1Cc8D888",
        "0x211Cc4DD073734dA055fbF44a2b4667d5E5fE5d2",
        "0x58538e6A46E07434d7E7375Bc268D3cb839C0133",
        "0xecAc9C5F704e954931349Da37F60E39f515c11c1",
        "0x0D8Ce2A99Bb6e3B7Db580eD848240e4a0F9aE153",
        "0x0Eb3a705fc54725037CC9e008bDede697f62F335",
        "0xa050FFb3eEb8200eEB7F61ce34FF644420FD3522",
        "0x4aae823a6a0b376De6A78e74eCC5b079d38cBCf7",
        "0x5f0Da599BB2ccCfcf6Fdfd7D81743B6020864350",
        "0x56b6fB708fC5732DEC1Afc8D8556423A2EDcCbD6",
        "0xbF7c81FFF98BbE61B40Ed186e4AfD6DDd01337fe",
        "0xb7F8Cd00C5A06c0537E2aBfF0b58033d02e5E094",
        "0x9996D0276612d23b35f90C51EE935520B3d7355B",
        "0xd944f1D1e9d5f9Bb90b62f9D45e447D989580782",
        "0x7950865a9140cB519342433146Ed5b40c6F210f7",
        "0xfb5B838b6cfEEdC2873aB27866079AC55363D37E",
        "0x352Cb5E19b12FC216548a2677bD0fce83BaE434B",
        "0x6E88056E8376Ae7709496Ba64d37fa2f8015ce3e",
        "0x882C173bC7Ff3b7786CA16dfeD3DFFfb9Ee7847B",
        "0x9Ac983826058b8a9C7Aa1C9171441191232E8404",
        "0x170C84E3b1D282f9628229836086716141995200",
    ]
})

SENSITIVE_ADDRESSES_ALL: frozenset = SENSITIVE_ADDRESSES_ETH | SENSITIVE_ADDRESSES_BSC


def is_sensitive_call(
    target_addr: Optional[str],
    function_selector: Optional[str] = None,
    network: str = "ethereum",
) -> bool:
    """Return True if this CALL matches SKANF sensitivity criteria."""
    if target_addr:
        norm = target_addr.lower()
        if not norm.startswith("0x"):
            norm = "0x" + norm
        if network == "bsc":
            addr_match = norm in SENSITIVE_ADDRESSES_BSC
        elif network == "all":
            addr_match = norm in SENSITIVE_ADDRESSES_ALL
        else:
            addr_match = norm in SENSITIVE_ADDRESSES_ETH
        if addr_match:
            return True
    if function_selector:
        norm_sel = function_selector.lower().lstrip("0x")
        if norm_sel in {ERC20_TRANSFER, ERC20_APPROVE, ERC20_TRANSFER_FROM}:
            return True
    return False


def erc20_calldata(selector_hex: str, attacker_addr: str) -> str:
    """
    Build a complete ERC-20 exploit calldata payload.
    Matches SKANF aeg.py construction exactly.

    transfer/approve: selector(4) + attacker_padded(32) + max_uint256(32)
    transferFrom:     selector(4) + zero(32) + attacker(32) + max_uint256(32)
    """
    _WORD = 32
    MAX_UINT256 = (2 ** 256 - 1).to_bytes(_WORD, "big")
    addr_int = int(attacker_addr, 16)
    addr_bytes = addr_int.to_bytes(_WORD, "big")
    sel = bytes.fromhex(selector_hex.lstrip("0x"))
    if selector_hex.lstrip("0x").lower() == ERC20_TRANSFER_FROM:
        zero = (0).to_bytes(_WORD, "big")
        payload = sel + zero + addr_bytes + MAX_UINT256
    else:
        payload = sel + addr_bytes + MAX_UINT256
    return "0x" + payload.hex()
