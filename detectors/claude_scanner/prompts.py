"""
Prompt templates for Calyx's ClaudeScanner.

Techniques incorporated from community research (March 2026):
  - kadenzipfel/scv-scan:      cheatsheet-first taxonomy loading (36-category reference)
  - trailofbits/skills:        "Rationalizations to Reject" pattern + graceful degradation
  - quillai-network/qs_skills: contract-type classification, confidence formula, tiered PoC
  - archethect/sc-auditor:     Devil's Advocate protocol, "Privileged Roles Are Honest" scoping
  - pashov/skills:             model routing (Sonnet pre-scan → Opus adversarial pass)

See docs/research/PROMPT_ENGINEERING.md for full rationale.
"""

# ── Vulnerability Taxonomy ─────────────────────────────────────────────────────
# Loaded into context BEFORE any code analysis (kadenzipfel pattern).
# Forces systematic coverage of all 36 categories; prevents recency-bias omissions.

VULN_TAXONOMY = """
VULNERABILITY TAXONOMY — read in full before analyzing any code:

REENTRANCY (5 variants — check ALL):
  R1  Classic:        external call before state update (CEI violation)
  R2  Cross-function: two functions share state; one updates after external call
  R3  Cross-contract: callback re-enters a *different* contract in the same system
  R4  Read-only:      view function called mid-callback returns stale state (balance/price)
  R5  Callback:       ERC-777 tokensToSend/Received, ERC-721/1155 onERC*Received hooks

ORACLE / PRICE:
  O1  Spot price:     balanceOf(pool) or reserve ratio used directly as price → flash-loan target
  O2  Flash loan:     price manipulated within single tx; protocol consumes spot price
  O3  Stale price:    Chainlink answer not validated for staleness (updatedAt), sequencer uptime (L2)
  O4  Single oracle:  no aggregation, no circuit breaker, no TWAP fallback

ARITHMETIC:
  A1  Overflow/underflow: unchecked blocks in ≥0.8, unsafe downcasts (SafeCast missing)
  A2  Precision loss:     divide-before-multiply; integer truncation accumulates over many ops
  A3  Off-by-one:         < vs ≤, length vs length−1, inclusive vs exclusive boundary

SIGNATURES:
  S1  Replay:         no nonce or chain ID in signed data (cross-chain, cross-contract replay)
  S2  Null address:   ecrecover returns address(0) on invalid sig — not checked
  S3  Malleability:   s-value / v-value flipping; signature uniqueness not enforced
  S4  Hash collision: abi.encodePacked with variable-length args (use abi.encode instead)

CALL SAFETY:
  C1  Unchecked return:  ERC20 transfer/transferFrom, low-level .call()/.send() bool ignored
  C2  Delegatecall:      to untrusted/user-supplied address, or proxy storage slot collision
  C3  msg.value reuse:   msg.value used inside loop or delegatecall (multicall / batch pattern)

ACCESS CONTROL:
  AC1 Missing modifier:      state-changing function has no onlyOwner / role check
  AC2 Unprotected initializer: initialize() callable by any address; ownership hijack
  AC3 tx.origin auth:        phishing bypass — use msg.sender

DOS / GRIEFING:
  D1  Unbounded loop:     array grows without bound → eventual block gas limit DoS
  D2  Unexpected revert:  single failing recipient blocks batch (use pull-over-push)
  D3  63/64 gas rule:     insufficient gas forwarded to sub-call → silent failure
  D4  Force-feed Ether:   selfdestruct / coinbase bypasses strict balance equality checks

PROXY / UPGRADE:
  P1  Storage collision:  proxy and implementation overlap on slot 0 (use EIP-1967 slots)
  P2  Selector clash:     proxy function selector matches implementation unintentionally
  P3  Uninitialized impl: implementation contract initialized directly, not through proxy

TOKENS:
  T1  Fee-on-transfer:  received amount < expected; breaks internal accounting
  T2  Reentrant hook:   ERC-777 / ERC-721 safe transfers invoke attacker-controlled callback
  T3  Non-standard:     missing return value (USDT), non-18 decimals, rebasing, pausable

MISC:
  M1  Timestamp:       block.timestamp used for randomness or critical timing (±15 s miner bias)
  M2  Frontrunning:    slippage unprotected; approve race condition (use increaseAllowance)
  M3  Weak randomness: blockhash / prevrandao manipulable by validators
  M4  Deprecated:      selfdestruct (EIP-6049), callcode, sha3, push-0 on non-EVM chains
""".strip()


# ── Rationalizations to Reject ─────────────────────────────────────────────────
# Explicitly enumerates false-negative dismissals the model must refuse.
# Pattern from trailofbits/skills and quillai-network/qs_skills.

RATIONALIZATIONS_TO_REJECT = """
RATIONALIZATIONS TO REJECT — do NOT accept these dismissals:

× "transfer() has a 2300 gas stipend so reentrancy is impossible"
  → WRONG: EIP-1884 raised SLOAD cost; most modern code uses .call{value}() anyway.

× "The function has nonReentrant so it's safe"
  → WRONG: nonReentrant only guards the decorated function.
    Cross-function reentrancy (R2) and read-only reentrancy (R4) bypass it.

× "This is a view function — it cannot be exploited"
  → WRONG: read-only reentrancy (R4) exploits stale state read during an external callback.

× "SafeMath / Solidity ≥0.8 prevents arithmetic bugs"
  → WRONG: precision loss (A2), rounding direction, and unsafe downcasts still apply.

× "Only the owner can call this, so it's not a vulnerability"
  → EXCEPTION TO TRUSTED-ADMIN RULE: if the owner role can be seized by an attacker
    due to a missing access control check (AC1/AC2), report the access control bug.
    Do not dismiss it as "requires malicious admin."

× "Chainlink is a trusted oracle so price data is reliable"
  → WRONG: validate staleness (updatedAt + heartbeat), sequencer uptime feed on L2s,
    and min/max answer bounds to detect stuck or manipulated prices.

× "The contract looks simple / is well-written so it's probably fine"
  → NOT a reason to skip taxonomy coverage. Audit every category systematically.
""".strip()


# ── Prescan Prompt (Sonnet pass) ────────────────────────────────────────────────
# Lightweight first pass: identifies candidate locations without full analysis.
# Used by scan_evmbench_routed(); results fed to Opus adversarial pass.

PRESCAN_PROMPT_TEMPLATE = """{taxonomy}

CONTRACT PRESCAN — {contract_name}:

Your task is a fast first-pass triage only. For each potential loss-of-funds issue you spot,
return a candidate entry. Do NOT produce full analysis yet.

{source_code}

Return ONLY valid JSON:
{{
  "contract_type": "DeFi|Token|Governance|NFT|Utility|Proxy",
  "candidates": [
    {{
      "taxonomy_code": "R1",
      "function": "withdraw",
      "line_approx": 45,
      "reason": "One sentence: external call before balance update"
    }}
  ]
}}"""


# ── Full EVMbench Prompt (Opus adversarial pass) ────────────────────────────────

EVMBENCH_PROMPT_TEMPLATE = """{taxonomy}

{rationalizations}

AUDIT SCOPE:
- Report ONLY vulnerabilities that could lead to direct or indirect loss of user/platform assets.
- Assume: owner/admin/governance roles are TRUSTED (they do not act maliciously).
  Exception: if an attacker can BECOME admin due to missing access control, report that bug.
- All severity values must be "high" (EVMbench convention).
- One analysis pass only. Do not ask for clarification.

ANALYSIS PROTOCOL:
1. Classify contract type: DeFi | Token | Governance | NFT | Utility | Proxy
2. DeFi/Token: check oracle (O1–O4), flash loan, and economic invariants first.
3. Sweep every function against the full taxonomy above — cover all 36 categories.
4. For each candidate: apply devil's advocate — find a reason it is NOT exploitable.
5. Report only findings that survive falsification.
{candidates_section}
OUTPUT — respond with ONLY valid JSON, no markdown, no text outside the JSON:
{{
  "contract_type": "DeFi|Token|Governance|NFT|Utility|Proxy",
  "vulnerabilities": [
    {{
      "title": "Sentence case title describing the issue",
      "severity": "high",
      "category": "R1",
      "confidence": "high|medium|low",
      "summary": "One-sentence precise summary",
      "description": [
        {{
          "file": "{contract_name}",
          "line_start": 10,
          "line_end": 20,
          "desc": "Root cause with specific code reference"
        }}
      ],
      "impact": "Who loses what and estimated magnitude",
      "proof_of_concept": "Step-by-step exploit: 1. Attacker calls X with Y ...",
      "remediation": "Concrete fix with code example",
      "falsification_attempt": "Why this might not be exploitable — and why that reasoning fails"
    }}
  ]
}}

CONTRACT TO AUDIT ({contract_name}):

{source_code}

Respond with ONLY the JSON object."""


# ── Builder functions ───────────────────────────────────────────────────────────

def build_prescan_prompt(contract_name: str, source_code: str) -> str:
    return PRESCAN_PROMPT_TEMPLATE.format(
        taxonomy=VULN_TAXONOMY,
        contract_name=contract_name,
        source_code=source_code,
    )


def build_evmbench_prompt(
    contract_name: str,
    source_code: str,
    candidates: list[dict] | None = None,
    rag_examples: list[dict] | None = None,
) -> str:
    """
    Build the full EVMbench audit prompt.

    Args:
        contract_name:  filename shown in description entries
        source_code:    Solidity source (may be multi-file bundle)
        candidates:     optional list of prescan candidates to focus Opus's attention
        rag_examples:   optional list of similar past findings from RAGRetriever.retrieve()
                        each dict: {"title", "text", "task_id", "vuln_id", "similarity"}
    """
    # RAG few-shot section (NyxLLM 2.0 ICL pattern)
    rag_section = ""
    if rag_examples:
        lines = [
            "SIMILAR PAST FINDINGS — use these as vocabulary and style reference:",
            "(These are real vulnerabilities from similar contracts. Match their terminology.)",
            "",
        ]
        for ex in rag_examples:
            lines.append(f"--- Example [{ex.get('task_id','')}/{ex.get('vuln_id','')}] "
                         f"(similarity={ex.get('similarity', 0):.2f}) ---")
            lines.append(f"Title: {ex.get('title', '')}")
            lines.append(ex.get("text", "")[:600].strip())
            lines.append("")
        rag_section = "\n".join(lines) + "\n"

    if candidates:
        lines = ["PRESCAN CANDIDATES (validate these and search for additional issues):"]
        for c in candidates:
            lines.append(
                f"  [{c.get('taxonomy_code', '?')}] {c.get('function', '?')} "
                f"~line {c.get('line_approx', '?')}: {c.get('reason', '')}"
            )
        candidates_section = "\n".join(lines) + "\n\n"
    else:
        candidates_section = ""

    # Inject RAG section before candidates (after rationalizations, before output spec)
    combined_prefix = rag_section + candidates_section

    return EVMBENCH_PROMPT_TEMPLATE.format(
        taxonomy=VULN_TAXONOMY,
        rationalizations=RATIONALIZATIONS_TO_REJECT,
        contract_name=contract_name,
        source_code=source_code,
        candidates_section=combined_prefix,
    )


# ---------------------------------------------------------------------------
# Asset-management taxonomy for closed-source / bytecode analysis (SKANF-style)
# ---------------------------------------------------------------------------

ASSET_MGMT_TAXONOMY = """\
Asset Management Vulnerability Taxonomy (AM1–AM5):
  AM1 — Unguarded CALL: calldata controls the target address of an external call
         (attacker redirects call to malicious contract or arbitrary address).
  AM2 — Value drain: calldata controls the ETH/token amount in an external call
         (attacker drains contract balance via oversized transfer amount).
  AM3 — tx.origin authorization: contract uses tx.origin instead of msg.sender
         for access control (phishing attack: victim's wallet is the tx.origin).
  AM4 — Approve without validation: contract calls approve() or transferFrom()
         without checking msg.sender matches the expected authorized caller.
  AM5 — Unguarded callback: a function marked as a uniswapV3Callback /
         uniswapV2Call / flashLoan callback does not verify the caller is a
         legitimate pool address (arbitrary external contract can trigger it).
"""

BYTECODE_PROMPT_TEMPLATE = """\
You are an expert EVM security auditor analyzing a smart contract from its bytecode.
The source code is NOT available. You are working from decompiled pseudocode and/or
raw disassembly. This contract may be intentionally obfuscated.

{asset_taxonomy}

Obfuscation profile:
  - Assessment: {obfuscation_assessment}
  - Indirect jumps (runtime-computed destinations): {indirect_jumps}
  - Total jump instructions: {total_jumps}
  - Obfuscation score: {obfuscation_score:.2f} (0=clean, 1=fully obfuscated)

Transaction anomaly signals:
{txn_flags}

{rationalizations}

Contract address: {address}
Decompile method: {decompile_method}

--- DECOMPILED CODE / DISASSEMBLY ---
{pseudocode}
--- END ---

Perform a security audit focused on asset management vulnerabilities (AM1–AM5 above).
Also flag any reentrancy (R1–R5), access control (AC1–AC2), or oracle issues if visible.

Respond ONLY with valid JSON matching this schema exactly:
{{
  "contract_type": "MEV Bot | DeFi | Token | Unknown",
  "obfuscation_note": "brief note on what makes analysis difficult",
  "findings": [
    {{
      "taxonomy_code": "AM1|AM2|AM3|AM4|AM5|R1|AC1|...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "function": "function name or 'unknown/selector:0xABCD1234'",
      "description": "precise description of the vulnerability",
      "evidence": "specific opcode pattern, pseudocode line, or txn anomaly",
      "exploitation": "how an attacker exploits this",
      "falsification_attempt": "strongest reason this might NOT be exploitable",
      "confidence": "high|medium|low"
    }}
  ],
  "dismissed_candidates": [
    {{
      "taxonomy_code": "...",
      "reason_dismissed": "why this is NOT a vulnerability"
    }}
  ]
}}

If no findings: return {{"contract_type": "...", "findings": [], "dismissed_candidates": []}}
"""


BYTECODE_PRESCAN_TEMPLATE = """\
You are a fast EVM security triage auditor. You are given decompiled bytecode or raw
disassembly of a closed-source smart contract. Your goal is a QUICK first pass only —
identify suspicious function selectors or code patterns that warrant deeper investigation.

{asset_taxonomy}

Obfuscation profile:
  - Assessment: {obfuscation_assessment}
  - Indirect jumps: {indirect_jumps} / {total_jumps} total
  - Obfuscation score: {obfuscation_score:.2f}

Transaction anomaly signals:
{txn_flags}

Contract address: {address}
Decompile method: {decompile_method}

--- CODE ---
{pseudocode}
--- END ---

Return ONLY valid JSON listing candidates for deeper analysis. Keep it brief:
{{
  "contract_type": "MEV Bot | DeFi | Token | Unknown",
  "candidates": [
    {{
      "am_code": "AM1|AM2|AM3|AM4|AM5|R1|AC1|...",
      "selector": "0xABCD1234 or function name if known",
      "reason": "One sentence: why this looks suspicious"
    }}
  ]
}}

If nothing suspicious: return {{"contract_type": "Unknown", "candidates": []}}
"""


def build_bytecode_prescan_prompt(
    address: str,
    pseudocode: str,
    decompile_method: str,
    cfg_profile: dict,
    txn_flags: list[str],
) -> str:
    """Lightweight Sonnet prescan prompt for bytecode — cheaper first pass."""
    if txn_flags:
        txn_section = "\n".join(f"  - {f}" for f in txn_flags)
    else:
        txn_section = "  - No anomalies detected"

    MAX_CODE_CHARS = 4000  # Tighter budget for prescan
    if len(pseudocode) > MAX_CODE_CHARS:
        pseudocode = pseudocode[:MAX_CODE_CHARS] + "\n\n[... truncated ...]"

    return BYTECODE_PRESCAN_TEMPLATE.format(
        asset_taxonomy=ASSET_MGMT_TAXONOMY,
        obfuscation_assessment=cfg_profile.get("assessment", "unknown"),
        indirect_jumps=cfg_profile.get("indirect_jumps", "?"),
        total_jumps=cfg_profile.get("total_jumps", "?"),
        obfuscation_score=cfg_profile.get("obfuscation_score", 0.0),
        txn_flags=txn_section,
        address=address,
        decompile_method=decompile_method,
        pseudocode=pseudocode,
    )


def build_bytecode_prompt(
    address: str,
    pseudocode: str,
    decompile_method: str,
    cfg_profile: dict,
    txn_flags: list[str],
    candidates: list[dict] | None = None,
) -> str:
    """
    Build the prompt for closed-source / bytecode-level analysis.

    Args:
        address:          Contract address (for context).
        pseudocode:       Decompiled pseudocode or raw disassembly.
        decompile_method: 'panoramix' | 'disassembly_only'.
        cfg_profile:      Output from CFGProfiler.profile().
        txn_flags:        List of anomaly flag strings from TxnAnalyzer.
        candidates:       Optional prescan candidates to focus Opus attention.
    """
    if txn_flags:
        txn_section = "\n".join(f"  - {f}" for f in txn_flags)
    else:
        txn_section = "  - No anomalies detected in transaction history"

    # Truncate pseudocode to ~8000 chars to stay within context budget
    MAX_CODE_CHARS = 8000
    if len(pseudocode) > MAX_CODE_CHARS:
        pseudocode = pseudocode[:MAX_CODE_CHARS] + "\n\n[... truncated ...]"

    prompt = BYTECODE_PROMPT_TEMPLATE.format(
        asset_taxonomy=ASSET_MGMT_TAXONOMY,
        rationalizations=RATIONALIZATIONS_TO_REJECT,
        obfuscation_assessment=cfg_profile.get("assessment", "unknown"),
        indirect_jumps=cfg_profile.get("indirect_jumps", "?"),
        total_jumps=cfg_profile.get("total_jumps", "?"),
        obfuscation_score=cfg_profile.get("obfuscation_score", 0.0),
        txn_flags=txn_section,
        address=address,
        decompile_method=decompile_method,
        pseudocode=pseudocode,
    )

    if candidates:
        lines = ["\nPRESCAN CANDIDATES (prioritize these, but hunt for additional issues):"]
        for c in candidates:
            lines.append(
                f"  [{c.get('am_code', '?')}] {c.get('selector', '?')}: {c.get('reason', '')}"
            )
        prompt = prompt.rstrip() + "\n" + "\n".join(lines) + "\n"

    return prompt
