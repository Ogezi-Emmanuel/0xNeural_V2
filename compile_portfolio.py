# compile_portfolio.py
import os
import re
from pathlib import Path

# --- 0. PATH RESOLUTION ---
BASE_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = BASE_DIR / "reports"
POC_DIR = BASE_DIR / "proof_of_concept_reports"

os.makedirs(POC_DIR, exist_ok=True)

# Static dictionary mapping real addresses to your anonymized filenames
# This matches the exactly generated 10 proof files in your portfolio catalog
VULN_MAPPING = {
    "0x0f36d67D4153549CdeE55Ca94c43E6Fd28126962".lower(): "UNHANDLED_RETURN_STATE.md",
    "0x2a323be63e08E08536Fc3b5d8C6f24825e68895e".lower(): "MISSING_ACCESS_CONTROL_BRIDGE.md",
    "0x3A44A3b263FB631cdbf25f339e2D29497511A81f".lower(): "PROXY_FUNCTION_SHADOWING.md",
    "0x3F0280687c22249c765E425871425eB5C266EdAf".lower(): "REENTRANCY_CALLBACK_BYPASS.md", # For legacy 0x3F0
    "0x4BE430401760075315E931dD34b892DFdfc706A7".lower(): "HARDCODED_GAS_FRAGILITY.md",
    "0x55cde53B7dbc24336E34FFE233AF8DF10f72F0Be".lower(): "TRANSITIVE_PRIVILEGE_ESCALATION.md",
    "0xBFC7B60684880457030C08AceE2E675CbcB9d646".lower(): "CROSS_CONTRACT_INITIALIZATION_BLOCK.md",
    "0xca07Ab58e0894B9F116E78d18Fe0Afcd12b73509".lower(): "UNCHECKED_ARITHMETIC_OVERFLOW.md",
    "0xcea7eEa12c6FC82D0318704B9d35A4192C2d260A".lower(): "REENTRANCY_STATE_VIOLATION.md",
    "0xd6982da59F1D26476E259559508f4135135cf9b8".lower(): "STORAGE_CONFIGURATION_FLAW.md",
    "0x6d0311699092A40AA952879061eECA01dDf3F0A8".lower(): "UNPROTECTED_V4_SWAP_SLIPPAGE.md",
    "0xf2709c559785cf4d1aa9c9a0ad6e0bb413afdf7a".lower(): "REENTRANCY_PROXY_INITIALIZER_EXPLOIT.md",
    "0x268305a14012591dc0ae8e59c722d60445e96dad".lower(): "IMPLICIT_ACCESS_CONTROL_REDEEM_DOS.md",
    "0x3286b881351551344de07e3f361a019a5a8540c9".lower(): "MISSING_ACCESS_CONTROL_DEPOSIT_CAP.md",
    "0xfd9862ffd1f4b444d799a31220f8d4c9787aa799".lower(): "UNTRUSTED_SETTLEMENT_ASSET_MANIPULATION.md",
    "0x0378627f24bd354346832f68b022b36349bbb528".lower(): "UNHANDLED_EXTERNAL_RETURN_DEFICIT.md",
    "0xa5d2cdd29e027432a959488811e6773581b0f304".lower(): "AUTOMATION_DATA_SPOOFING_BYPASS.md"
}

# Day 5 Extensions - Additional Findings
VULN_MAPPING.update({
    # OCAS: Trait Probability Overriding Logic Bugs
    "0x6aa34ba07ec9e1b95c975d93ceb2a0d8ec7305dc": "CONFLICTING_TRAIT_PROBABILITY.md",
    "0x43fea9c36c23b60e14499a577a497508c3673bb0": "CONFLICTING_TRAIT_PROBABILITY_ALT.md",

    # OCAS: Permanent Metadata Elimination on Burn History
    "0x1095c73c33cc5e03f9e1d426c524cc3e32a50f6": "BURNS_HISTORY_DATA_LOSS.md",

    # OCAS: Premature SVGRenderer State Initialization
    "0x3fcbf4e34aead9128b07831b66728be5085d2e0": "PREMATURE_SVG_RENDER_QUERY.md",

    # Wormhole Transceiver: Supply Chain Dependency Vulnerability
    "0xbaf40ad16071871ac05633ff7428b238913dc923": "UNOFFICIAL_SDK_SUPPLY_CHAIN.md"
})

# Day 5 Ingestion Update - Morning through Afternoon Run
VULN_MAPPING.update({
    # OCAS/Traits: Conflicting Probability Distribution Overrides
    "0x6aa34ba07ec9e1b95c975d93ceb2a0d8ec7305dc": "CONFLICTING_TRAIT_PROBABILITY.md",
    "0x43fea9c36c23b60e14499a577a497508c3673bb0": "CONFLICTING_TRAIT_PROBABILITY_ALT.md",

    # OCAS Machine: Permanent Destruction of Finalized Provenance Records
    "0x1095c73c33cc5e03f9e1d426c524cc3e32a50f6": "HISTORICAL_BURN_DATA_ERASURE.md",

    # OCAS Renderer: Premature SVG State Querying Exploits
    "0x3fcbf4e34aead9128b07831b66728be5085d2e0": "PREMATURE_SVG_RENDER_QUERY.md",

    # BirdWatcher Automation: Untrusted Calldata performData Injection
    "0x43826f890b2dc00675d15d66fa5ec9E473341999": "AUTOMATION_DATA_SPOOFING_BYPASS.md",

    # Wormhole Transceiver: Unofficial SDK Package Dependency Risk
    "0xbaf40ad16071871ac05633ff7428b238913dc923": "UNOFFICIAL_SDK_SUPPLY_CHAIN.md",

    # AddressBook Proxy: Inconsistent Upgrade Authority / Shadow UUPS Control
    "0x57ade7d5e9d2f45a07f8039da7228acc305fbeaf": "PROXY_SHADOW_UPGRADE_AUTHORITY.md",

    # PToken: Missing Implementation Initializer Lockout Hijack
    "0x9b88802823f49a213dd768719f0958c982786824": "UNLOCKED_IMPLEMENTATION_INITIALIZER.md",

    # PayingProxy: Constructor-Level External Call Reentrancy Hijack
    "0x567725581c7518d86c7d163dd579b2c4258337d0": "CONSTRUCTOR_EXTERNAL_CALL_REENTRANCY.md",

    # LendPool: Non-Additive Global Pause Duration Time Distortion
    "0x99a3995abf912dc362b0a9552faa7a69c7ea9202": "NON_ADDITIVE_PAUSE_TIME_DISTORTION.md",

    # Synthetix Module: CEI Violation with External Distribution Call
    "0x8f0e3e1f0e1f444f780d6dd11d0a3d9c16b5be01": "MINT_DISTRIBUTION_REENTRANCY_CEI.md",

    # ReserveOracle: Truncated TWAP Calculation Window / Stale Oracle Fallback
    "0x5403d04a7cc08744022c0f4c516c2819d06fcbd9": "TRUNCATED_TWAP_PRICE_MANIPULATION.md"
})

# Weekend Engine Sweep - Ingestion Index
VULN_MAPPING.update({
    # Vault Solvency: Classic CEI Violation via SafeERC20 Call
    "0x4b82c33692a87daebc9c27817e3364e2398907ea": "VAULT_SOLVENCY_REENTRANCY.md",

    # MoreVaultsLib: Flawed Whitelist Deposit Cap Addition Math
    "0x9084cc13dff1102b147bcff816ee7f7622a8717c": "WHITELIST_ECONOMIC_CAP_FLAW.md",

    # LombardBtc: Quadratic Gas Accumulation DoS via abi.encodePacked
    "0x17d3652758c839bad55cc8775a3fda03b151c7fc": "QUADRATIC_GAS_ROUTER_DOS.md",

    # TaxDistributor: Hardcoded Zero-Slippage Automated AMM Swaps
    "0xbb843b111639b9f19e575e3804b7c006ee1f80a9": "TAX_AUTOMATION_SLIPPAGE_MEV.md",

    # TokenSale: Missing Refund Slippage Protection via Trusted Zap
    "0x674a745adb09c3333d655cc63e2d77acbe6de935": "TOKEN_SALE_REFUND_SLIPPAGE.md"
})

# Day 8 - Evening Consolidation Ingestion Run
VULN_MAPPING.update({
    # NFT Staking/Rewards: Unbounded claiming index gas exhaustion DoS
    "0x8b35a9e104ab791495653ce28050b3e52f0a0e3b": "NFT_CLAIM_LOOP_GAS_DOS.md",

    # ERC1967 Proxy: Assertion failure due to storage slot string mismatch
    "0x8e277fb10f76c73f97241fe16aece0f817e487de": "PROXY_SLOT_ASSERTION_REVERT.md",

    # Harvest Strategy: Complete omission of slippage bounds in Curve/UniV3
    "0xe37d0de73125af8ce56ef56dc948845779356208": "HARVEST_ZERO_SLIPPAGE_MEV.md",

    # MultiPath Router: Self-bricking external address call for missing hasRole
    "0xa7465ccd97899edcf11c56d2d26b49125674e45f": "UNIMPLEMENTED_SELECTOR_SELF_BRICK.md",

    # PairPriceOracle: Early return logic flaw bypassing TWAP verification
    "0x41718d90b2889be621f17a7f7801aa1bbd9c6840": "ORACLE_TWAP_VALIDATION_BYPASS.md"
})

# Day 8 Consolidated Evening Ingestion Map
VULN_MAPPING.update({
    # Uniswap V2: Vulnerable spot reserve price calculation vector
    "0x1cd632e48bebbda94ea0431fb8979c3012e186e9": "SPOT_RESERVE_ORACLE_MANIPULATION.md",

    # Aladdin Staking: Inflationary economic reentrancy mint loop
    "0x1cca80c17e9155eb1f5a1df52ef92cc551a4b816": "ALADDIN_INFLATION_REENTRANCY.md",

    # BaseStrategy: Fee-on-transfer residual asset storage lock
    "0xe9bb64f916f2f4b5f946688ff28d222915a19e12": "FEE_ON_TRANSFER_STRATEGY_LOCK.md",

    # Controller: Migration state valuation lag vulnerability
    "0xa0c500ed25a88640f250c55da7299c3345637f5e": "CONTROLLER_VALUATION_LAG_BLIND_SPOT.md",

    # MerkleDistributor2: Self-destructive token burn recovery mechanism
    "0xaa4b07bf68e007af0b4d2a55fbec1744b314b840": "RECOVERY_TYPO_TOKEN_BURN.md"
})

# Day 8 Late-Night Ingestion Run - Bytecode Invariant Extensions
VULN_MAPPING.update({
    # HundredVesting: Math truncation leading to permanent asset locking
    "0x6edcb931168c9f7c20144f201537c0243b19dca4": "VESTING_INTEGER_TRUNCATION.md",

    # ERC1155Creator: Un-deployed logic contract front-running proxy hijack
    "0x0239a6a823cbb789c235a53364d91fafc6c1b557": "HARDCODED_PROXY_HIJACK_RACE.md",

    # SigmaIndexPoolV1: First-depositor pool share math inflation vulnerability
    "0x7b3b2b39cbdbddadc13d8559d82c054b9c2fd5f3": "FIRST_DEPOSITOR_POOL_INFLATION.md",

    # Implementation Alpha: onlyConstructor code size check factory revert
    "0x0055b3a718ca5722f38771d7146b3f190f4d6452": "PROXY_FACTORY_CODE_SIZE_REVERT.md",

    # Implementation Beta: onlyConstructor modifier structural self-brick
    "0x0bc51c36b3a4543f9e8f3c5d1ccb6a8df10cc09a": "PROXY_FACTORY_CODE_SIZE_REVERT_ALT.md"
})

# Day 8 Late-Night Extensions - Invariant Validation Mapping
VULN_MAPPING.update({
    # RouterModuleVLSDT: Delegatecall arbitrary token approval drain
    "0x8155b8858af2b12baf8a79e22021b14f91557707": "DELEGATECALL_APPROVAL_DRAIN.md",

    # CurveStableSwapNG: Division-by-zero math core AMM freeze DoS
    "0x47ab5f9d8c9c7d002a92320f23a696D348C56A7F": "CORE_AMM_DIV_ZERO_DOS.md",

    # Implementation Gamma: onlyConstructor code length factory mismatch
    "0x0a1754d37774e83fd483d7c80ee71e4e4176c6d8": "FACTORY_MODIFIER_SELF_BRICK.md",

    # Implementation Delta: onlyConstructor initialization proxy failure
    "0x070e30b077f6742d745a3e27b6e2efabd80d8467": "FACTORY_MODIFIER_SELF_BRICK_ALT.md",

    # Implementation Epsilon: onlyConstructor modifier runtime code size revert
    "0x819d271cc14568692dbc91b45d8620f76ccdf1b9": "FACTORY_MODIFIER_SELF_BRICK_VAR.md"
})

# Day 8 Late-Night Final Extension Sweep
VULN_MAPPING.update({
    # ERC1155Creator: Missing implementation initializer guard on JTD clone
    "0x30098ee5494c94a1c9e08b8a38c47956b029a7e5": "PROXY_IMPLEMENTATION_HIJACK.md",

    # NFTStrategyHook: Missing nonReentrant mutex on Uniswap V4 afterSwap hook
    "0x4105f6339849e9ba7ca7c0ca4b762803341328c4": "UNISWAP_V4_HOOK_REENTRANCY.md",

    # CanonGuard: Public execution delegatecall exploit vector for Gnosis Safe
    "0x656c264f914bd8Fe7bbAfb9B4F2EBcB4f259F67C": "GNOSIS_SAFE_GUARD_ETHER_DRAIN.md",

    # CurveConvexStratBaseMk3_NG: Unincremented state variable breaking revenue fees
    "0x647b54a713a73a9c9ef34ba238877f4ededd1489": "BROKEN_REVENUE_FEE_COLLECTION.md"
})

def sanitize_and_format_content(raw_text, filename_poc):
    """
    Parses live report layout sections, scrubs production data signatures,
    and returns a clean, abstract white-hat engineering report structure.
    """
    # 1. Strip the live title header block completely
    # Pattern looks for lines starting with "# Audit Report:"
    text = re.sub(r"# Audit Report:.*?\n", "", raw_text, flags=re.IGNORECASE)
    
    # 2. Strip scan dates and static metadata rows
    text = re.sub(r"\*\*Scan Date:\*\*.*?\n", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\*\*High Value Logic:\*\*.*?\n", "", text, flags=re.IGNORECASE)
    
    # 3. Strip Etherscan-style matched signatures or PDF tracker indexes if present
    text = re.sub(r"\[MATCHED SIGNATURE\]:.*?\n", "", text, flags=re.IGNORECASE)
    
    # 4. Extract standard vulnerability sections cleanly
    vuln_match = re.search(r"\[VULNERABILITY\]:(.*?)(?=\[EXPLOIT PATH\]|$)", text, re.DOTALL | re.IGNORECASE)
    exploit_match = re.search(r"\[EXPLOIT PATH\]:(.*?)(?=\[REMEDIATION\]|$)", text, re.DOTALL | re.IGNORECASE)
    rem_match = re.search(r"\[REMEDIATION\]:(.*?)(?=## 🕵️|$)", text, re.DOTALL | re.IGNORECASE)
    
    vuln_content = vuln_match.group(1).strip() if vuln_match else "Analysis pending system verification frame."
    exploit_content = exploit_match.group(1).strip() if exploit_match else "Exploit trace mapping isolated locally."
    rem_content = rem_match.group(1).strip() if rem_match else "Apply defensive access control bounds."
    
    # 5. Extract customized title headers based on specific portfolio files
    title_name = filename_poc.replace(".md", "").replace("_", " ").title()
    
    # 6. Rebuild the file inside your public template schema layout
    sanitized_markdown = f"""# Vulnerability Report: {title_name}

**Vulnerability Category:** {title_name} Analysis 
**Severity:** High / Medium Invariant Variance
**Impact:** Structural Protocol Inconsistency Verification Flow

---

## 1. Technical Analysis
{vuln_content}

---

## 2. Theoretical Exploit Scenario
{exploit_content}

---

## 3. Remediation
{rem_content}
"""
    # 7. Final deep scrub to clear any stray hex addresses or hashes anywhere in text
    sanitized_markdown = re.sub(r"0x[a-fA-F0-9]{40}", "[ANONYMIZED_ADDRESS]", sanitized_markdown)
    sanitized_markdown = re.sub(r"0x[a-fA-F0-9]{64}", "[ANONYMIZED_HASH]", sanitized_markdown)
    
    return sanitized_markdown

def run_compilation_pipeline():
    print("🚀 Initiating 0xNeural V2 Automated Portfolio Compiler...")
    
    if not os.path.exists(REPORTS_DIR):
        print(f"❌ Target reports directory folder missing at: {REPORTS_DIR}")
        return
        
    compiled_count = 0
    
    # Iterate through files in the live logs/reports directory
    for file in os.listdir(REPORTS_DIR):
        if not file.endswith(".md"):
            continue
            
        file_path = REPORTS_DIR / file
        
        # Isolate the address from file format name structure (e.g., VULN_0x123...md)
        addr_match = re.search(r"0x[a-fA-F0-9]{40}", file)
        if not addr_match:
            continue
            
        target_address = addr_match.group(0).lower()
        
        # Route to your clean destination file based on the validation matrix mapping
        if target_address in VULN_MAPPING:
            poc_filename = VULN_MAPPING[target_address]
            poc_path = POC_DIR / poc_filename
            
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_report = f.read()
                
            # Compile and scrub the raw report into the anonymous format
            clean_markdown = sanitize_and_format_content(raw_report, poc_filename)
            
            with open(poc_path, 'w', encoding='utf-8') as f:
                f.write(clean_markdown.strip() + "\n")
                
            print(f"  Processed: {file} ➡️ {poc_filename}")
            compiled_count += 1

    print(f"\n🎯 Portfolio generation loop complete! Compiled {compiled_count} public files inside '{REPORTS_DIR.name}/'!")

if __name__ == "__main__":
    run_compilation_pipeline()