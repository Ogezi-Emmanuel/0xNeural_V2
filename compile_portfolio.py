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
    "0x3F0280687c22249c765E425871425eB5C266EdAf.md".lower(): "REENTRANCY_CALLBACK_BYPASS.md", # For legacy 0x3F0
    "0x4BE430401760075315E931dD34b892DFdfc706A7".lower(): "HARDCODED_GAS_FRAGILITY.md",
    "0x55cde53B7dbc24336E34FFE233AF8DF10f72F0Be".lower(): "TRANSITIVE_PRIVILEGE_ESCALATION.md",
    "0xBFC7B60684880457030C08AceE2E675CbcB9d646".lower(): "CROSS_CONTRACT_INITIALIZATION_BLOCK.md",
    "0xca07Ab58e0894B9F116E78d18Fe0Afcd12b73509".lower(): "UNCHECKED_ARITHMETIC_OVERFLOW.md",
    "0xcea7eEa12c6FC82D0318704B9d35A4192C2d260A".lower(): "REENTRANCY_STATE_VIOLATION.md",
    "0xd6982da59F1D26476E259559508f4135135cf9b8".lower(): "STORAGE_CONFIGURATION_FLAW.md"
}

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