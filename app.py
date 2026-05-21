# app.py
import os
import torch
import json
import re
import torch.nn.functional as F
import hashlib
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
import google.generativeai as genai
from dotenv import load_dotenv

from utils.hunter_utils import triage_contract_ast

# --- 0. PATH RESOLUTION (OS-AGNOSTIC ROOT CONTEXT) ---
BASE_DIR = Path(__file__).parent.resolve()  # SITTING DIRECTLY AT ROOT

ENV_PATH = BASE_DIR / ".env"
CACHE_DIR = BASE_DIR / "cache"
METADATA_PATH = BASE_DIR / "data" / "0xneural_metadata.json"
VECTOR_DB_PATH = BASE_DIR / "data" / "0xneural_vector_db.pt"

# Load secret keys from .env
load_dotenv(dotenv_path=ENV_PATH)

app = FastAPI(title="0xNeural V2 Command Center")

os.makedirs(CACHE_DIR, exist_ok=True)

print("🔌 Booting 0xNeural Backend...")

# --- 1. API Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY missing from .env file.")

genai.configure(api_key=GEMINI_API_KEY)
# We use Flash 2.5 for the massive free tier and blistering speed. 
model = genai.GenerativeModel('gemini-2.5-flash') 

# --- 2. Load the Librarian (Local Vector DB) ---
device = 'cuda' if torch.cuda.is_available() else 'cpu'
print(f"🧠 Loading Vector Database on {device}...")

try:
    with open(METADATA_PATH, 'r', encoding='utf-8') as f:
        historical_hacks = json.load(f)
    db_embeddings = torch.load(VECTOR_DB_PATH, map_location=device)
    embedding_model = SentenceTransformer('BAAI/bge-small-en-v1.5').to(device)
    print(f"✅ Brain Loaded: {len(historical_hacks)} vectors active.")
except Exception as e:
    print(f"⚠️ Warning: Brain files not found in {METADATA_PATH.parent}. Error: {e}")
    historical_hacks = []
    db_embeddings = None

print("✅ System Online and Ready for Targets.")

# --- API Models & Helper Functions ---
class ScanRequest(BaseModel):
    source_code: str

def clean_query_for_embedding(code):
    """Prevents the Librarian from matching generic modifiers."""
    stopwords = ["ReentrancyGuard", "nonReentrant", "Ownable", "onlyOwner", "SafeMath", "IERC20", "require"]
    cleaned = code
    for word in stopwords:
        cleaned = re.sub(rf'\b{word}\b', '', cleaned, flags=re.IGNORECASE)
    return cleaned

def opsec_anonymize(code):
    """Scrubs specific protocol names before sending code to Google's API."""
    replacements = {
        r'\bYieldRouter\b': 'TargetContractA',
        r'\bFlashloanVulnerableVault\b': 'TargetContractB',
        # You can add the specific names of whatever protocol you are hunting here
    }
    anonymized = code
    for pattern, rep in replacements.items():
        anonymized = re.sub(pattern, rep, anonymized)
    return anonymized

# --- Main Inference Endpoint ---
@app.post("/scan")
def scan_contract(request: ScanRequest):
    if db_embeddings is None:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    # 0. Check Cache
    code_hash = hashlib.sha256(request.source_code.encode()).hexdigest()
    cache_path = os.path.join(CACHE_DIR, f"{code_hash}.json")
    if os.path.exists(cache_path):
        print(f"♻️ Cache Hit: {code_hash}")
        with open(cache_path, 'r') as f:
            return json.load(f)

    # Step A: The Librarian (Local Vector Search)
    search_query = clean_query_for_embedding(request.source_code)
    query_vector = embedding_model.encode(search_query, convert_to_tensor=True).to(device)
    
    scores = F.cosine_similarity(query_vector.unsqueeze(0), db_embeddings)
    safe_k = min(6, len(db_embeddings))
    top_scores, top_indices = torch.topk(scores, k=safe_k)
    
    retrieved_context_payload = ""
    for score, idx in zip(top_scores, top_indices):
        retrieved_context_payload += f"\n--- SOURCE REFERENCE: {historical_hacks[idx.item()]['name']} ---\n{historical_hacks[idx.item()]['context']}\n"
        
    # Step B: OPSEC Anonymization
    safe_code = opsec_anonymize(request.source_code)

    # Step C: The Analyst (Gemini API) - UPGRADED WITH SEVERITY THRESHOLDS
    system_instruction = (
        "You are an elite smart contract security auditor specializing in logic-based vulnerabilities. "
        "Your task is to analyze the TARGET SOURCE CODE using the provided HISTORICAL SECURITY REFERENCE DATA.\n\n"
        "*** SEVERITY THRESHOLD (CRITICAL DIRECTIVE) ***\n"
        "You are hunting for High and Critical severity logic flaws ONLY (e.g., Reentrancy, Access Control breaks, MEV Sandwich vectors, Price Oracle manipulation, State manipulation).\n"
        "You MUST IGNORE all QA, Low Severity, and Informational findings. Do NOT generate reports for:\n"
        "- Missing `indexed` fields in events.\n"
        "- Missing event emissions for parameter changes.\n"
        "- Floating pragmas (e.g., ^0.8.0).\n"
        "- Lack of zero-address checks.\n"
        "- Gas optimizations.\n"
        "- Single-step ownership transfers (e.g., standard Ownable/OwnableUpgradeable implementations).\n"
        "- Centralization risks where an Admin must make a mistake for the bug to occur.\n"
        "- Standard OpenZeppelin ERC4626 findings related to `DECIMALS_OFFSET` loss-shifting or empty vault inflation attacks. (These are known design trade-offs).\n"
        "- Swallowed revert reasons, missing error strings, or opaque transaction failures. These are strictly Informational/QA.\n\n"
        "If the ONLY findings in a contract are Low/QA/Informational, you must treat the contract as CLEAN and output 'High Value Logic: False'. Do not generate a vulnerability report for QA noise.\n\n"
        "ANALYSIS PROCESS (Chain of Thought):\n"
        "1. Identify the core logic flow of the target code.\n"
        "2. Centralization risks and Privileged Roles. (e.g., 'Admin can rug pull', 'Owner can mint infinite tokens', 'Keeper executes arbitrary calldata'). Bug bounties require an EXTERNAL, UNPRIVILEGED attacker to exploit the code. If the exploit requires compromising an Owner, Admin, Keeper, or Whitelisted address to execute, DROP IT immediately.\n"
        "3. Look for matching High/Critical logical patterns.\n"
        "4. Standard Proxy Templates. Do NOT flag OpenZeppelin ERC1967Proxy, TransparentUpgradeableProxy, or UUPS contracts for 'uninitialized proxy' or 'front-running initialization' risks. You are auditing the generic template, not the on-chain deployment state. Assume the deployer initialized it correctly. ONLY flag vulnerabilities in custom IMPLEMENTATION logic. \n"
        "5. Mathematical & Economic Reality. In Solidity ^0.8.0, arithmetic operations revert on overflow/underflow unless explicitly wrapped in an `unchecked {}` block. Do not flag standard addition/subtraction as wrap-around exploits unless you can mathematically prove an attacker can realistically supply enough tokens (e.g., >10^50) to hit type(uint256).max. For precision loss, if multiplication occurs before division on heavily scaled numbers (e.g., 1e18), truncation to zero is economically impossible. Do not flag it.\n"
        "6. Pull-Based Oracles. If a function accepts price_data, updateData, or payload as bytes calldata and passes it to an external Oracle contract, assume it is a Pull-Based Oracle (e.g., Pyth, RedStone). Do not flag this as arbitrary user-data injection unless you can mathematically prove the Oracle implementation fails to verify the cryptographic signature.\n"
        "7. Outflow Caps vs DoS. When analyzing variables named capacity, limit, or quota related to withdrawals or borrowing, do not flag missing replenishments on successful execution (e.g., withdraw, borrow, solve). Assume these are Outflow Caps designed to strictly limit volume over time. Only expect replenishments on cancellations or reversals.\n"
        "8. Known Issues & Dev Notes. Do not flag vulnerabilities that are explicitly acknowledged as accepted risks or user errors in the contract's NatSpec or `// dev` comments. (e.g., leaving residual funds on a stateless adapter due to a user not using type(uint256).max is an accepted risk, not a bug).\n"
        "9. Partial Fills. In P2P lending or order-book contracts, if a `borrow` or `activate` function overrides a requested amount with the actual funded amount (e.g., `totalSupply`), this is standard 'Partial Fill' logic. Do not flag this as a malicious unilateral parameter modification.\n"
        "10. Yul Assembly Validation. Strictly validate any inline assembly (Yul) claims against EVM opcode argument requirements before flagging syntax errors in deployed mainnet bytecode. (e.g., `returndatacopy` strictly requires 3 arguments).\n"
        "11. Determine if the target code contains a highly exploitable vulnerability described in a reference.\n\n"
        "STRICT OUTPUT FORMAT:\n"
        "If a HIGH/CRITICAL vulnerability is found:\n"
        "   High Value Logic: True\n"
        "   [MATCHED SIGNATURE]: <Name of the matching SOURCE REFERENCE>\n"
        "   [VULNERABILITY]: <Detailed explanation of the flaw>\n"
        "   [EXPLOIT PATH]: <Step-by-step instructions for an attacker>\n"
        "   [REMEDIATION]: <Specific code recommendations to fix the issue>\n\n"
        "If no vulnerability matches the references, or only low/informational issues exist:\n"
        "   High Value Logic: False\n"
        "   NO VULNERABILITY FOUND\n"
        "Rule: Do not flag msg.sender.transfer() or msg.sender.send() as vulnerable to reentrancy. These methods forward a 2300 gas stipend, making state-modifying reentrancy impossible. Only flag CEI violations as reentrancy if the interaction uses .call. \n"
    )

    prompt = f"{system_instruction}\n\nHISTORICAL SECURITY REFERENCE DATA:\n{retrieved_context_payload}\n\nTARGET SOURCE CODE TO BE SCANNED:\n{safe_code}\n\nTask: Perform a deep logical analysis."
    
    try:
        response = model.generate_content(prompt)
        
        # Safe extraction
        try:
            report_text = response.text.strip()
        except ValueError:
            # This triggers if Google's Trust & Safety filters block the response
            print("🛡️ API blocked response due to safety filters.")
            report_text = "High Value Logic: False\nNO VULNERABILITY FOUND (Blocked by API Safety Filters)"

        result = {"status": "success", "report": report_text}
        
        # Save to Cache
        with open(cache_path, 'w') as f:
            json.dump(result, f)
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reload")
def reload_brain():
    """Forces the API to re-read the database from the hard drive."""
    global db_embeddings, historical_hacks
    try:
        with open(METADATA_PATH, 'r', encoding='utf-8') as f:
            historical_hacks = json.load(f)
        db_embeddings = torch.load(VECTOR_DB_PATH, map_location=device)
        return {"status": "success", "message": f"Brain reloaded. {len(historical_hacks)} vectors active."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload brain: {e}")