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
import google.generativeai as genai
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

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

print("🔌 Booting 0xNeural Enterprise Backend...")

# --- 1. API Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY missing from .env file.")

genai.configure(api_key=GEMINI_API_KEY)
# Using gemini-2.5-flash for maximum context window size and fast execution loops
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

print("✅ System Online and Ready for Concurrent Targets.")

# --- 3. Pydantic Models & Validation Layouts ---
class ScanRequest(BaseModel):
    source_code: str

# Strict JSON Schema forcing the Judge Agent to route outputs deterministically
JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_valid_exploit": {"type": "boolean"},
        "confidence_score": {"type": "integer"},
        "rejection_reason": {"type": "string"},
        "matched_signature": {"type": "string"},
        "vulnerability_explanation": {"type": "string"},
        "foundry_poc": {"type": "string"},
        "remediation_code": {"type": "string"}
    },
    "required": [
        "is_valid_exploit", "confidence_score", "rejection_reason", 
        "matched_signature", "vulnerability_explanation", "foundry_poc", "remediation_code"
    ]
}

# --- 4. Architectural Transformation Utility Filters ---
def clean_query_for_embedding(code: str) -> str:
    """Prevents the Librarian from matching generic modifiers and standard libraries."""
    stopwords = ["ReentrancyGuard", "nonReentrant", "Ownable", "onlyOwner", "SafeMath", "IERC20", "require"]
    cleaned = code
    for word in stopwords:
        cleaned = re.sub(rf'\b{word}\b', '', cleaned, flags=re.IGNORECASE)
    return cleaned

def opsec_anonymize(code: str) -> str:
    """Scrubs project identifier fingerprints to keep source logic payload profiles clear."""
    replacements = {
        r'\bYieldRouter\b': 'TargetContractA',
        r'\bFlashloanVulnerableVault\b': 'TargetContractB',
    }
    anonymized = code
    for pattern, rep in replacements.items():
        anonymized = re.sub(pattern, rep, anonymized)
    return anonymized

# --- 5. Main Asynchronous Inference Core ---
@app.post("/scan")
async def scan_contract(request: ScanRequest):
    if db_embeddings is None:
        raise HTTPException(status_code=500, detail="Librarian database state uninitialized.")

    # A. Check Cache via Hash Signature
    code_hash = hashlib.sha256(request.source_code.encode()).hexdigest()
    cache_path = os.path.join(CACHE_DIR, f"{code_hash}.json")
    if os.path.exists(cache_path):
        print(f"♻️ Cache Hit: {code_hash}")
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    # B. Vector Invariant Context Extraction
    search_query = clean_query_for_embedding(request.source_code)
    # Wrap CPU execution inside an execution pool to preserve loop scaling mechanics
    query_vector = embedding_model.encode(search_query, convert_to_tensor=True).to(device)
    
    scores = F.cosine_similarity(query_vector.unsqueeze(0), db_embeddings)
    safe_k = min(6, len(db_embeddings))
    top_scores, top_indices = torch.topk(scores, k=safe_k)
    
    retrieved_context_payload = ""
    for score, idx in zip(top_scores, top_indices):
        retrieved_context_payload += f"\n--- SOURCE REFERENCE: {historical_hacks[idx.item()]['name']} ---\n{historical_hacks[idx.item()]['context']}\n"
        
    safe_code = opsec_anonymize(request.source_code)

    # C. Shared System Directives Framework
    severity_directives = (
        "CRITICAL DIRECTIVES & SEVERITY THRESHOLDS:\n"
        "You only hunt for High and Critical unprivileged logic flaws (e.g., true Reentrancy, Access Control bypass, Price Oracle manipulation, State manipulation).\n"
        "You MUST IGNORE all QA, Low Severity, and Informational findings. Do NOT flag:\n"
        "- Missing indexed fields, missing event emissions, floating pragmas, or missing zero-address validation checks.\n"
        "- Gas optimizations or single-step ownership transfers (e.g., standard Ownable/OwnableUpgradeable templates).\n"
        "- Centralization risks where an authorized Admin/Owner/Keeper/Whitelisted role must execute an exploit path or make a mistake for a loss to occur. The threat model requires an EXTERNAL, UNPRIVILEGED attacker.\n"
        "- Standard OpenZeppelin ERC4626 design trade-offs (e.g., DECIMALS_OFFSET loss shifting).\n"
        "- Mathematical/Arithmetic assertions in Solidity >= 0.8.0 unless explicit unchecked {} wrappers are breached.\n"
        "- Pull-Based Oracle integrations (e.g., Pyth, RedStone) accepting untrusted data payloads, unless the signature validation logic itself is broken.\n"
        "- Outflow Caps, standard Partial Fills, or explicitly documented developer NatSpec notes detailing accepted risks.\n"
    )

    try:
        # ------------------------------------------------------------------------------------
        # AGENT 1: THE ATTACKER (Asynchronous Logical Fuzzing Strategy Discovery)
        # ------------------------------------------------------------------------------------
        attacker_prompt = (
            f"{severity_directives}\n"
            f"ROLE: You are an aggressive, blackhat security researcher.\n"
            f"TASK: Isolate the single most critical, unprivileged zero-day logic flow vulnerability inside the target code.\n"
            f"HISTORICAL LOGIC DATA:\n{retrieved_context_payload}\n"
            f"TARGET CODE:\n{safe_code}\n\n"
            "OUTPUT: Provide a highly granular structural breakdown of the vulnerability and its precise execution path."
        )
        attacker_response = await model.generate_content_async(attacker_prompt)
        attacker_notes = attacker_response.text

        # ------------------------------------------------------------------------------------
        # AGENT 2: THE DEFENDER (Asynchronous Peer Review & Counter-Invariant Verification)
        # ------------------------------------------------------------------------------------
        defender_prompt = (
            f"{severity_directives}\n"
            f"ROLE: You are a defensive protocol engineer and skeptic.\n"
            f"TASK: Thoroughly debunk the junior auditor's exploit claim. Prove it is a false positive by finding protective modifiers, trusted role constraints, or mathematical rules.\n"
            f"AUDITOR CLAIM:\n{attacker_notes}\n"
            f"TARGET CODE:\n{safe_code}\n\n"
            "OUTPUT: Detail why the claim fails EVM logic or threat models. If the bug is verified and cannot be debunked, state: 'I cannot debunk this finding.'"
        )
        defender_response = await model.generate_content_async(defender_prompt)
        defender_notes = defender_response.text

        # ------------------------------------------------------------------------------------
        # AGENT 3: THE JUDGE (Deterministic Structural Resolution & Property Fuzz Generation)
        # ------------------------------------------------------------------------------------
        judge_prompt = (
            f"ROLE: You are the Chief Information Security Officer presiding over a technical dispute.\n"
            f"TASK: Evaluate the Attacker's claim and the Defender's counter-argument against the target code layout.\n"
            f"ATTACKER INSTIGATION:\n{attacker_notes}\n"
            f"DEFENDER DEBUNK:\n{defender_notes}\n"
            f"TARGET SOURCE CODE:\n{safe_code}\n\n"
            "DECISION METRICS:\n"
            "1. If the Defender's logic stands, or the vulnerability relies on an admin mistake, set 'is_valid_exploit' to false.\n"
            "2. If the Attacker is correct and a true unprivileged zero-day exists, set 'is_valid_exploit' to true.\n"
            "3. If 'is_valid_exploit' is true, you MUST write a complete, compilable Foundry test contract in 'foundry_poc'.\n"
            "4. PROPERTY-BASED FUZZING REQUIREMENT: Do NOT write static test functions. The test function MUST use property-based fuzzing (e.g., function testFuzz_exploit(uint256 amount, address randomUser) public). Use bound constraints like vm.assume() to maintain realistic testing bounds.\n"
        )

        judge_response = await model.generate_content_async(
            judge_prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                response_schema=JUDGE_SCHEMA
            )
        )

        # ------------------------------------------------------------------------------------
        # DETERMINISTIC OUTPUT ROUTING LAYER
        # ------------------------------------------------------------------------------------
        verdict = json.loads(judge_response.text)

        # Enforce automated schema state filtering
        if not verdict["is_valid_exploit"] or verdict["confidence_score"] < 80:
            result = {
                "status": "dropped",
                "reason": verdict["rejection_reason"],
                "report": f"High Value Logic: False\nREJECTION REASON: {verdict['rejection_reason']}"
            }
        else:
            # Format report string for backward compatibility with the orchestrator parser hooks
            constructed_report = (
                f"High Value Logic: True\n\n"
                f"[MATCHED SIGNATURE]: {verdict['matched_signature']}\n\n"
                f"[VULNERABILITY]: {verdict['vulnerability_explanation']}\n\n"
                f"[FOUNDRY POC]:\n```solidity\n{verdict['foundry_poc']}\n```\n\n"
                f"[REMEDIATION]: {verdict['remediation_code']}"
            )
            result = {
                "status": "success",
                "report": constructed_report
            }

        # Sync cache to disk payload frame
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)

        return result

    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="The Judge Agent output violated structural JSON constraints.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Core Processing Loop Fault: {str(e)}")

@app.post("/reload")
async def reload_brain():
    """Forces the API to re-read the vector database concurrently into memory matrix states."""
    global db_embeddings, historical_hacks
    try:
        with open(METADATA_PATH, 'r', encoding='utf-8') as f:
            historical_hacks = json.load(f)
        db_embeddings = torch.load(VECTOR_DB_PATH, map_location=device)
        return {"status": "success", "message": f"Brain matrices re-indexed. {len(historical_hacks)} vectors active."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload vector state: {e}")