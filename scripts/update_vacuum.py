import os
import json
import torch
import re
from sentence_transformers import SentenceTransformer
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader

# Resolve paths relative to where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "../audit_reports") # Where you drop new PDFs/JSONs
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "../data")       # Where the brain lives

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("Initializing the Core Memory Bank Update...\n")

# Your absolute source of truth
GOLDEN_SIGNATURES = [
    {
        "name": "Proprietary_Sig_01 - Fixed-Point Division by Zero Trap",
        "context": "Vulnerability Signature: Division by zero via fixed-point math exponentiation. Abstract Pattern: Occurs when an interest rate, fee, or amortization calculation uses an exponential power function where the base evaluates to 1.0 (or its 1e18 fixed-point equivalent). If the rate is 0, the base remains 1e18. The exponentiation helper calculates 1.0^n = 1.0 (1e18). The denominator subsequently subtracts the scale (1e18 - 1e18 = 0), causing an EVM Panic(0x12) Division by Zero error, permanently locking user assets inside the settlement loop."
    },
    {
        "name": "Proprietary_Sig_02 - O(N^2) Iterative Loop Gas Exhaustion",
        "context": "Vulnerability Signature: Unbounded quadratic time complexity O(N^2) in state-changing execution streams. Abstract Pattern: Occurs when an outer function loops over a dynamically sized array or time-based intervals, and calls an internal mathematical helper (like an exponentiation or compounding multiplier) that also uses a manual loop. This nested iteration scales gas consumption exponentially. When executed on multi-year durations or large datasets, it deterministically breaches the EVM block gas limit (30M gas), causing the transaction to permanently revert."
    },
    {
        "name": "Proprietary_Sig_03 - Arbitrary Calldata Swap/Adapter Injection",
        "context": "Vulnerability Signature: Unauthenticated external execution routing and slippage payload injection. Abstract Pattern: Occurs when an entry-point function accepts an arbitrary `bytes calldata` payload from a user and blindly forwards it to a secondary contract, timelock, or whitelisted swap adapter. Because the router does not decode the bytes to enforce minimum output boundaries (slippage limits) or validate the execution path, an attacker can pass malicious swap parameters. This allows them to route the protocol's capital through a manipulated, low-liquidity pool they control, draining the excess buffer."
    }
]

# We start the list with your Golden Signatures
historical_hacks = [sig for sig in GOLDEN_SIGNATURES]

class SoliditySemanticSplitter:
    def __init__(self, chunk_size=1200, chunk_overlap=200):
        self.chunk_size = chunk_size
        self.text_splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)

    def split_solidity(self, text):
        pattern = re.compile(r'(function\s+\w+\s*\(.*?\)\s*(?:public|external|internal|private|pure|view|payable)?\s*(?:returns\s*\(.*?\))?\s*\{)')
        parts = pattern.split(text)
        chunks = []
        current_chunk = ""
        for part in parts:
            if len(current_chunk) + len(part) < self.chunk_size:
                current_chunk += part
            else:
                if current_chunk.strip():
                    chunks.append(current_chunk)
                current_chunk = part
        if current_chunk.strip():
            chunks.append(current_chunk)
        return chunks if len(chunks) > 0 else self.text_splitter.split_text(text)

sol_splitter = SoliditySemanticSplitter()

print(f"🧩 Scanning '{DATA_DIR}' for new audit reports...")

# 1. Process PDF Files
pdf_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.pdf')]
for filename in pdf_files:
    filepath = os.path.join(DATA_DIR, filename)
    try:
        loader = PyPDFLoader(filepath)
        pages = loader.load_and_split()
        for i, page in enumerate(pages):
            text = page.page_content.strip()
            if len(text) > 150 and "Table of Contents" not in text:
                chunks = sol_splitter.split_solidity(text)
                for j, chunk in enumerate(chunks):
                    historical_hacks.append({"name": f"{filename} - Pg {i} - Ch {j}", "context": chunk})
        print(f"  -> Ingested PDF: {filename}")
    except Exception as e:
        print(f"  ❌ Error parsing {filename}: {e}")

# 2. Process JSON Files
json_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.json')]
for filename in json_files:
    filepath = os.path.join(DATA_DIR, filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            text = data.get("content", "")
            if len(text.strip()) > 150:
                chunks = sol_splitter.text_splitter.split_text(text)
                for j, chunk in enumerate(chunks):
                    historical_hacks.append({"name": f"{filename} - Part {j}", "context": chunk})
        print(f"  -> Ingested JSON: {filename}")
    except Exception as e:
        print(f"  ❌ Error parsing {filename}: {e}")

print(f"\n🚀 Total extracted contexts: {len(historical_hacks)}")

print("🧠 Spawning Embedding Engine (BAAI/bge-small-en-v1.5)...")
device = 'cuda' if torch.cuda.is_available() else 'cpu'
embedding_model = SentenceTransformer('BAAI/bge-small-en-v1.5').to(device)

print("⚡ Mapping contexts into Vector Space (this may take a few minutes)...")
context_texts = [hack["context"] for hack in historical_hacks]
db_embeddings = embedding_model.encode(context_texts, convert_to_tensor=True, show_progress_bar=True).to(device)

print(f"💾 Saving updated matrices to '{OUTPUT_DIR}'...")
torch.save(db_embeddings, os.path.join(OUTPUT_DIR, "0xneural_vector_db.pt"))
with open(os.path.join(OUTPUT_DIR, "0xneural_metadata.json"), 'w', encoding='utf-8') as f:
    json.dump(historical_hacks, f)

print("\n✅ Database update complete! You can now restart your app.py server to load the new data.")

import shutil

# 5. Invalidate the Engine Cache
cache_dir = os.path.join(SCRIPT_DIR, "../cache")
if os.path.exists(cache_dir):
    print("🧹 Wiping stale cache to ensure new signatures are applied...")
    shutil.rmtree(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)