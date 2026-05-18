# ingest_hack.py
import os
import json
import torch
import argparse
from pathlib import Path
from sentence_transformers import SentenceTransformer
import shutil

# --- 0. PATH RESOLUTION (OS-AGNOSTIC) ---
SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_DIR = SCRIPT_DIR.parent.resolve()

# Configuration paths
DATA_DIR = BASE_DIR / "data"
AUDIT_REPORTS_DIR = BASE_DIR / "audit_reports"
CACHE_DIR = BASE_DIR / "cache"

METADATA_FILE = DATA_DIR / "0xneural_metadata.json"
VECTOR_DB_FILE = DATA_DIR / "0xneural_vector_db.pt"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(AUDIT_REPORTS_DIR, exist_ok=True)

def ingest(name, context):
    print(f"🧠 Ingesting new knowledge: {name}...")
    
    # --- ADD THIS: The Hard Drive Backup ---
    # Save a permanent copy to the vacuum folder so it survives database rebuilds
    backup_filename = AUDIT_REPORTS_DIR / f"MANUAL_INGEST_{name.replace(' ', '_')}.json"
    with open(backup_filename, 'w', encoding='utf-8') as f:
        json.dump({"content": context}, f, indent=4)
    print(f"💾 Permanent backup saved to {backup_filename}")
    # ---------------------------------------

    # 1. Load existing data
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    else:
        metadata = []

    # 2. Add new entry
    new_entry = {"name": name, "context": context}
    metadata.append(new_entry)

    # 3. Handle Embeddings efficiently (O(1) insertion)
    print("🔄 Updating vector database...")
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = SentenceTransformer('BAAI/bge-small-en-v1.5').to(device)
    
    # Only encode the new context
    new_embedding = model.encode([context], convert_to_tensor=True).to(device)
    
    # Load existing tensor and append the new one
    if os.path.exists(VECTOR_DB_FILE):
        existing_embeddings = torch.load(VECTOR_DB_FILE, map_location=device)
        updated_embeddings = torch.cat((existing_embeddings, new_embedding), dim=0)
    else:
        updated_embeddings = new_embedding

    # 4. Save
    torch.save(updated_embeddings, VECTOR_DB_FILE)
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=4)
    
    # 5. Invalidate the Engine Cache
    if os.path.exists(CACHE_DIR):
        print("🧹 Wiping stale cache to ensure new signatures are applied...")
        shutil.rmtree(CACHE_DIR)
        os.makedirs(CACHE_DIR, exist_ok=True)

    print(f"✅ Successfully added '{name}'. Total brain size: {len(metadata)} entries.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest new security context into 0xNeural Brain")
    parser.add_argument("--name", required=True, help="Short name/ID of the vulnerability")
    parser.add_argument("--context", required=True, help="Full description of the exploit logic")
    
    args = parser.parse_args()
    ingest(args.name, args.context)
