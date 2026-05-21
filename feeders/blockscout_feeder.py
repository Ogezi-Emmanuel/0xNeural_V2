# blockscout_feeder.py
import time
import os
import requests
from pathlib import Path

# --- 0. PATH RESOLUTION (OS-AGNOSTIC) ---
SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_DIR = SCRIPT_DIR.parent.resolve()

# Configuration paths
QUEUE_FILE = BASE_DIR / "target_queue.txt"
SEEN_FILE = BASE_DIR / "seen_verified.txt"
MAX_CACHE_SIZE = 500  # Enforces a boundary so the cache file drops old state entries

def load_seen():
    """Loads addresses into a clean, order-preserving Python list to manage window size."""
    if not os.path.exists(SEEN_FILE): 
        return []
    with open(SEEN_FILE, 'r') as f:
        # Filter empty lines and preserve historical order
        return [line.strip() for line in f if line.strip()]

def save_seen(seen_list):
    """Saves only the latest N addresses to disk, automatically purging old entries."""
    # Strict FIFO slice: keeps only the newest entries up to your limit
    trimmed_cache = seen_list[-MAX_CACHE_SIZE:]
    
    with open(SEEN_FILE, 'w') as f:
        for addr in trimmed_cache:
            f.write(f"{addr}\n")

def fetch_verified_contracts():
    """Uses Blockscout's free, open JSON API to get recently verified contracts."""
    # This is the official Blockscout V2 API for Ethereum Mainnet
    url = "https://eth.blockscout.com/api/v2/smart-contracts"
    
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        print(f"\n📡 Requesting verified contracts from Blockscout API...")
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"❌ API Error {response.status_code}: {response.text}")
            return []
            
        data = response.json()
        addresses = []
        
        # Blockscout returns a list of 'items', each containing an 'address' object
        for item in data.get('items', []):
            address_data = item.get('address', {})
            hash_val = address_data.get('hash')
            if hash_val and hash_val.startswith('0x'):
                addresses.append(hash_val)
                
        # Deduplicate while preserving order
        return list(dict.fromkeys(addresses))
        
    except Exception as e:
        print(f"❌ API fetch error: {e}")
        return []

def run_feeder():
    print("🎯 0xNeural Pipeline Ingestion Initiated (Sliding Cache Mode).")
    print(f"📂 Stream target queue tracking destination: {QUEUE_FILE}")
    
    # 1. Initialize our tracking structures on startup
    seen_addresses_list = load_seen()
    seen_set = set(seen_addresses_list)  # Set representation ensures sub-millisecond lookups
    
    if not os.path.exists(QUEUE_FILE): 
        open(QUEUE_FILE, 'w').close()
    
    while True:
        try:
            new_targets = fetch_verified_contracts()
            added_count = 0
            
            # 2. Append unlogged network variants straight to target_queue.txt
            with open(QUEUE_FILE, 'a') as queue:
                for addr in new_targets:
                    if addr not in seen_set:
                        queue.write(f"{addr}\n")
                        seen_addresses_list.append(addr)
                        seen_set.add(addr)
                        added_count += 1
                        print(f"   [QUEUE-INJECT] ✅ {addr}")
            
            if added_count > 0:
                # 3. Enforce the sliding window ceiling on disk
                save_seen(seen_addresses_list)
                
                # 4. Re-sync in-memory tracking footprints
                seen_addresses_list = load_seen()
                seen_set = set(seen_addresses_list)
                print(f"📥 Piped {added_count} fresh targets to target_queue.txt.")
            else:
                print(f"⏳ Duplicate block barrier met. Cycling background indices...")
                
                # TACTICAL FLUSH: If the pipeline completely stalls because upstream API pages 
                # are stagnant, drop the oldest 50 items to force data cycling on the next loop.
                if len(seen_addresses_list) >= MAX_CACHE_SIZE:
                    seen_addresses_list = seen_addresses_list[50:]
                    save_seen(seen_addresses_list)
                    seen_addresses_list = load_seen()
                    seen_set = set(seen_addresses_list)
                
            # Keep polling cycle stable and stay clear of rate limit firewalls
            time.sleep(45)
            
        except KeyboardInterrupt:
            print("\n👋 Halting Feeder Pipeline safely.")
            break
        except Exception as e:
            print(f"❌ Core runtime loop error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    run_feeder()