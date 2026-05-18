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

def load_seen():
    """Loads previously seen addresses to avoid duplicates."""
    if not os.path.exists(SEEN_FILE): 
        return set()
    with open(SEEN_FILE, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_seen(seen_set):
    """Saves the seen addresses to disk."""
    with open(SEEN_FILE, 'w') as f:
        for addr in seen_set:
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
    print("🎯 0xNeural Blockscout Feeder Initiated.")
    print(f"📂 Piping verified targets to: {QUEUE_FILE}")
    
    seen_addresses = load_seen()
    
    if not os.path.exists(QUEUE_FILE): 
        open(QUEUE_FILE, 'w').close()
    
    while True:
        try:
            new_targets = fetch_verified_contracts()
            added_count = 0
            
            with open(QUEUE_FILE, 'a') as queue:
                for addr in new_targets:
                    if addr not in seen_addresses:
                        queue.write(f"{addr}\n")
                        seen_addresses.add(addr)
                        added_count += 1
                        print(f"   [ADDED] ✅ {addr}")
            
            if added_count > 0:
                save_seen(seen_addresses)
                print(f"📥 Successfully piped {added_count} verified contracts to the Hunter queue.")
            else:
                print(f"⏳ No new verified contracts found on Blockscout. Waiting...")
                
            # Blockscout API is generous, but 30-60 seconds is polite and prevents rate limits
            time.sleep(30)
            
        except KeyboardInterrupt:
            print("\n👋 Stopping Blockscout Feeder.")
            break
        except Exception as e:
            print(f"❌ Error in main loop: {e}")
            time.sleep(30)

if __name__ == "__main__":
    run_feeder()