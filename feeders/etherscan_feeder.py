# etherscan_feeder.py
import time
import os
import re
from curl_cffi import requests # 🛡️ UPGRADED WEAPON
from bs4 import BeautifulSoup

# --- CONFIG ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
QUEUE_FILE = os.path.join(SCRIPT_DIR, "target_queue.txt")
SEEN_FILE = os.path.join(SCRIPT_DIR, "seen_verified.txt")

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
    """Bypasses Cloudflare by impersonating Chrome's exact TLS cryptographic fingerprint."""
    url = "https://etherscan.io/contractsVerified"
    
    try:
        print(f"\n📡 Executing TLS-Impersonated scrape on Etherscan...")
        
        # 'chrome120' perfectly mimics the handshake of a modern desktop browser
        response = requests.get(url, impersonate="chrome120", timeout=15)
        
        if response.status_code != 200:
            print(f"❌ HTTP Error {response.status_code}. Cloudflare is still blocking.")
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all hrefs that match an Ethereum address pattern
        links = soup.find_all('a', href=re.compile(r'/address/0x[a-fA-F0-9]{40}'))
        
        addresses = []
        for link in links:
            addr_match = re.search(r'0x[a-fA-F0-9]{40}', link.get('href'))
            if addr_match:
                addresses.append(addr_match.group(0))
        
        # Deduplicate the list while preserving order
        return list(dict.fromkeys(addresses))
        
    except Exception as e:
        print(f"❌ Scraping error: {e}")
        return []

def run_feeder():
    print("🎯 0xNeural Etherscan Feeder Initiated.")
    print(f"📂 Piping verified targets to: {QUEUE_FILE}")
    
    seen_addresses = load_seen()
    
    # Ensure queue file exists
    if not os.path.exists(QUEUE_FILE): 
        open(QUEUE_FILE, 'w').close()
    
    while True:
        try:
            new_targets = fetch_verified_contracts()
            added_count = 0
            
            # Append new targets to the queue file for the Hunter to pick up
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
                print(f"⏳ No new verified contracts found. Waiting for next block...")
                
            # Sleep for 60 seconds before scraping again to stay off Cloudflare's radar
            time.sleep(60)
            
        except KeyboardInterrupt:
            print("\n👋 Stopping Etherscan Feeder.")
            break
        except Exception as e:
            print(f"❌ Error in main loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    run_feeder()