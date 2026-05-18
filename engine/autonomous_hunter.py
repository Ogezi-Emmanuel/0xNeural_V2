# autonomous_hunter.py
import time
import os
import json
import requests

# Import all the heavy lifting from our new utils file
from hunter_utils import (
    fetch_source_code, triage_contract, get_contract_creator,
    resolve_ens_name, search_github_for_address, send_discord_alert
)

# --- CONFIG ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_API_URL = "http://127.0.0.1:8000/scan"

QUEUE_FILE = os.path.join(SCRIPT_DIR, "target_queue.txt")
WAITING_ROOM_FILE = os.path.join(SCRIPT_DIR, "waiting_room.json")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")
LOGS_DIR = os.path.join(SCRIPT_DIR, "logs")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ==========================================
# 📥 QUEUE HELPERS
# ==========================================
def load_waiting_room():
    if os.path.exists(WAITING_ROOM_FILE):
        try:
            with open(WAITING_ROOM_FILE, 'r') as f: return json.load(f)
        except json.JSONDecodeError: return {}
    return {}

def save_waiting_room(data):
    with open(WAITING_ROOM_FILE, 'w') as f: json.dump(data, f, indent=4)

def get_target_from_queue():
    if not os.path.exists(QUEUE_FILE) or os.path.getsize(QUEUE_FILE) == 0: return None
    try:
        with open(QUEUE_FILE, 'r') as f: lines = f.readlines()
        if not lines: return None
        
        target = None
        remaining_lines = []
        for line in lines:
            if not target and line.strip().startswith('0x'): target = line.strip()
            else: remaining_lines.append(line)
                
        if target:
            with open(QUEUE_FILE, 'w') as f: f.writelines(remaining_lines)
        return target
    except Exception:
        return None


# ==========================================
# 🧠 CORE SCANNING LOGIC
# ==========================================
def scan_address(address, force=False):
    print(f"\n🔍 Hunting target: {address}...")
    
    # 1. Fetch & Triage
    source_code = fetch_source_code(address)
    if not source_code:
        print(f"   [SKIPPED] 🗑️ No code returned from Etherscan API. Dropping target.")
        return "DONE" 

    is_high_value = triage_contract(source_code)
    if not is_high_value and not force:
        print(f"⏭️ Skipped {address} - Standard code.")
        return "DONE"

    # 2. OSINT Bouncer
    print(f"🕵️ Running OSINT checks before Engine analysis...")
    creator_wallet, tx_hash = get_contract_creator(address)
    
    # 🛑 KILL SWITCH 1: Factory Deployments (Uniswap Pairs, Proxies, etc.)
    if str(creator_wallet).lower() in ["none", "unknown", "", "null"]:
        print(f"   [BLOCKED] 🗑️ Dropping {address} (Factory Deployed / Infrastructure).")
        return "DONE"
        
    ens_name = resolve_ens_name(creator_wallet) if creator_wallet else "Unknown"
    github_repo = search_github_for_address(address)
    
    # 🛑 KILL SWITCH 2: The "High-Signal" Filter
    is_unknown_identity = ("Anonymous Wallet" in ens_name or "Unknown" in ens_name)
    has_no_repo = ("No public repo found" in github_repo or "Failed" in github_repo)
    
    if is_unknown_identity and has_no_repo:
        print(f"   [BLOCKED] 🗑️ Dropping {address} (No Identity + No Repo = No Bounty).")
        with open(os.path.join(LOGS_DIR, "dropped_scams.txt"), "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address} (Low Signal)\n")
        return "DONE" 

    # 3. Ask the LLM Engine
    print(f"   [APPROVED] 🚀 Sending to 0xNeural Engine...")
    try:
        response = requests.post(LOCAL_API_URL, json={"source_code": source_code}, timeout=120)
        
        if response.status_code == 200:
            report = response.json().get('report', '')
            
            # 4. Severity Filter
            if "High Value Logic: False" in report:
                print(f"   [TRASHED] 📉 Engine found only QA/Low-Severity noise.")
                return "DONE"

            # 5. Payout / Reporting
            print(f"🎯 VULNERABILITY FOUND! Saving report...")
            filename = os.path.join(REPORTS_DIR, f"VULN_{address}.md")
            osint_data = (
                f"\n\n## 🕵️ Automated OSINT Dossier\n"
                f"- **Deployer Wallet:** `{creator_wallet}`\n"
                f"- **Deployer ENS:** `{ens_name}`\n"
                f"- **Creation Tx:** `{tx_hash}`\n"
                f"- **Likely GitHub Repo:** {github_repo}\n"
            )
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Audit Report: {address}\n**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n**High Value Logic:** True\n\n")
                clean_report = report.replace("High Value Logic: True\n", "").strip()
                f.write(clean_report)
                f.write(osint_data)
                
            send_discord_alert(address, clean_report, osint_data)
            return "DONE"
            
        elif response.status_code == 500:
            print(f"   ⚠️ [API LIMIT] Engine returned HTTP 500. Gemini quota reached.")
            return "RATE_LIMIT"
            
        else:
            print(f"❌ Engine error: {response.status_code}")
            return "DONE"
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to Engine. Is app.py running?")
        return "DONE"


# ==========================================
# 📥 QUEUE MANAGEMENT
# ==========================================
def run_queue_mode():
    print(f"🦇 Queue Mode Active. Watching '{QUEUE_FILE}'...")
    if not os.path.exists(QUEUE_FILE): open(QUEUE_FILE, 'w').close()

    # Waiting Room is now exclusively for Gemini 500 Rate Limits
    MAX_RETRIES = 12 
    last_retry_time = 0
    RETRY_INTERVAL = 300 

    while True:
        try:
            pending_retries = load_waiting_room()
            target = get_target_from_queue()
            
            if target:
                if target not in pending_retries:
                    status = scan_address(target)
                    
                    if status == "RATE_LIMIT":
                        print(f"   [WAITING] ⏳ Moving {target} to Waiting Room until API quota resets.")
                        pending_retries[target] = 0
                        save_waiting_room(pending_retries)
                
                time.sleep(1)
            else:
                time.sleep(10)

            current_time = time.time()
            if pending_retries and (current_time - last_retry_time > RETRY_INTERVAL):
                print(f"\n🔄 Checking {len(pending_retries)} rate-limited targets in the Waiting Room...")
                
                for addr in list(pending_retries.keys()):
                    status = scan_address(addr)
                    
                    if status == "RATE_LIMIT":
                        print(f"   [WAITING] ⏳ API still limited. Retry {pending_retries[addr] + 1}/{MAX_RETRIES}")
                        pending_retries[addr] += 1
                        
                        if pending_retries[addr] >= MAX_RETRIES:
                            print(f"   [TIMEOUT] 🗑️ Dropping {addr} - Exceeded waiting limit.")
                            del pending_retries[addr]
                    else:
                        del pending_retries[addr]
                        
                    time.sleep(1) 
                    
                save_waiting_room(pending_retries)
                last_retry_time = time.time()

        except KeyboardInterrupt:
            print("\n👋 Stopping Hunter.")
            break
        except Exception as e:
            print(f"❌ Error in queue loop: {e}")
            time.sleep(10)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="0xNeural V2 Autonomous Hunter")
    parser.add_argument("target", nargs="?", help="Contract address, file path, or 'queue'")
    parser.add_argument("--force", action="store_true", help="Skip triage and scan regardless of logic complexity")
    args = parser.parse_args()

    if not args.target or args.target == "queue":
        run_queue_mode()
    elif os.path.isfile(args.target):
        with open(args.target, 'r') as f:
            addresses = [line.strip() for line in f if line.strip().startswith('0x')]
        for addr in addresses:
            scan_address(addr, force=args.force)
            time.sleep(1)
    else:
        scan_address(args.target, force=args.force)