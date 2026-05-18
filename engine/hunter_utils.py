# hunter_utils.py
import os
import time
import re
import requests
import json
from pathlib import Path
from web3 import Web3
from dotenv import load_dotenv

# --- 0. PATH RESOLUTION (OS-AGNOSTIC) ---
SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_DIR = SCRIPT_DIR.parent.resolve()

# Configuration paths
ENV_PATH = BASE_DIR / ".env"

# Load secret keys from .env
load_dotenv(dotenv_path=ENV_PATH)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ALCHEMY_WSS_URL = os.getenv("ALCHEMY_WSS_URL")

# Web3 Connection
w3 = None
if ALCHEMY_WSS_URL:
    try:
        w3 = Web3(Web3.LegacyWebSocketProvider(ALCHEMY_WSS_URL))
    except Exception as e:
        print(f"⚠️ Could not connect Web3 for OSINT: {e}")

# ==========================================
# 🕵️ OSINT FUNCTIONS
# ==========================================
def get_contract_creator(address):
    if not ETHERSCAN_API_KEY: return None, None
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getcontractcreation&contractaddresses={address}&apikey={ETHERSCAN_API_KEY}"
    try:
        res = requests.get(url).json()
        if res['status'] == '1' and res['result']:
            return res['result'][0]['contractCreator'], res['result'][0]['txHash']
    except Exception:
        pass
    return None, None

def resolve_ens_name(wallet_address):
    if not w3 or not w3.is_connected() or not wallet_address:
        return "Unknown"
    try:
        ens_name = w3.ens.name(wallet_address)
        return ens_name if ens_name else "Anonymous Wallet"
    except Exception:
        return "Anonymous Wallet"

def search_github_for_address(address):
    if not GITHUB_TOKEN: return "No GitHub Token configured."
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    url = f"https://api.github.com/search/code?q={address}"
    try:
        res = requests.get(url, headers=headers).json()
        if 'items' in res and len(res['items']) > 0:
            repo_name = res['items'][0]['repository']['full_name']
            repo_url = res['items'][0]['repository']['html_url']
            return f"{repo_name}\n({repo_url})"
        return "No public repo found."
    except Exception:
        return "GitHub Search Failed."

# ==========================================
# 🔍 ETHERSCAN & TRIAGE
# ==========================================
def fetch_source_code(address):
    if not ETHERSCAN_API_KEY: return None
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={address}&apikey={ETHERSCAN_API_KEY}"
    for attempt in range(3):
        try:
            res = requests.get(url).json()
            if res['status'] == '0':
                reason = res.get('result', 'Unknown Error')
                if "Max rate limit" in reason:
                    time.sleep(5)
                    continue
                return None
            if res['status'] == '1' and res['result'] and res['result'][0]['SourceCode'] != "":
                source_code = res['result'][0]['SourceCode']
                if source_code.startswith('{{') and source_code.endswith('}}'):
                    json_code = json.loads(source_code[1:-1])
                    combined_source = ""
                    if 'sources' in json_code:
                        for file_path, content in json_code['sources'].items():
                            combined_source += f"// File: {file_path}\n{content['content']}\n\n"
                        return combined_source
                return source_code
        except Exception:
            return None
    return None

def triage_contract(source_code):
    if not source_code or len(source_code.split('\n')) < 50: return False
    high_value_patterns = [
        r'delegatecall\(', r'assembly\s*\{', r'getReserves\(', 
        r'flashLoan', r'liquidate', r'twap', r'oracle', r'unchecked\s*\{',
        r'calldata', r'allocateWithSwap', r'Yul', r'permit\(', r'onFlashLoan'
    ]
    for pattern in high_value_patterns:
        if re.search(pattern, source_code, re.IGNORECASE): return True 
    return False

# ==========================================
# 🚨 DISCORD
# ==========================================
def send_discord_alert(address, report_summary, osint_raw_text=""):
    if not DISCORD_WEBHOOK_URL: return
    vuln_text = "See local report for details."
    match = re.search(r'\[VULNERABILITY\]:\s*(.*?)(?=\[EXPLOIT PATH\]|\[REMEDIATION\]|$)', report_summary, re.DOTALL)
    if match:
        vuln_text = match.group(1).strip()
        if len(vuln_text) > 1000: vuln_text = vuln_text[:1000] + "..."
    
    embed = {
        "title": "🚨 0xNeural Alert: Vulnerability Found!",
        "description": f"**Target:** [{address}](https://etherscan.io/address/{address})",
        "color": 16711680,
        "fields": [{"name": "📝 Vulnerability Summary", "value": vuln_text, "inline": False}],
        "footer": {"text": "0xNeural Autonomous Trawler Pipeline"},
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    }

    if osint_raw_text:
        clean_osint = osint_raw_text.replace("## 🕵️ Automated OSINT Dossier\n", "").strip()
        embed["fields"].append({"name": "🕵️ OSINT Dossier", "value": clean_osint, "inline": False})
        
    embed["fields"].append({"name": "📂 Full Report Location", "value": f"`reports/VULN_{address}.md`", "inline": False})

    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
    except Exception:
        pass