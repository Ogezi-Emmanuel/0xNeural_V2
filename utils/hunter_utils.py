# utils/hunter_utils.py
import os
import time
import re
import json
import asyncio
import requests
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from web3 import Web3, AsyncWeb3, WebSocketProvider, AsyncHTTPProvider
from dotenv import load_dotenv

# --- 0. PATH RESOLUTION (OS-AGNOSTIC & PACKAGE-AWARE) ---
UTILS_DIR = Path(__file__).parent.resolve()
BASE_DIR = UTILS_DIR.parent.resolve()  # Stepping one folder up from utils/ to Root

# Dynamic project assets
ENV_PATH = BASE_DIR / ".env"
CONSTANTS_PATH = UTILS_DIR / "constants.json"  

# Load secret keys from .env
load_dotenv(dotenv_path=ENV_PATH)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ALCHEMY_WSS_URL = os.getenv("ALCHEMY_WSS_URL")
ALCHEMY_RPC_URL = os.getenv("ALCHEMY_RPC_URL") # Fallback for async HTTP

# --- ROBUST REQUESTS SESSION ---
# Prevents connection drops and handles rate limits natively for REST APIs
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 429, 500, 502, 503, 504 ])
session.mount('https://', HTTPAdapter(max_retries=retries))

# --- WEB3 CONNECTIONS ---
w3 = None
async_w3 = None

if ALCHEMY_WSS_URL or ALCHEMY_RPC_URL:
    try:
        # Sync provider for legacy functions
        w3 = Web3(Web3.LegacyWebSocketProvider(ALCHEMY_WSS_URL))
        # Async provider for high-throughput pipeline functions
        # Prefer HTTP for async I/O to avoid websocket timeout drops during long LLM inference
        async_provider = AsyncHTTPProvider(ALCHEMY_RPC_URL) if ALCHEMY_RPC_URL else WebSocketProvider(ALCHEMY_WSS_URL)
        async_w3 = AsyncWeb3(async_provider)
    except Exception as e:
        print(f"⚠️ Could not connect Web3 for OSINT: {e}")

# ==========================================
# 🛡️ PIPELINE GATEKEEPER LAYER
# ==========================================
def is_canonical_address(address: str) -> bool:
    if not os.path.exists(CONSTANTS_PATH):
        return False
    try:
        with open(CONSTANTS_PATH, 'r') as f:
            constants = json.load(f)
        whitelist = constants.get("CANONICAL_WHITELIST", [])
        return address.lower() in [addr.lower() for addr in whitelist]
    except Exception as e:
        print(f"⚠️ Ingestion Warning: Error reading constants matrix: {e}")
        return False

def triage_contract_ast(source_code: str, force_bypass: bool = False) -> bool:
    if force_bypass:
        return True
        
    complexity_keywords = [
        r"\bfor\b", r"\bwhile\b", r"\bexecuteOperation\b", r"\bonFlashLoan\b"
    ]
    
    for pattern in complexity_keywords:
        if re.search(pattern, source_code):
            return True
            
    return False

# ==========================================
# 💰 AUTOMATED ECONOMIC TRIAGE (ASYNC)
# ==========================================
async def check_economic_viability(address: str, min_eth: float = 0.01) -> bool:
    """
    Asynchronously verifies contract TVL and activity.
    Uses exponential backoff for RPC rate limits to prevent pipeline crashes.
    """
    if not async_w3 or not await async_w3.is_connected():
        print("   ⚠️ [RPC ERROR] Async Web3 disconnected. Failing open.")
        return True 

    try:
        checksum_addr = AsyncWeb3.to_checksum_address(address)
    except ValueError:
        return False # Invalid address format

    retries = 3
    for attempt in range(retries):
        try:
            # Run I/O bound RPC calls concurrently
            balance_wei, tx_count = await asyncio.gather(
                async_w3.eth.get_balance(checksum_addr),
                async_w3.eth.get_transaction_count(checksum_addr)
            )
            
            balance_eth = float(AsyncWeb3.from_wei(balance_wei, 'ether'))
            
            # Strict Economic Threshold: Must have funds or actual usage
            if balance_eth < min_eth and tx_count <= 2:
                print(f"   [TVL-DROP] 🗑️ {address} is economically dead (Bal: {balance_eth:.4f} ETH, Txs: {tx_count}).")
                return False
                
            print(f"   [TVL-PASS] 💰 {address} is active (Bal: {balance_eth:.4f} ETH, Txs: {tx_count}).")
            return True

        except Exception as e:
            await asyncio.sleep(2 ** attempt) # Exponential backoff
            if attempt == retries - 1:
                print(f"   ⚠️ [RPC TIMEOUT] Failed to fetch TVL for {address}: {e}")
                return True # Fail open to prevent missing a bug due to an RPC drop

# ==========================================
# 🕵️ OSINT FUNCTIONS
# ==========================================
def get_contract_creator(address):
    if not ETHERSCAN_API_KEY: return None, None
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getcontractcreation&contractaddresses={address}&apikey={ETHERSCAN_API_KEY}"
    try:
        res = session.get(url, timeout=10).json()
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
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    url = f"https://api.github.com/search/code?q={address}"
    try:
        res = session.get(url, headers=headers, timeout=10).json()
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
            res = session.get(url, timeout=15).json()
            if res['status'] == '0':
                reason = res.get('result', 'Unknown Error')
                if "Max rate limit" in reason:
                    time.sleep(2 ** attempt) # Exponential backoff for Etherscan limits
                    continue
                return None
                
            if res['status'] == '1' and res['result'] and res['result'][0]['SourceCode'] != "":
                source_code = res['result'][0]['SourceCode']
                
                # Handle Etherscan's nested JSON format for multi-file verification
                if source_code.startswith('{{') and source_code.endswith('}}'):
                    json_code = json.loads(source_code[1:-1])
                    combined_source = ""
                    if 'sources' in json_code:
                        for file_path, content in json_code['sources'].items():
                            combined_source += f"// File: {file_path}\n{content['content']}\n\n"
                        return combined_source
                return source_code
        except Exception as e:
            print(f"   ⚠️ Etherscan Fetch Error: {e}")
            time.sleep(2)
            
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
def send_discord_alert(address, report_summary, osint_raw_text="", verified=False):
    if not DISCORD_WEBHOOK_URL: return
    
    vuln_text = "See local report for details."
    match = re.search(r'\[VULNERABILITY\]:\s*(.*?)(?=\[EXPLOIT PATH\]|\[REMEDIATION\]|$)', report_summary, re.DOTALL)
    if match:
        vuln_text = match.group(1).strip()
        if len(vuln_text) > 1000: vuln_text = vuln_text[:1000] + "..."
    
    # Visual distinction for sandbox-verified vulnerabilities
    title = "🎯 EVM-VERIFIED ZERO-DAY DETECTED!" if verified else "🚨 0xNeural Alert: Vulnerability Found!"
    color = 65280 if verified else 16711680 # Green if verified, Red if static
    
    embed = {
        "title": title,
        "description": f"**Target:** [{address}](https://etherscan.io/address/{address})",
        "color": color,
        "fields": [{"name": "📝 Vulnerability Summary", "value": vuln_text, "inline": False}],
        "footer": {"text": "0xNeural Autonomous Trawler Pipeline"},
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    }

    if osint_raw_text:
        clean_osint = osint_raw_text.replace("## 🕵️ Automated OSINT Dossier\n", "").strip()
        embed["fields"].append({"name": "🕵️ OSINT Dossier", "value": clean_osint, "inline": False})
        
    embed["fields"].append({"name": "📂 Full Report Location", "value": f"`reports/VULN_{address}.md`", "inline": False})

    try:
        session.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
    except Exception:
        pass