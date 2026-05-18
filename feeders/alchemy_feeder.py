# alchemy_feeder.py
import time
import os
from pathlib import Path
from web3 import Web3
from web3.exceptions import Web3Exception
from dotenv import load_dotenv

# --- 0. PATH RESOLUTION (OS-AGNOSTIC) ---
SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_DIR = SCRIPT_DIR.parent.resolve()

# Configuration paths
ENV_PATH = BASE_DIR / ".env"
QUEUE_FILE = BASE_DIR / "target_queue.txt"

# Load secret keys from .env
load_dotenv(dotenv_path=ENV_PATH)

ALCHEMY_WSS_URL = os.getenv("ALCHEMY_WSS_URL")

# Ensure queue file exists
if not os.path.exists(QUEUE_FILE):
    open(QUEUE_FILE, 'w').close()

def connect_to_node():
    """Establishes the WebSocket connection to Alchemy."""
    print("🔌 Connecting to Alchemy WebSockets...")
    w3 = Web3(Web3.LegacyWebSocketProvider(ALCHEMY_WSS_URL))
    if w3.is_connected():
        print("✅ Connected to Ethereum Mainnet!")
        return w3
    else:
        raise ConnectionError("Failed to connect to Alchemy.")

def process_block(w3, block_number):
    """Scans a single block for contract deployment transactions."""
    try:
        block = w3.eth.get_block(block_number, full_transactions=True)
        print(f"🧱 Scanning Block #{block_number} ({len(block.transactions)} txs)...")
        
        contracts_found = 0
        for tx in block.transactions:
            # In EVM, a transaction creates a contract if the 'to' address is empty (None)
            if tx['to'] is None:
                # We must get the receipt to find out what address the network assigned it
                receipt = w3.eth.get_transaction_receipt(tx['hash'])
                contract_address = receipt['contractAddress']
                
                if contract_address:
                    print(f"  🏭 New Contract Deployed: {contract_address}")
                    # Feed the Hunter!
                    with open(QUEUE_FILE, "a") as f:
                        f.write(f"{contract_address}\n")
                    contracts_found += 1
                    
        return contracts_found
    except Exception as e:
        print(f"⚠️ Error processing block {block_number}: {e}")
        return 0

def run_feeder():
    w3 = connect_to_node()
    
    # We use a polling mechanism instead of w3.eth.filter because WebSockets 
    # frequently drop connections after a few hours. Polling is bulletproof for 24/7 runs.
    latest_block_processed = w3.eth.block_number
    print(f"🦇 Alchemy Feeder Online. Starting at block {latest_block_processed}...")

    while True:
        try:
            current_block = w3.eth.block_number
            
            if current_block > latest_block_processed:
                # Catch up if we fell behind
                for block_num in range(latest_block_processed + 1, current_block + 1):
                    process_block(w3, block_num)
                
                latest_block_processed = current_block
                
            # Ethereum blocks take ~12 seconds. Base/Arbitrum take ~2 seconds.
            time.sleep(12) 
            
        except Web3Exception:
            print("❌ Alchemy connection lost. Reconnecting in 5 seconds...")
            time.sleep(5)
            w3 = connect_to_node()
        except KeyboardInterrupt:
            print("\n👋 Shutting down Feeder.")
            break

if __name__ == "__main__":
    if not ALCHEMY_WSS_URL:
        print("CRITICAL: ALCHEMY_WSS_URL missing from .env")
    else:
        run_feeder()