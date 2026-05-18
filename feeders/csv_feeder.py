# csv_feeder.py
import csv
import os

# Bulletproof pathing
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "export.csv")
QUEUE_FILE = os.path.join(SCRIPT_DIR, "target_queue.txt")

def load_csv_to_queue():
    if not os.path.exists(CSV_FILE):
        print(f"❌ Could not find export.csv in {SCRIPT_DIR}!")
        return

    print("📖 Reading export.csv...")
    addresses = []
    
    with open(CSV_FILE, mode='r', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        next(csv_reader) # Skip the header row
        
        for row in csv_reader:
            # Etherscan CSVs usually have the address in the second column (index 1)
            # or sometimes the first (index 0). We will check both safely.
            for col in row:
                if col.strip().startswith("0x") and len(col.strip()) == 42:
                    addresses.append(col.strip())
                    break # Found the address, move to next row

    if addresses:
        # Remove duplicates
        unique_addresses = list(set(addresses))
        print(f"🎯 Found {len(unique_addresses)} unique historical targets.")
        print("💉 Injecting into Hunter Queue...")
        
        # Append to target queue
        with open(QUEUE_FILE, "a") as f:
            for addr in unique_addresses:
                f.write(f"{addr}\n")
                
        print("✅ Injection complete. The queue is fully loaded!")
    else:
        print("⚠️ No valid addresses found in the CSV.")

if __name__ == "__main__":
    load_csv_to_queue()