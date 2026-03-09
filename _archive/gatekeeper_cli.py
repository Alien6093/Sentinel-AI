import sys
import json
import time
import subprocess

LEDGER_FILE = "access_ledger.json"

def read_ledger():
    try:
        with open(LEDGER_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

def write_ledger(data):
    try:
        with open(LEDGER_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error writing ledger: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python gatekeeper_cli.py <command>")
        sys.exit(1)
        
    command = sys.argv[1:]
    
    ledger = read_ledger()
    if not ledger:
        print("Error reading access ledger.")
        sys.exit(1)
        
    if ledger.get("status") == "UNLOCKED":
        subprocess.run(command)
        sys.exit(0)
        
    if ledger.get("status") == "LOCKED":
        print("\033[91m[UNAUTHORIZED] E-1 Level detected. Requesting E-4 Manager approval...\033[0m")
        ledger["status"] = "PENDING"
        write_ledger(ledger)
        
    # Polling loop
    timeout_seconds = 60
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        ledger = read_ledger()
        if ledger and ledger.get("status") == "UNLOCKED":
            print("\033[92m[AUTHORIZED] Manager approved. Elevating privileges via JIT...\033[0m")
            subprocess.run(command)
            sys.exit(0)
        elif ledger and ledger.get("status") == "DENIED":
            print("\033[91m[REJECTED] E-4 Manager declined the elevation request.\033[0m")
            ledger["status"] = "LOCKED"
            write_ledger(ledger)
            sys.exit(1)
            
        time.sleep(2)
        
    print("\n\033[93m[TIMEOUT] No response from E-4 Manager within 60 seconds. Cancelling request.\033[0m")
    
    # Clean up timeout state
    ledger = read_ledger()
    if ledger and ledger.get("status") in ["PENDING", "AWAITING_APPROVAL"]:
        ledger["status"] = "LOCKED"
        write_ledger(ledger)
    sys.exit(1)

if __name__ == "__main__":
    main()
