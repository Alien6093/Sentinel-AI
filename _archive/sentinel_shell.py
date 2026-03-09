import os
import json
import time

def load_ledger():
    try:
        with open('access_ledger.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"status": "LOCKED", "current_level": "E-1"}

def run_shell():
    print("--- SENTINEL-AI VIRTUAL TERMINAL (SANDBOX MODE) ---")
    print("Type 'exit' to quit. Use 'sudo' to test Zero Trust.")
    
    while True:
        # This mimics the look of your real terminal
        cmd = input("Aditya@SteelPlant-Sandbox:~$ ").strip()
        
        if cmd == "exit":
            break
        
        if cmd.startswith("sudo"):
            ledger = load_ledger()
            if ledger.get("status") == "LOCKED":
                print("\033[91m[UNAUTHORIZED] E-1 Level detected. Requesting E-4 Manager approval via Discord...\033[0m")
                # Here we simulate waiting for the Discord bot to update the JSON
                print("Waiting for manager response...")
                while True:
                    time.sleep(2)
                    updated_ledger = load_ledger()
                    if updated_ledger.get("status") == "UNLOCKED":
                        print("\033[92m[ACCESS GRANTED] E-4 Elevation Active. Executing command...\033[0m")
                        os.system(cmd.replace("sudo ", ""))
                        break
            else:
                print("\033[92m[E-4 SESSION ACTIVE] Executing admin command...\033[0m")
                os.system(cmd.replace("sudo ", ""))
        else:
            # Run normal commands like 'ls' or 'pwd'
            os.system(cmd)

if __name__ == "__main__":
    run_shell()