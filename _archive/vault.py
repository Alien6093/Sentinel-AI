import sys
import json
import hashlib
import time
import os
import argparse

VAULT_FILE = "sentinel_vault.json"
DIFFICULTY = 3

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA-256 hash of the block's contents including the nonce."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        """Implements Proof of Work by finding a hash with a specific number of leading zeros."""
        start_time = time.time()
        target = "0" * difficulty
        
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
            
        elapsed = time.time() - start_time
        print(f"⛏️  [PoW Mined] Block {self.index} in {elapsed:.2f}s (Nonce: {self.nonce}) -> Hash: {self.hash[:8]}...", file=sys.stderr)

    def to_dict(self):
        """Helper to serialize block for saving."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }


class VaultChain:
    def __init__(self, vault_path=VAULT_FILE):
        self.vault_path = vault_path
        self.chain = []
        self.load_chain()

    def load_chain(self):
        """Loads the blockchain from disk or creates the Genesis block if missing."""
        if os.path.exists(self.vault_path):
            try:
                with open(self.vault_path, 'r') as f:
                    chain_data = json.load(f)
                    for b_data in chain_data:
                        block = Block(
                            b_data['index'],
                            b_data['timestamp'],
                            b_data['data'],
                            b_data['previous_hash'],
                            b_data.get('nonce', 0)
                        )
                        # We overwrite the recalculation with the stored hash to preserve chain state
                        block.hash = b_data['hash']
                        self.chain.append(block)
                print(f"[Vault] Loaded {len(self.chain)} blocks from {self.vault_path}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"[Vault Error] {self.vault_path} is corrupted. Starting fresh.", file=sys.stderr)
                self.create_genesis_block()
        else:
            self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the very first block in the chain."""
        print("[Vault] Initializing new Sentinel-AI Vault with Genesis Block...", file=sys.stderr)
        genesis_block = Block(0, time.time(), "Genesis Block - Sentinel AI Initialized", "0")
        self.chain.append(genesis_block)
        self.save_chain()

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        """Appends a new anomaly block securely to the chain using Proof of Work."""
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            data=data,
            previous_hash=latest_block.hash
        )
        new_block.mine_block(DIFFICULTY)
        self.chain.append(new_block)
        self.save_chain()
        print(f"[Vault] Securely logged Anomaly Block #{new_block.index}", file=sys.stderr)

    def save_chain(self):
        """Writes the entire chain to the local JSON file."""
        with open(self.vault_path, 'w') as f:
            chain_dict = [block.to_dict() for block in self.chain]
            json.dump(chain_dict, f, indent=4)

    def verify_chain(self):
        """Recalculates every hash to check for tampering."""
        print(f"--- Sentinel Vault Integrity Check ---", file=sys.stderr)
        print(f"Checking {len(self.chain)} blocks for tampering...", file=sys.stderr)
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # 1. Check if the hash matches the data (which implicitly validates the nonce)
            recalculated_hash = current_block.calculate_hash()
            if current_block.hash != recalculated_hash:
                print(f"❌ [TAMPER ALERT] Block {current_block.index} data has been altered!", file=sys.stderr)
                print(f"   Stored Hash  : {current_block.hash}", file=sys.stderr)
                print(f"   Actual Hash  : {recalculated_hash}", file=sys.stderr)
                return False

            # 2. Check if the block actually points to the previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"❌ [TAMPER ALERT] Block {current_block.index} disconnected from chain! It doesn't match Block {previous_block.index}'s hash.", file=sys.stderr)
                return False

            # 3. Check Proof of Work
            target = "0" * DIFFICULTY
            if not current_block.hash.startswith(target) and current_block.index != 0:
                print(f"❌ [TAMPER ALERT] Block {current_block.index} fails Proof of Work! It does not have {DIFFICULTY} leading zeros.", file=sys.stderr)
                return False

        print("✅ [SECURE] The Sentinel Ledger is fully intact. No tampering detected. Proof of Work validated.", file=sys.stderr)
        return True

def run_vault_listener():
    """Reads stdin passively from muscle.py and adds anomalies to the Vault."""
    print("Starting Sentinel-AI Vault (Cryptographic Ledger)...", file=sys.stderr)
    print("Listening to Muscle (stdin) for finalized alerts to secure...", file=sys.stderr)
    
    vault = VaultChain()
    
    # We buffer lines just like muscle.py did, but here we expect muscle's raw output 
    # OR we just listen for the brain alerts passing through.
    # Since muscle.py prints its macOS notifications and Discord alerts to stderr, 
    # it can pipe stdout exactly as it received it!
    # Wait, muscle.py in phase 3 didn't print the anomaly lines back to stdout. it swallowed them.
    # Let's adjust vault.py to listen for the specific strings Brain sent to Muscle, IF muscle passes them via tee OR we modify muscle.py later.
    # For now, let's assume muscle.py pipes the same lines out, or Vault is placed after Brain.
    
    capturing = False
    anomaly_buffer = []

    try:
        for line in sys.stdin:
            line = line.strip()
            
            # Print the line back to stdout so it functions as a transparent pipe layer if chained further
            print(line, flush=True)

            if not line:
                continue

            if "[!!! ANOMALY DETECTED !!!]" in line:
                capturing = True
                anomaly_buffer = []
                continue

            if capturing:
                anomaly_buffer.append(line)
                if len(anomaly_buffer) == 3:
                    capturing = False
                    
                    data_payload = {
                        "context": anomaly_buffer[0],
                        "message": anomaly_buffer[1],
                        "telemetry": anomaly_buffer[2]
                    }
                    vault.add_block(data_payload)
                    
    except KeyboardInterrupt:
        print("\nVault execution stopped.", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel-AI Vault: Cryptographic Log Ledger")
    parser.add_argument("--verify", action="store_true", help="Verify the integrity of the saved blockchain")
    args = parser.parse_args()

    if args.verify:
        vault = VaultChain()
        vault.verify_chain()
    else:
        run_vault_listener()
