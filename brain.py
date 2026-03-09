import sys
import json
import csv
import os
import glob
import argparse
import sqlite3
import threading
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta
from collections import deque
import pandas as pd
import time
import base64
import re
import jwt
from cryptography.fernet import Fernet

SHARED_AES_KEY = b'lSpNYNK8YNQDKoS3tk64JLkHM7iDsHb1b8HAMtAq2b0='
JWT_SECRET = "12a0e2bae012d54f190854db509d6c3b1ae3d0c1aef39bf3a047a8ea413bf733"

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import LabelEncoder
    import joblib
    import numpy as np
except ImportError:
    print("Missing ML dependencies. Please run:", file=sys.stderr)
    print("pip install scikit-learn joblib numpy pandas", file=sys.stderr)
LEDGER_FILE = "access_ledger.json"
SOC_DB_FILE = "data/soc_fleet.db"
MODEL_DIR = "data/sentinel_models"
EVENT_QUEUE_FILE = "data/event_queue.jsonl"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE"  # Add your discord webhook

# Globals for ML
BLACKHOLED_IPS = set()
ml_model = None
ml_encoders = None

user_risk_scores: dict[str, int] = {}
user_event_history: dict[str, deque] = {}
CRITICAL_THRESHOLD = 100

def init_db():
    conn = sqlite3.connect(SOC_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fleet_registry (
            mac_address TEXT PRIMARY KEY,
            ip_address TEXT,
            role TEXT,
            status TEXT
        )
    ''')
    
    # Insert Dummy Admin for testing
    cursor.execute('''
        INSERT OR IGNORE INTO fleet_registry (mac_address, ip_address, role, status)
        VALUES ('00:1A:2B:3C:4D:5E', '127.0.0.1', 'Admin', 'Approved')
    ''')
    conn.commit()
    conn.close()

init_db()

def get_user_risk(ip_address):
    if ip_address not in user_risk_scores:
        user_risk_scores[ip_address] = 0
    return user_risk_scores[ip_address]

def decay_risk(ip_address, amount=2):
    if ip_address in user_risk_scores:
        user_risk_scores[ip_address] -= amount
        if user_risk_scores[ip_address] < 0:
            user_risk_scores[ip_address] = 0

def check_lineage_risk(event_dict):
    pname = str(event_dict.get('pname', '')).lower()
    proc = str(event_dict.get('proc', '')).lower()
    
    suspect_parents = ['curl', 'wget', 'python', 'python3', 'bash', 'sh', 'ruby', 'perl', 'php', 'osascript', 'node']
    
    is_suspect_parent = any(sp in pname for sp in suspect_parents)
    child_base = os.path.basename(proc)
    
    # +80 points if a suspect parent spawns a critical child
    is_risky_child = child_base in ['sudo', 'su', 'chmod']
    
    if is_suspect_parent and is_risky_child:
        return 80
    return 0

def calculate_risk_increment(event_dict, ml_score, heuristics_broken):
    increment = 0
    proc = str(event_dict.get('proc', ''))
    sensitive = event_dict.get('sensitive', False)
    
    is_sudo_related = 'sudo' in proc or 'su' in proc
    
    # High Risk (+70): Critical heuristic violations paired with AI anomaly Below -0.1
    if heuristics_broken and ml_score < -0.1:
        increment = 70
    # Medium Risk (+40): Sudo combined with negative AI anomaly score
    elif is_sudo_related and ml_score < 0:
        increment = 40
    # Low Risk (+10): Standard sudo commands or accessing sensitive files natively
    elif is_sudo_related or sensitive:
        increment = 10
        
    lineage_risk = check_lineage_risk(event_dict)
    increment += lineage_risk
        
    return increment

def evaluate_behavioral_sequence(ip_address):
    history = user_event_history.get(ip_address, [])
    if len(history) < 2:
        return False
        
    # Rule 1: The USB Execution Trap
    # usb_insertion -> exec (script) within 60s
    for i in range(len(history) - 1):
        evt_i = history[i]
        if evt_i and isinstance(evt_i, dict) and evt_i.get('type') == 'usb_insertion':
            for j in range(i + 1, len(history)):
                evt_j = history[j]
                if evt_j and isinstance(evt_j, dict) and evt_j.get('type') == 'exec':
                    proc = str(evt_j.get('proc', '')).lower()
                    if any(shell in proc for shell in ['python', 'powershell', 'cmd', 'bash', 'sh']):
                        # Check timestamp delta
                        try:
                            t1 = pd.to_datetime(evt_i.get('ts'))
                            t2 = pd.to_datetime(evt_j.get('ts'))
                            delta = t2 - t1
                            if delta.total_seconds() <= 60:  # type: ignore
                                print(f"\033[91m[BEHAVIORAL TRAP TRIGGERED] Sequence: USB Script Execution detected for IP {ip_address}. Executing System Lock.\033[0m")
                                return True
                        except Exception:
                            pass
                            
    # Rule 2: The Recon Trap
    # exec whoami -> ifconfig/ipconfig -> netstat inside 15s
    if len(history) >= 3:
        for i in range(len(history) - 2):
            evt_i = history[i]
            if evt_i and isinstance(evt_i, dict) and evt_i.get('type') == 'exec' and 'whoami' in str(evt_i.get('proc', '')).lower():
                j = i + 1
                evt_j = history[j]
                if evt_j and isinstance(evt_j, dict) and evt_j.get('type') == 'exec' and any(cmd in str(evt_j.get('proc', '')).lower() for cmd in ['ifconfig', 'ipconfig']):
                    k = i + 2
                    evt_k = history[k]
                    if evt_k and isinstance(evt_k, dict) and evt_k.get('type') == 'exec' and 'netstat' in str(evt_k.get('proc', '')).lower():
                        try:
                            t1 = pd.to_datetime(evt_i.get('ts'))
                            t3 = pd.to_datetime(evt_k.get('ts'))
                            delta = t3 - t1
                            if delta.total_seconds() <= 15:  # type: ignore
                                print(f"\033[91m[BEHAVIORAL TRAP TRIGGERED] Sequence: Automated Recon detected for IP {ip_address}. Executing System Lock.\033[0m")
                                return True
                        except Exception:
                            pass
                            
    return False

def analyze_fileless_payload(cmd_string):
    if not isinstance(cmd_string, str) or not cmd_string:
        return False
        
    cmd_lower = cmd_string.lower()
    
    # 1. Check for encoded payload flags
    encoded_flags = ['-enc', '-encodedcommand', '-w hidden', '-ep bypass']
    is_encoded = any(flag in cmd_lower for flag in encoded_flags)
    
    decoded_string = cmd_string
    
    # 2. Extract and Decode Base64 if suspected
    if is_encoded:
        # Very basic regex to grab a large base64 string
        # PowerShell base64 blobs are usually quite long
        match = re.search(r'(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)', cmd_string, re.IGNORECASE)
        if match:
            b64_blob = match.group(1)
            try:
                # PowerShell uses UTF-16LE for its Base64 encoding
                decoded_bytes = base64.b64decode(b64_blob)
                decoded_string = decoded_bytes.decode('utf-16le', errors='ignore')
            except Exception:
                # Fallback to UTF-8 if standard
                try:
                    decoded_string = base64.b64decode(b64_blob).decode('utf-8', errors='ignore')
                except Exception:
                    pass
                    
    # 3. Heuristic Keyword Scanning on the final string
    dec_lower = decoded_string.lower()
    critical_indicators = ['net.webclient', 'downloadstring', 'invoke-expression', 'iex', 'virtualalloc', 'hidden']
    
    for ind in critical_indicators:
        if ind in dec_lower:
            print(f"\033[91m[FILELESS MALWARE DETECTED] Memory Injection Attempt Caught!\033[0m")
            print(f"\033[91mPayload Snippet: {decoded_string[:150]}...\033[0m")
            return True
            
    return False

def load_training_data(log_dir="sentinel_logs"):
    all_files = glob.glob(os.path.join(log_dir, "*.jsonl"))
    data = []
    for file_path in all_files:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    data.append(obj)
                except json.JSONDecodeError:
                    pass
    return pd.DataFrame(data)

def preprocess_features(df):
    df['ts'] = pd.to_datetime(df['ts'])
    df['hour'] = df['ts'].dt.hour
    
    df['sensitive'] = df['sensitive'].astype(int)
    
    df['proc_simplified'] = df['proc'].astype(str).apply(lambda x: os.path.basename(x))
    
    df['pname'] = df.get('pname', 'unknown').fillna('unknown').astype(str)
    
    type_encoder = LabelEncoder()
    df['type_encoded'] = type_encoder.fit_transform(df['type'].astype(str))
    
    proc_encoder = LabelEncoder()
    df['proc_encoded'] = proc_encoder.fit_transform(df['proc_simplified'])
    
    pname_encoder = LabelEncoder()
    df['pname_encoded'] = pname_encoder.fit_transform(df['pname'])
    
    encoders = {'type': type_encoder, 'proc': proc_encoder, 'pname': pname_encoder}
    
    return df[['hour', 'uid', 'sensitive', 'type_encoded', 'proc_encoded', 'pname_encoded']], encoders

def train_and_save_model(df, encoders, model_dir="sentinel_models"):
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
        
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    clf.fit(df)
    
    joblib.dump(clf, os.path.join(model_dir, 'isolation_forest.joblib'))
    joblib.dump(encoders, os.path.join(model_dir, 'encoders.joblib'))

def predict_event(event_dict, model, encoders):
    # Try to parse datetime falling back to now
    try:
        ts = pd.to_datetime(event_dict.get('ts'))
        hour = ts.hour
    except Exception:
        hour = datetime.now().hour
        
    uid = event_dict.get('uid', 0)
    sensitive = int(event_dict.get('sensitive', False))
    
    proc_simplified = os.path.basename(str(event_dict.get('proc', 'unknown')))
    
    try:
        type_encoded = encoders['type'].transform([str(event_dict.get('type', 'unknown'))])[0]
    except ValueError:
        type_encoded = -1
        
    try:
        proc_encoded = encoders['proc'].transform([proc_simplified])[0]
    except ValueError:
        proc_encoded = -1
        
    try:
        pname_encoded = encoders['pname'].transform([str(event_dict.get('pname', 'unknown'))])[0]
    except ValueError:
        pname_encoded = -1
        
    live_df = pd.DataFrame([[hour, uid, sensitive, type_encoded, proc_encoded, pname_encoded]], 
                           columns=['hour', 'uid', 'sensitive', 'type_encoded', 'proc_encoded', 'pname_encoded'])
                           
    return live_df

def lock_system():
    try:
        with open(LEDGER_FILE, "r") as f:
            current_state = json.load(f)
            
        if current_state.get("status") == "UNLOCKED":
            current_state["status"] = "LOCKED"
            current_state["reason"] = "Sentinel-AI Detection"
            current_state["timestamp"] = datetime.now().isoformat()
            current_state["expiry_timestamp"] = 0
            with open(LEDGER_FILE, "w") as f:
                json.dump(current_state, f, indent=4)
            print(f"[Brain Automator] 🛑 Anomaly confirmed! Instantly revoking {current_state.get('level')} JIT Access.", file=sys.stderr)
    except Exception as e:
        print(f"[Brain Error] Failed automated revocation: {e}", file=sys.stderr)

def evaluate_event(event_dict, ip_address, model, encoders):
    # Phase 22: Ransomware Trap Bypass
    if event_dict.get('type') == 'ransomware_canary_tripped':
        print(f"\033[91m[CRITICAL] RANSOMWARE TRAP SPRUNG! Canary file modified. Device MAC isolated and BURNED.\033[0m")
        user_risk_scores[ip_address] = user_risk_scores.get(ip_address, 0) + 1000
        lock_system()
        mac = event_dict.get('mac_address', '')
        if mac:
            conn = sqlite3.connect(SOC_DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE fleet_registry SET status = 'BURNED' WHERE mac_address = ?", (mac,))
            conn.commit()
            conn.close()
            BLACKHOLED_IPS.add(ip_address)
        return

    # Phase 14: Sequence Ledger update
    history = user_event_history.get(ip_address, deque(maxlen=5))
    history.append(event_dict)
    user_event_history[ip_address] = history
    
    # Phase 14: Behavioral State Machine Trap
    if evaluate_behavioral_sequence(ip_address):
        user_risk_scores[ip_address] = user_risk_scores.get(ip_address, 0) + 100
        lock_system()
        mac = event_dict.get('mac_address', '')
        if mac:
            conn = sqlite3.connect(SOC_DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE fleet_registry SET status = 'BURNED' WHERE mac_address = ?", (mac,))
            conn.commit()
            conn.close()
            BLACKHOLED_IPS.add(ip_address)
        return

    # Phase 15: Fileless Malware Detection Trap
    cmdline = str(event_dict.get('cmdline', ''))
    if cmdline and analyze_fileless_payload(cmdline):
        user_risk_scores[ip_address] = user_risk_scores.get(ip_address, 0) + 100
        lock_system()
        mac = event_dict.get('mac_address', '')
        if mac:
            conn = sqlite3.connect(SOC_DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE fleet_registry SET status = 'BURNED' WHERE mac_address = ?", (mac,))
            conn.commit()
            conn.close()
            BLACKHOLED_IPS.add(ip_address)
        return
        
    decay_risk(ip_address, amount=1)
    
    if not model or not encoders:
        return
        
    try:
        live_df = predict_event(event_dict, model, encoders)
        # Predict using IsolationForest -> returns -1 for outliers, 1 for inliers
        prediction = model.predict(live_df)[0]
        # score_samples returns negative score for outliers
        ml_score = model.score_samples(live_df)[0]
        
        heuristics_broken = (prediction == -1)
        
        # Calculate heuristics
        bump = calculate_risk_increment(event_dict, ml_score, heuristics_broken)
        if bump > 0:
            user_risk_scores[ip_address] = user_risk_scores.get(ip_address, 0) + bump
            total_risk = user_risk_scores[ip_address]
            print(f"[Brain Automator] Event Risk Incremented (+{bump}). Total IP {ip_address} Risk: {total_risk}")
            
            if total_risk >= CRITICAL_THRESHOLD:
                print(f"\033[91m[CRITICAL THRESHOLD REACHED] Executing System Lock for IP {ip_address}.\033[0m")
                lock_system()
                mac = event_dict.get('mac_address', '')
                if mac:
                    conn = sqlite3.connect(SOC_DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE fleet_registry SET status = 'BURNED' WHERE mac_address = ?", (mac,))
                    conn.commit()
                    conn.close()
                    BLACKHOLED_IPS.add(ip_address)
    except Exception as e:
        print(f"[Brain Error] ML evaluation failed: {e}", file=sys.stderr)

def tail_event_queue():
    print(f"\033[92m[CQRS Diode Active] Offline Engine tailing {EVENT_QUEUE_FILE}...\033[0m")
    
    # Wait for the file to exist
    while not os.path.exists(EVENT_QUEUE_FILE):
        time.sleep(1)
        
    global ml_model, ml_encoders
    
    with open(EVENT_QUEUE_FILE, "r") as f:
        # Seek to the end to only process new events organically (or process backlog if preferred)
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Sleep briefly and poll again
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                log_entry = json.loads(line)
                client_ip = log_entry.get("diode_source_ip", "unknown")
                evaluate_event(log_entry, client_ip, ml_model, ml_encoders)
            except json.JSONDecodeError:
                print(f"[Brain Error] Malformed JSON in Event Queue: {line[:50]}")
            except Exception as e:
                print(f"[Brain Error] Offline processing error: {e}", file=sys.stderr)

def rolling_db_backup():
    backup_dir = "data/backups"
    os.makedirs(backup_dir, exist_ok=True)
    
    while True:
        time.sleep(60)
        try:
            if not os.path.exists(SOC_DB_FILE):
                continue
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_dir, f"soc_fleet_{timestamp}.db")
            shutil.copy2(SOC_DB_FILE, backup_path)
            
            # Cleanup older backups (keep last 5)
            backups = sorted(glob.glob(os.path.join(backup_dir, "soc_fleet_*.db")))
            if len(backups) > 5:
                for old_backup in backups[:-5]:
                    try:
                        os.remove(old_backup)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Backup Error] Failed to backup DB: {e}", file=sys.stderr)

class ServerIronDome(FileSystemEventHandler):
    def check_tamper(self, event):
        if event.is_directory:
            return
            
        filename = os.path.basename(event.src_path)
        
        # Explicitly protect the core logic and models
        if filename == "brain.py" or filename.endswith(".joblib") or filename.endswith(".env"):
            print(f"\n\033[91m[IRON DOME TRIGGERED] Unauthorized modification to core server files detected!\033[0m")
            print(f"\033[91mTargeted file: {filename} | Action: {event.event_type}\033[0m")
            print(f"\033[91mExecuting Fail-Secure Shutdown.\033[0m\n")
            os._exit(1) # Hard OS kill to drop connections instantly
            
    def on_modified(self, event):
        self.check_tamper(event)
        
    def on_deleted(self, event):
        self.check_tamper(event)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel-AI Brain: Log Anomaly Detector")
    parser.add_argument("--train", action="store_true", help="Run in training mode to build a baseline CSV + train model")
    parser.add_argument("--add-mac", type=str, help="Add or update a device MAC in the fleet whitelist")
    parser.add_argument("--ip", type=str, help="IP address of the device being added", default="0.0.0.0")
    parser.add_argument("--role", type=str, help="Role of the device being added", default="Endpoint")
    parser.add_argument("--pardon-mac", type=str, help="Pardon a BURNED device and restore trust")
    parser.add_argument("--list-fleet", action="store_true", help="List all registered devices in the fleet")
    args = parser.parse_args()

    def pardon_device(mac_address):
        conn = sqlite3.connect(SOC_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, status FROM fleet_registry WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()
        if row and row[1] == 'BURNED':
            ip_addr = row[0]
            cursor.execute("UPDATE fleet_registry SET status = 'Approved' WHERE mac_address = ?", (mac_address,))
            conn.commit()
            if ip_addr in user_risk_scores:
                user_risk_scores[ip_addr] = 0
            if ip_addr in BLACKHOLED_IPS:
                BLACKHOLED_IPS.remove(ip_addr)
            print(f"\033[92m[PARDON ISSUED] MAC {mac_address} trust restored. Risk score reset to 0.\033[0m")
        else:
            print(f"MAC {mac_address} is either not in a BURNED state or does not exist.")
        conn.close()
        sys.exit(0)

    if args.pardon_mac:
        pardon_device(args.pardon_mac)
        
    elif args.add_mac:
        conn = sqlite3.connect(SOC_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO fleet_registry (mac_address, ip_address, role, status)
            VALUES (?, ?, ?, 'Approved')
            ON CONFLICT(mac_address) DO UPDATE SET
            ip_address=excluded.ip_address, role=excluded.role, status='Approved'
        ''', (args.add_mac, args.ip, args.role))
        conn.commit()
        conn.close()
        print(f"[Admin] Successfully whitelisted device: MAC={args.add_mac}, IP={args.ip}, Role={args.role}")
        sys.exit(0)
        
    elif args.list_fleet:
        conn = sqlite3.connect(SOC_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address, role, status FROM fleet_registry')
        rows = cursor.fetchall()
        conn.close()
        print(f"{'MAC ADDRESS':<20} | {'IP ADDRESS':<15} | {'ROLE':<10} | {'STATUS'}")
        print("-" * 65)
        for row in rows:
            print(f"{row[0]:<20} | {row[1]:<15} | {row[2]:<10} | {row[3]}")
        sys.exit(0)

    elif args.train:
        # Load encoders and ML models 
        print(f"Loading Brain and Encoders from {MODEL_DIR}...", file=sys.stderr)
        ml_model = joblib.load(os.path.join(MODEL_DIR, 'isolation_forest.joblib'))
        ml_encoders = joblib.load(os.path.join(MODEL_DIR, 'encoders.joblib'))

        # Phase 18: Server Self-Preservation Initialization
        print("\033[94m[Iron Dome] Active. Shielding core ML files.\033[0m")
        
        # Start DB Backup Thread
        threading.Thread(target=rolling_db_backup, daemon=True).start()
        
        # Start Server Tripwire
        observer = Observer()
        observer.schedule(ServerIronDome(), path='.', recursive=False)
        observer.start()
        
        tail_event_queue()
    else:
        print("\033[94m[Iron Dome] Active. Shielding core files.\033[0m")
        print("\033[94m[Brain] Executive Engine starting offline analysis...\033[0m")
        
        # Start DB Backup Thread
        import threading
        threading.Thread(target=rolling_db_backup, daemon=True).start()
        
        # Start Server Tripwire
        from watchdog.observers import Observer
        observer = Observer()
        observer.schedule(ServerIronDome(), path='.', recursive=False)
        observer.start()
        
        # Start the infinite loop to read the logs
        tail_event_queue()
