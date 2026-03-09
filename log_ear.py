import os
import sys
import time
import socket
import uuid
import psutil
import requests
import subprocess
import threading
import math
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
import json

SHARED_AES_KEY = b'lSpNYNK8YNQDKoS3tk64JLkHM7iDsHb1b8HAMtAq2b0='
AUTH_TOKEN = None

# Central SOC Receiver URL. 
# REPLACE THIS WITH YOUR ACTUAL HOST HOTSPOT IP IF TESTING ACROSS DEVICES
SERVER_URL = "http://127.0.0.1:5000/telemetry"

CRITICAL_COMMANDS = ['nc', 'ncat', 'netcat', 'socat']
SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.bat', '.ps1', '.sh', '.py', '.bin']
ENTROPY_THRESHOLD = 7.2

CANARY_PATHS = set()

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            byte_counts = [0] * 256
            total_bytes = 0
            
            # Read in 64KB chunks to prevent memory overload
            while chunk := f.read(65536):
                total_bytes += len(chunk)
                for byte in chunk:
                    byte_counts[byte] += 1
                    
            if total_bytes == 0:
                return 0.0
                
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / total_bytes
                    entropy -= p * math.log2(p)
                    
            return entropy
            
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0


def get_device_identity():
    """Generates a hardware-locked identity payload."""
    try:
        # Connect to an external host to force resolution of the local network IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # Fetch physical MAC
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                    for ele in range(0, 8 * 6, 8)][::-1]).upper()
                    
    return mac, local_ip

def encrypt_payload(json_dict):
    json_str = json.dumps(json_dict)
    f = Fernet(SHARED_AES_KEY)
    encrypted_data = f.encrypt(json_str.encode('utf-8'))
    return {"encrypted_data": encrypted_data.decode('utf-8')}

def authenticate_to_server(mac_address, ip_address):
    global AUTH_TOKEN
    register_url = SERVER_URL.replace("/telemetry", "/register")
    print(f"Authenticating with SOC Command at {register_url} ...", flush=True)
    try:
        payload = {"mac_address": mac_address, "ip_address": ip_address}
        response = requests.post(register_url, json=payload, timeout=3.0)
        
        if response.status_code == 200:
            resp_data = response.json()
            role = resp_data.get("role", "Endpoint")
            AUTH_TOKEN = resp_data.get("token")
            print(f"\033[92m[Zero Trust] Handshake Successful. Role: {role}. Commencing telemetry stream.\033[0m")
        elif response.status_code == 403 and "BURNED" in response.text:
            print("\033[91m[FATAL] Device has been BURNED by the server. Cannot connect.\033[0m")
            sys.exit(1)
        else:
            print("\033[91m[Zero Trust] ACCESS DENIED. Device MAC not whitelisted by Admin.\033[0m")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print("\033[91m[Zero Trust] Network Error: Cannot reach Central Command for authentication. Exiting.\033[0m")
        sys.exit(1)

def _safe_post(url, payload, timeout=2.0):
    try:
        headers = {}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        resp = requests.post(url, json=encrypt_payload(payload), headers=headers, timeout=timeout)
        if resp.status_code == 401:
            print("\033[91m[AUTH REVOKED] Token invalid or expired. Shutting down.\033[0m")
            os._exit(1)
        if resp.status_code == 403:
            print("\033[91m[FATAL] Blackholed by Central Command.\033[0m")
            os._exit(1)
        return resp
    except requests.exceptions.RequestException:
        return None

def transmit_heartbeat():
    while True:
        time.sleep(5)
        try:
            url = SERVER_URL.replace("/telemetry", "/heartbeat")
            _safe_post(url, {}, timeout=2.0)
        except Exception:
            pass

# --- PHASE 12 TRIPWIRES ---

class TripwireHandler(FileSystemEventHandler):
    def __init__(self, mac_address, ip_address):
        self.mac_address = mac_address
        self.ip_address = ip_address
        super().__init__()

    def check_canary(self, event):
        path = getattr(event, 'src_path', '')
        dest = getattr(event, 'dest_path', '')
        
        if path in CANARY_PATHS or dest in CANARY_PATHS:
            print(f"\033[91m[CRITICAL] RANSOMWARE TRAP SPRUNG! Canary file modified: {path}\033[0m")
            payload = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "type": "ransomware_canary_tripped",
                "proc": "deception_engine",
                "target": path,
                "uid": "unknown",
                "sensitive": True,
                "mac_address": self.mac_address,
                "ip_address": self.ip_address
            }
            try:
                _safe_post(SERVER_URL, payload, timeout=2.0)
            except Exception:
                pass
            return True
        return False

    def process_event(self, event):
        if event.is_directory:
            return
            
        if self.check_canary(event):
            return
            
        try:
            uid = os.getlogin()
        except Exception:
            try:
                import getpass
                uid = getpass.getuser()
            except Exception:
                uid = "unknown"

        payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "type": "persistence_creation",
            "proc": "file_system",
            "pname": "watchdog",
            "target": event.src_path,
            "uid": uid,
            "sensitive": True,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address
        }
        
        print(f"\033[91m[TRIPWIRE] Persistence Detected: {event.src_path}\033[0m")
        try:
            _safe_post(SERVER_URL, payload, timeout=2.0)
        except Exception:
            pass

        # Phase 13: Shannon Entropy Analysis
        _, ext = os.path.splitext(event.src_path.lower())
        if ext in SUSPICIOUS_EXTENSIONS:
            score = calculate_entropy(event.src_path)
            print(f"[Entropy Engine] Scanned {os.path.basename(event.src_path)} | Score: {score:.2f}")
            
            if score >= ENTROPY_THRESHOLD:
                print(f"\033[91m[!!!] HIGH ENTROPY DETECTED: Packed Malware Suspected!\033[0m")
                entropy_payload = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "high_entropy_anomaly",
                    "proc": "entropy_engine",
                    "pname": "watchdog",
                    "target": event.src_path,
                    "uid": uid,
                    "entropy_score": score,
                    "sensitive": True,
                    "mac_address": self.mac_address,
                    "ip_address": self.ip_address
                }
                try:
                    _safe_post(SERVER_URL, entropy_payload, timeout=2.0)
                except Exception:
                    pass

    def on_created(self, event):
        self.process_event(event)

    def on_modified(self, event):
        self.process_event(event)
        
    def on_deleted(self, event):
        self.check_canary(event)

    def on_moved(self, event):
        self.check_canary(event)

def start_tripwires(mac_address, ip_address):
    paths_to_watch = []
    if os.name == 'nt':
        appdata = os.getenv('APPDATA', '')
        if appdata:
            paths_to_watch.append(os.path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
        programdata = os.getenv('PROGRAMDATA', 'C:\\ProgramData')
        paths_to_watch.append(os.path.join(programdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
    elif os.name == 'posix':
        paths_to_watch.append(os.path.expanduser('~/Library/LaunchAgents'))
        paths_to_watch.append('/Library/LaunchAgents')

    observer = Observer()
    handler = TripwireHandler(mac_address, ip_address)
    active = 0
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=False)
            active += 1
            
    if active > 0:
        observer.start()
    return observer

def monitor_registry(mac_address, ip_address):
    if os.name != 'nt':
        return
        
    try:
        import winreg
    except ImportError:
        return

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    known_keys = set()
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            for i in range(1024):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    known_keys.add(f"{name}={value}")
                except OSError:
                    break
    except Exception:
        pass

    while True:
        try:
            time.sleep(10)
            current_keys = set()
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                for i in range(1024):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        current_keys.add(f"{name}={value}")
                    except OSError:
                        break
                        
            new_keys = current_keys - known_keys
            for new_key in new_keys:
                try:
                    uid = os.getlogin()
                except Exception:
                    uid = "unknown"
                    
                payload = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "registry_persistence",
                    "proc": "winreg",
                    "pname": "unknown",
                    "target": new_key,
                    "uid": uid,
                    "sensitive": True,
                    "mac_address": mac_address,
                    "ip_address": ip_address
                }
                print(f"\033[91m[TRIPWIRE] Registry Persistence Detected: {new_key}\033[0m")
                try:
                    _safe_post(SERVER_URL, payload, timeout=2.0)
                except Exception:
                    pass
                
            known_keys = current_keys
        except Exception:
            time.sleep(10)

def monitor_hardware(mac_address, ip_address):
    try:
        known_drives = set(p.mountpoint for p in psutil.disk_partitions(all=False))
    except Exception:
        known_drives = set()
        
    while True:
        try:
            time.sleep(3)
            current_drives = set(p.mountpoint for p in psutil.disk_partitions(all=False))
            new_drives = current_drives - known_drives
            for drive in new_drives:
                try:
                    uid = os.getlogin()
                except Exception:
                    try:
                        import getpass
                        uid = getpass.getuser()
                    except Exception:
                        uid = "unknown"
                        
                payload = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "usb_insertion",
                    "proc": "hardware_bus",
                    "pname": "watchdog",
                    "target": drive,
                    "uid": uid,
                    "sensitive": True,
                    "mac_address": mac_address,
                    "ip_address": ip_address
                }
                print(f"\033[91m[TRIPWIRE] New Hardware Mount Detected: {drive}\033[0m")
                try:
                    _safe_post(SERVER_URL, payload, timeout=2.0)
                except Exception:
                    pass
            known_drives = current_drives
        except Exception:
            time.sleep(3)

def deploy_canaries():
    """Phase 22: Deception Engine Canary Deployment"""
    filename = "._!passwords_vault.docx" if os.name == 'posix' else "!_passwords_vault.docx"
    
    try:
        if os.name == 'posix':
            target_dir = os.path.expanduser('~/Documents')
            if not os.path.exists(target_dir):
                target_dir = os.path.expanduser('~')
        else:
            target_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\'), 'Documents')
            if not os.path.exists(target_dir):
                target_dir = os.environ.get('USERPROFILE', 'C:\\')
                
        canary_path = os.path.join(target_dir, filename)
        
        # Write randomized harmless string
        random_bytes = os.urandom(1024)
        with open(canary_path, "wb") as f:
            f.write(random_bytes)
            
        # Hide it on Windows
        if os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(canary_path, 0x02)
            except Exception:
                pass
                
        CANARY_PATHS.add(canary_path)
        print(f"\033[94m[Deception Engine] Canary deployed securely: {canary_path}\033[0m")
    except Exception as e:
        print(f"[Deception Error] Could not deploy canary: {e}")

def main():
    print("Initializing Sentinel-AI Endpoint Sensor (Phase 10)...")
    mac_address, ip_address = get_device_identity()
    print(f"[{mac_address}] Endpoint IP: {ip_address}")
    
    # Strict Startup Authentication Handshake
    authenticate_to_server(mac_address, ip_address)
    
    # Phase 22: Deploy Canaries after successful handshake
    deploy_canaries()

    known_pids = set(psutil.pids())
    print("Baseline PIDs Established. Waiting for new executions...")
    
    print("\033[94m[Tripwire] Active. Guarding Startup Folders and Registry.\033[0m")
    observer = start_tripwires(mac_address, ip_address)
    reg_thread = threading.Thread(target=monitor_registry, args=(mac_address, ip_address), daemon=True)
    reg_thread.start()
    hw_thread = threading.Thread(target=monitor_hardware, args=(mac_address, ip_address), daemon=True)
    hw_thread.start()
    pulse_thread = threading.Thread(target=transmit_heartbeat, daemon=True)
    pulse_thread.start()

    # Main Polling Loop
    while True:
        try:
            time.sleep(0.5)
            current_pids = set(psutil.pids())
            
            # Find new PIDs that spawned in the last 0.5s
            new_pids = current_pids - known_pids
            
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    # Fetch Process specific data safely
                    try:
                        cmdline = proc.cmdline()
                        full_cmd = " ".join(cmdline) if cmdline else ""
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        full_cmd = ""
                        
                    proc_name = proc.name()
                    proc_exe = proc.exe() or proc_name # Fallback to name if path is denied
                    
                    # Interceptor Check
                    is_critical = any(cmd in full_cmd for cmd in CRITICAL_COMMANDS)
                    if is_critical:
                        print(f"\033[91m[INTERCEPT] Blocked '{full_cmd}'. Requesting SOC Authorization...\033[0m")
                        request_url = SERVER_URL.replace("/telemetry", "/request_action")
                        try:
                            req_payload = {"mac_address": mac_address, "ip_address": ip_address, "command": full_cmd}
                            resp = _safe_post(request_url, req_payload, timeout=3.0)
                            if resp and resp.status_code == 200:
                                task_id = resp.json().get("task_id")
                                status_url = SERVER_URL.replace("/telemetry", f"/action_status/{task_id}")
                                
                                # Enter Polling Loop with 30s Timeout
                                approved = False
                                for _ in range(10): # 10 * 3s = 30s TTL
                                    time.sleep(3)
                                    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}
                                    status_resp = requests.get(status_url, headers=headers, timeout=3.0)
                                    if status_resp.status_code == 200:
                                        curr_status = status_resp.json().get("status")
                                        if curr_status == "APPROVED":
                                            print(f"\033[92m[OVERRIDE] Task {task_id} Approved. Executing natively.\033[0m")
                                            subprocess.Popen(cmdline) # Release the lock essentially
                                            approved = True
                                            break
                                        elif curr_status == "DENIED":
                                            print(f"\033[91m[DENIED] Task {task_id} Rejected by SOC.\033[0m")
                                            approved = True # Exit loop, handled
                                            break
                                        else:
                                            print(f"[Pending] Task {task_id} awaiting Dual-Admin override...", flush=True)
                                
                                if not approved:
                                    print(f"\033[91m[TIME EXPIRED] Action Aborted. Did not receive 2 Admin approvals for Task {task_id}.\033[0m")
                                    
                            else:
                                print(f"[Intercept Error] SOC rejected request: {resp.text}")
                        except Exception as e:
                            print(f"[Intercept Error] Could not reach SOC for authorization: {e}")
                        
                        # Stop normal event processing for this PID
                        continue
                    
                    try:
                        uid = proc.uids().real # Get real user ID
                    except AttributeError:
                        uid = proc.username() # Fallback for Windows
                        
                    ppid = proc.ppid()
                    try:
                        pname = psutil.Process(ppid).name() if ppid else "unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pname = "unknown"
                        
                    # Calculate ML Risk Feature: Was it a sensitive path?
                    is_sensitive = any(sensitive in proc_exe.lower() for sensitive in ['/etc/', '/var/root', 'system32'])

                    payload = {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "type": "exec",
                        "proc": proc_exe,
                        "pname": pname,
                        "uid": uid,
                        "sensitive": is_sensitive,
                        "mac_address": mac_address,
                        "ip_address": ip_address
                    }
                    
                    # Output to console
                    print(f"[Captured] Exec: {pname} -> {proc_name} (PID: {pid})")
                    
                    # Transmit to SOC
                    try:
                        _safe_post(SERVER_URL, payload, timeout=2.0)
                    except Exception:
                        print(f"\033[93m[Network Error] Cannot reach Central Command at {SERVER_URL}\033[0m")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass # Short lived process died before we could inspect it, or we lacked Admin rights

            # Update our tracker State
            known_pids = current_pids
            
        except KeyboardInterrupt:
            print("\nShutting down Sentinel-AI Endpoint Sensor.")
            break
        except Exception as e:
            print(f"Unexpected Loop Error: {e}")
            time.sleep(1) # Prevent CPU spin out

if __name__ == "__main__":
    main()
