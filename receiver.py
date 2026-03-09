import sys
import json
import os
import argparse
import sqlite3
import uvicorn
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fastapi import FastAPI, Request, HTTPException, status, Depends, Header, Response
from pydantic import BaseModel
from contextlib import asynccontextmanager
import jwt
from cryptography.fernet import Fernet

SHARED_AES_KEY = b'lSpNYNK8YNQDKoS3tk64JLkHM7iDsHb1b8HAMtAq2b0='
JWT_SECRET = "12a0e2bae012d54f190854db509d6c3b1ae3d0c1aef39bf3a047a8ea413bf733"

SOC_DB_FILE = "data/soc_fleet.db"
EVENT_QUEUE_FILE = "data/event_queue.jsonl"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE"  # Add your discord webhook

pending_actions: dict[str, dict] = {}
critical_cooldowns: dict[str, float] = {}
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

# FastAPI Integration Setup

def sweep_dead_sensors():
    while True:
        time.sleep(10)
        now = time.time()
        for ip, last_seen in list(endpoint_heartbeats.items()):
            if (now - last_seen) > 15 and ip not in BLACKHOLED_IPS:
                BLACKHOLED_IPS.add(ip)
                print(f"\033[91m[SENSOR DEAD] IP {ip} missed heartbeat. Assuming compromised. Blackholed.\033[0m")

@asynccontextmanager
async def lifespan(app: FastAPI):
    threading.Thread(target=sweep_dead_sensors, daemon=True).start()
    print("SOC Front Desk Receiver Online and Listening...", file=sys.stderr)
    yield
    print("SOC Receiver shutting down...", file=sys.stderr)


app = FastAPI(lifespan=lifespan)

BLACKHOLED_IPS: set[str] = set()
request_timestamps: dict[str, deque] = {}
endpoint_heartbeats: dict[str, float] = {}

@app.middleware("http")
async def blackhole_bouncer(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    
    if client_ip in BLACKHOLED_IPS:
        return Response(status_code=403)
        
    if client_ip != "unknown":
        now = time.time()
        if client_ip not in request_timestamps:
            request_timestamps[client_ip] = deque(maxlen=10)
            
        timestamps = request_timestamps[client_ip]
        timestamps.append(now)
        
        if len(timestamps) == 10 and (timestamps[-1] - timestamps[0]) < 1.0:
            BLACKHOLED_IPS.add(client_ip)
            print(f"\033[91m[BLACKHOLE] IP {client_ip} blacklisted for Log Flooding (Rate Limit Exceeded).\033[0m")
            return Response(status_code=403)
            
    return await call_next(request)

class RegistrationData(BaseModel):
    mac_address: str
    ip_address: str

@app.post("/register")
async def register_node(data: RegistrationData):
    conn = sqlite3.connect(SOC_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT role, status FROM fleet_registry WHERE mac_address = ?', (data.mac_address,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or row[1] != 'Approved':
        if row and row[1] == 'BURNED':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="DEVICE BURNED. Cryptographic trust revoked. Contact SOC Admin."
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Node not authorized in fleet registry"
        )
        
    encoded_jwt = jwt.encode(
        {"mac_address": data.mac_address, "role": row[0], "exp": datetime.utcnow() + timedelta(hours=12)},
        JWT_SECRET,
        algorithm="HS256"
    )
        
    return {"status": "success", "role": row[0], "token": encoded_jwt, "message": "Welcome to Sentinel-AI SOC"}

def verify_jwt(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

class EncryptedPayload(BaseModel):
    encrypted_data: str

def decrypt_payload(data: EncryptedPayload):
    try:
        f = Fernet(SHARED_AES_KEY)
        decrypted_bytes = f.decrypt(data.encrypted_data.encode('utf-8'))
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception:
        print("\033[91m[CRYPTO ALERT] Invalid Decryption Attempt\033[0m")
        raise HTTPException(status_code=400, detail="Invalid Decryption")

import uuid
import requests

def send_discord_alert(task_id, ip, command):
    if not DISCORD_WEBHOOK_URL or "YOUR_WEBHOOK" in DISCORD_WEBHOOK_URL:
        print(f"[Warning] Discord Webhook not configured. Skipping alert for Task: {task_id}")
        return
        
    payload = {
        "content": "@everyone 🚨 **CRITICAL INFRASTRUCTURE ACTION REQUESTED** 🚨",
        "embeds": [{
            "title": "Action Authorization Required",
            "description": f"**User IP:** {ip} | **Command:** `{command}`\n\n⏳ **TIME SENSITIVE:** 2 distinct Admin approvals required within exactly 30 seconds.",
            "color": 16711680, # Red
            "fields": [
                {"name": "Task ID", "value": f"`{task_id}`"},
                {"name": "How to Approve", "value": f"```bash\ncurl -X POST http://YOUR_SERVER_IP:5000/approve_action/{task_id} -H 'Authorization: Bearer YOUR_ADMIN_TOKEN' -H 'Content-Type: application/json' -d '{{\"mac_address\": \"YOUR_ADMIN_MAC\"}}'\n```"}
            ]
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3.0)
    except requests.exceptions.RequestException as e:
        print(f"[Discord Error] Failed to send webhook: {e}")

class ActionRequest(BaseModel):
    mac_address: str
    ip_address: str
    command: str

@app.post("/request_action")
async def request_action(data: EncryptedPayload, token_payload: dict = Depends(verify_jwt)):
    raw_data = decrypt_payload(data)
    req_mac = raw_data.get("mac_address", "")
    req_ip = raw_data.get("ip_address", "")
    req_cmd = raw_data.get("command", "")
    
    # Cooldown check
    last_req_time = critical_cooldowns.get(data.mac_address, 0)
    last_req_time = critical_cooldowns.get(req_mac, 0)
    if time.time() - last_req_time < 600:
        raise HTTPException(status_code=429, detail="Cooldown Active. You must wait 10 minutes between critical requests.")
        
    # Enforce basic Zero Trust on the requester
    conn = sqlite3.connect(SOC_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM fleet_registry WHERE mac_address = ?', (req_mac,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or row[0] != 'Approved':
        raise HTTPException(status_code=403, detail="UNAUTHORIZED DEVICE")

    task_id = str(uuid.uuid4())[:8]
    critical_cooldowns[req_mac] = time.time()
    
    pending_actions[task_id] = {
        "command": req_cmd,
        "ip": req_ip,
        "requester_mac": req_mac,
        "timestamp": time.time(),
        "approvals": 0,
        "approved_by": [],
        "status": "PENDING"
    }
    
    print(f"\033[93m[Action Requested] Task {task_id}: {req_ip} wants to run '{req_cmd}'. Pending Dual-Admin Approval.\033[0m")
    
    # Fire the webhook asynchronously or in background realistically, doing synchronously for now
    send_discord_alert(task_id, req_ip, req_cmd)
    
    return {"status": "pending", "task_id": task_id}

class ApprovalBlock(BaseModel):
    mac_address: str

@app.post("/approve_action/{task_id}")
async def approve_action(task_id: str, data: ApprovalBlock, token_payload: dict = Depends(verify_jwt)):
    if task_id not in pending_actions:
        raise HTTPException(status_code=404, detail="Task ID not found")
        
    action = pending_actions[task_id]
    
    if time.time() - float(action.get("timestamp", 0)) > 30:
        pending_actions.pop(task_id, None)
        raise HTTPException(status_code=408, detail="Approval Window Expired.")
    
    if action["status"] != "PENDING":
        return {"status": str(action.get("status", "UNKNOWN")), "message": f"Task is already {action.get('status', 'UNKNOWN')}"}
        
    conn = sqlite3.connect(SOC_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT role, status FROM fleet_registry WHERE mac_address = ?', (data.mac_address,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or row[1] != 'Approved' or row[0] != 'Admin':
        raise HTTPException(status_code=403, detail="Only Approved Admins can authorize critical actions.")
        
    if data.mac_address == action["requester_mac"]:
        raise HTTPException(status_code=403, detail="You cannot approve your own request.")
        
    if data.mac_address in action["approved_by"]:
        return {"status": "pending", "message": "You have already approved this action."}
        
    action["approvals"] = int(action.get("approvals", 0)) + 1
    
    app_list = action.get("approved_by", [])
    if isinstance(app_list, list):
        app_list.append(data.mac_address)
    action["approved_by"] = app_list
    
    print(f"\033[92m[Admin Approval] MAC {data.mac_address} approved Task {task_id}. ({action.get('approvals')}/2)\033[0m")
    
    if int(action.get("approvals", 0)) >= 2:
        action["status"] = "APPROVED"
        cmd = str(action.get('command', ''))
        print(f"\033[91m[CRITICAL OVERRIDE] Task {task_id} fully approved. Executing command: {cmd}\033[0m")
        return {"status": "APPROVED", "message": "Dual-Admin quorum reached. Action Executing."}
        
    rem_approvals = 2 - int(action.get('approvals', 0))
    return {"status": "PENDING", "message": f"Approval logged. {rem_approvals} more required."}

@app.get("/action_status/{task_id}")
async def get_action_status(task_id: str):
    action = pending_actions[task_id]
    return {"status": str(action.get("status", "UNKNOWN"))}

@app.post("/telemetry")
async def receive_telemetry(request: Request, data: EncryptedPayload, token_payload: dict = Depends(verify_jwt)):
    client_ip = request.client.host if request.client else "unknown"
    
    try:
        log_entry = decrypt_payload(data)
        incoming_mac = log_entry.get('mac_address')
        
        conn = sqlite3.connect(SOC_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT status FROM fleet_registry WHERE mac_address = ?', (incoming_mac,))
        row = cursor.fetchone()
        conn.close()
        
        if not row or row[0] != 'Approved':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="UNAUTHORIZED DEVICE"
            )
            
        # Diode Logic: Append the JSON to event_queue.jsonl async
        # We inject the client IP directly into the event object for the offline brain
        log_entry['diode_source_ip'] = client_ip 
        
        with open(EVENT_QUEUE_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
        return {"status": "received"}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

@app.post("/heartbeat")
async def receive_heartbeat(request: Request, data: EncryptedPayload, token_payload: dict = Depends(verify_jwt)):
    _ = decrypt_payload(data)  # Validate encryption
    client_ip = request.client.host if request.client else "unknown"
    if client_ip != "unknown":
        endpoint_heartbeats[client_ip] = time.time()
    return {"status": "alive"}


class ReceiverIronDome(FileSystemEventHandler):
    def check_tamper(self, event):
        if event.is_directory:
            return
            
        filename = os.path.basename(event.src_path)
        
        if filename == "receiver.py" or filename.endswith(".env"):
            print(f"\n\033[91m[IRON DOME TRIGGERED] Unauthorized modification to Receiver files detected!\033[0m")
            print(f"\033[91mExecuting Fail-Secure Shutdown.\033[0m\n")
            os._exit(1)
            
    def on_modified(self, event):
        self.check_tamper(event)
        
    def on_deleted(self, event):
        self.check_tamper(event)

if __name__ == "__main__":
    print("\033[94m[Iron Dome] Active. Shielding Front Desk receiver.py.\033[0m")
    
    observer = Observer()
    observer.schedule(ReceiverIronDome(), path='.', recursive=False)
    observer.start()
    
    print("Starting FastAPI SOC Receiver Diode...")
    uvicorn.run(app, host="0.0.0.0", port=5000)
