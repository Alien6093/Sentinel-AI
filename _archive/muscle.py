import sys
import os
import subprocess
import time
import json
import urllib.request
import urllib.error

# Configuration
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1477954438546194433/iCIrAxFfxlsQytovTTuSvbTJUi4cTSRZJrAgpiAnppZGSri7UxXgYAGGq0I8E5OSA4Zd"  # Placeholder: Replace with your actual Discord Webhook URL
COOLDOWN_SECONDS = 10     # Delay between alerts to prevent storming

class AlertEngine:
    """
    Handles triggering notifications (macOS Desktop & Discord).
    Includes a cooldown mechanism to prevent notification spam.
    """
    def __init__(self, cooldown=10):
        self.cooldown = cooldown
        self.last_alert_time = 0.0

    def can_alert(self):
        """Checks if enough time has passed since the last alert."""
        current_time = time.time()
        if (current_time - self.last_alert_time) >= self.cooldown:
            self.last_alert_time = current_time
            return True
        return False

    def trigger_macos_notification(self, title, message):
        """Triggers a native macOS desktop notification using osascript."""
        # Sanitize message to prevent command injection in AppleScript
        safe_message = message.replace('"', '\\"')
        safe_title = title.replace('"', '\\"')
        osascript_cmd = f'display notification "{safe_message}" with title "{safe_title}"'
        try:
            subprocess.run(["osascript", "-e", osascript_cmd], check=True)
            print(f"[Mac Alert Sent] {title}: {message}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"[Mac Alert Failed] Error: {e}", file=sys.stderr)

    def trigger_discord_webhook(self, embed_data):
        """Sends a formatted JSON payload to a Discord webhook."""
        if not DISCORD_WEBHOOK_URL:
            print("[Discord Alert Skipped] No Webhook URL provided.", file=sys.stderr)
            return

        payload = {
            "username": "Sentinel-AI",
            "avatar_url": "https://i.imgur.com/4M34hi2.png", # Placeholder icon
            "content": "🚨 **High-Risk Activity Detected!** 🚨",
            "embeds": [embed_data]
        }

        try:
            req = urllib.request.Request(
                DISCORD_WEBHOOK_URL,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req) as response:
                if response.status in (200, 204):
                    print(f"[Discord Alert Sent] Status: {response.status}", file=sys.stderr)
                else:
                    print(f"[Discord Alert Error] Status: {response.status}", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"[Discord Alert Failed] Error: {e.reason}", file=sys.stderr)


def main():
    print("Starting Sentinel-AI Muscle (Execution Engine)...", file=sys.stderr)
    print("Listening to Brain (stdin) for anomalies...", file=sys.stderr)
    
    engine = AlertEngine(cooldown=COOLDOWN_SECONDS)
    
    # We will buffer lines after seeing the anomaly trigger to capture the details
    capturing_details = False
    anomaly_details = []
    
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            # Look for the exact trigger string from brain.py
            if "[!!! ANOMALY DETECTED !!!]" in line:
                if engine.can_alert():
                    # If we aren't on cooldown, start capturing the next 3 lines of details
                    capturing_details = True
                    anomaly_details = []
                else:
                    print(f"[Alert Suppressed] Cooldown active ({COOLDOWN_SECONDS}s). Anomaly ignored.", file=sys.stderr)
                continue

            # If we just triggered an alert, brains prints exactly 3 follow-up lines: Time/Process, Message, Features
            if capturing_details:
                anomaly_details.append(line)
                
                # We expect exactly 3 lines of context after the anomaly banner
                if len(anomaly_details) == 3:
                    capturing_details = False
                    
                    # Parse the captured details roughly
                    time_proc = anomaly_details[0]   # "Time: ... | Process: ..."
                    msg = anomaly_details[1]         # "Message: ..."
                    feats = anomaly_details[2]       # "Extracted Features -> ..."
                    
                    # 1. Trigger Mac Notification
                    engine.trigger_macos_notification(
                        title="Sentinel-AI Alert", 
                        message=f"{time_proc}\n{msg}"
                    )
                    
                    # 2. Trigger Discord Webhook
                    embed = {
                        "title": "System Anomaly",
                        "color": 16711680, # Red
                        "fields": [
                            {"name": "Context", "value": time_proc, "inline": False},
                            {"name": "Command/Message", "value": f"`{msg}`", "inline": False},
                            {"name": "AI Telemetry", "value": feats, "inline": False}
                        ],
                        "footer": {"text": "Sentinel-AI Local Execution Engine"}
                    }
                    engine.trigger_discord_webhook(embed)
                    
                    # 3. Transparently pass it to stdout for the Vault
                    print("[!!! ANOMALY DETECTED !!!]")
                    print(time_proc)
                    print(msg)
                    print(feats)
                    sys.stdout.flush()
                    
    except KeyboardInterrupt:
        print("\nMuscle execution stopped.", file=sys.stderr)
    except Exception as e:
        print(f"\nUnexpected error in Muscle: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
