#!/bin/bash

# ==========================================
# Sentinel-AI Shield Block (Phase 8 Wrapper)
# ==========================================
# This script wraps 'sudo' to enforce Zero Trust
# based on access_ledger.json state.

LEDGER="access_ledger.json"
TRIGGER_FLAG="jit_trigger.flag"

# 1. Quickly check if Ledger is UNLOCKED using inline Python
STATE_CHECK=$(python3 -c "
import json, time
try:
    with open('$LEDGER', 'r') as f:
        data = json.load(f)
    if data.get('status') == 'UNLOCKED' and time.time() < data.get('expiry_timestamp', 0):
        print('ALLOW')
    else:
        print('DENY')
except Exception:
    print('DENY')
")

if [ "$STATE_CHECK" == "DENY" ]; then
    echo -e "\033[0;31m[UNAUTHORIZED] E-1 Level detected. Requesting E-4 Manager approval via Discord...\033[0m"
    # Trigger Gatekeeper Discord Bot invisibly
    touch "$TRIGGER_FLAG"
    exit 1
fi

# 2. If UNLOCKED, execute the requested original command!
echo -e "\033[0;32m[AUTHORIZED] E-4 Manager Session Active. Executing...\033[0m"
echo ""

# Run whatever they passed (e.g., ./shield_block.sh cat /etc/shadow)
sudo "$@"
COMMAND_EXIT_CODE=$?

# 3. Securely pack this authorized execution back into the Blockchain Vault using inline Python
python3 -c "
import sys, json, time
from datetime import datetime

cmd = 'sudo ' + ' '.join(sys.argv[1:])
log = {
    'timestamp': datetime.now().isoformat(),
    'process': 'shield_block.sh',
    'message': f'[AUTHORIZED EXEC] {cmd}'
}

# The vault expects an anomaly object through stdin, so we format it simply
print(json.dumps(log))
" "$@" | python3 vault.py

exit $COMMAND_EXIT_CODE
