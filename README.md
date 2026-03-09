Sentinel-AI: Autonomous Zero-Trust Defense for Critical Infrastructure
Sentinel-AI is a distributed, machine-speed security framework designed to protect legacy and unpatchable industrial systems (SCADA, Medical IoT, and Financial OT) from zero-day ransomware and lateral supply-chain attacks.

By utilizing an offline behavioral AI brain and an autonomous remediation agent, Sentinel-AI moves incident response from the 45-minute industry average to under 500 milliseconds—neutralizing threats before a single file can be fully encrypted.

The Core Problem:-
Legacy infrastructure (like hospital networks and power grids) relies on cloud-dependent security and human intervention. When a zero-day attack hits:
Network Latency: Cloud-based EDRs suffer from data transfer delays.
Human Delay: SOC analysts take minutes or hours to respond, while ransomware encrypts drives in seconds.
IT/OT Convergence: Flat networks allow malware to move laterally from a compromised laptop to a life-critical surgical machine.
Architecture: The Digital Immune System
Sentinel-AI follows a "dead-drop" spy architecture to ensure the AI brain remains mathematically untouchable.

1. The Eyes (Telemetry Sensors)
Lightweight OS-level scripts (log_ear.py) monitor process lineage, file entropy, and canary file modifications.

2. The Wall (Software Data Diode)
A strict, one-way network funnel built on NGINX and FastAPI. It enforces an "Inbound Only" rule, preventing hackers from using the security channel to back-out data or attack the AI server.

3. The Brain (Offline ML)
An Isolation Forest model sandboxed in a secure Docker vault. It performs unsupervised behavioral analysis to identify mathematical anomalies in process execution—detecting threats without needing a pre-existing virus signature.

4. The Cure (The Surgeon Agent)
A pull-based autonomous agent that wakes up every 500ms to check for "Kill Orders" in the central registry. If an infection is detected, it executes an OS-level TASKKILL and network isolation locally, requiring zero human input.

Technical Stack:-

Category	Technology
Intelligence	Python 3.10, Scikit-Learn (Isolation Forest)
Infrastructure	Docker, NGINX Reverse Proxy, FastAPI
Storage	SQLite3 (Fleet Registry & Threat Intel)
Cryptography	AES-256 (Telemetry), JWT (Identity Verification)
Monitoring	Flask (Real-time Analytics Dashboard)

Key Security Protocols:-

The Burned Protocol: The moment a MAC address is flagged as compromised, its cryptographic JWT is permanently revoked at the database level.
Deception Canary Traps: Hidden system files serve as tripwires. Any unauthorized modification triggers an immediate local process termination.
Iron Dome Self-Preservation: The central server monitors its own code integrity and executes a fail-secure shutdown if tampering is detected.

Prerequisites:-

Python 3.10+
Docker & Docker Compose
NGINX

Installation (PoC Deployment)
Clone the repository:
git clone https://github.com/Alien6093/Sentinel-AI.git
cd Sentinel-AI

Setup the AI Vault:
docker-compose up --build
Deploy Endpoint Sensor:
pip install -r requirements.txt
python sensors/log_ear.py

Project Status:-

Version: V1 Prototype (Proof-of-Concept)

Developed by Sentinel Syndicate for the India Innovates 2026 Summit.