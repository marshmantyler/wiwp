# Wishin' I Was Phishin' (WIWP)

> **A lightweight, automated phishing triage and ChatOps pipeline designed to combat SOC alert fatigue.**

WIWP is a continuous background daemon that monitors employee-reported phishing inboxes, automatically enriches Indicators of Compromise (IoCs) using VirusTotal, leverages Groq's high-speed LLMs for deterministic threat analysis, and pushes color-coded, actionable alerts directly to your SOC's Discord channel.

## Key Features & Technical Achievements

*   **Zero Hardcoding Policy:** 100% environment-variable driven. No hardcoded credentials, API keys, or channel IDs.
*   **Async-Safe IMAP Handling:** Safely wraps blocking Python `imaplib` I/O operations in `asyncio.to_thread()` to prevent freezing the Discord event loop.
*   **In-Memory Malware Hashing:** Calculates SHA-256 hashes of malicious attachments strictly in-memory. **Zero disk writes** prevent accidental execution or triggering of local endpoint AV/EDR.
*   **Rate-Limit-Aware Threat Intel:** Integrates with VirusTotal v3 via asynchronous HTTP (`aiohttp`). Includes a built-in domain allowlist and automatic throttling to respect free-tier API quotas (4 req/min).
*   **Strict JSON AI Parsing:** Utilizes Groq's API with forced JSON-mode to guarantee deterministic, machine-readable outputs from the LLM (Verdict, Confidence, Tactics, Remediation).
*   **Defensive Parsing & Sanitization:** Automatically defangs malicious URLs (e.g., `hxxps[://]malicious[.]com`) before logging or displaying them to prevent accidental clicks by analysts.

## Architecture Pipeline

The daemon runs a sequential 3-step pipeline every 30 seconds (configurable) to prevent SQLite database locking:

1.  **Ingestion & Enrichment (Phase 1):** Polls configured IMAP folders (e.g., INBOX, Spam). Extracts URLs and attachment hashes, sanitizes the HTML body, and queries VirusTotal for threat intelligence. Saves the pending record to a local SQLite state machine (`wiwp.db`).
2.  **AI Triage (Phase 2):** Fetches pending records and injects the email body and VT enrichment data into a strict prompt. The Groq LLM acts as a Tier 3 Analyst, returning a structured JSON verdict (SAFE, SUSPICIOUS, MALICIOUS).
3.  **ChatOps Alerting (Phase 3):** Constructs a visually distinct, color-coded Discord Embed containing the AI's executive summary, identified tactics, and suggested remediation steps. Pushes the alert to a dedicated SOC channel and marks the ticket as resolved.

## Prerequisites

Before you begin, ensure you have the following:
*   **Python 3.11+** installed.
*   **Discord Bot Token:** Create an app in the [Discord Developer Portal](https://discord.com/developers/applications). **Crucial:** You must enable the **Message Content Intent** under the Bot tab.
*   **Groq API Key:** Obtain a free API key from the [Groq Console](https://console.groq.com/).
*   **VirusTotal API Key:** Obtain a free API key from [VirusTotal](https://www.virustotal.com/).
*   **Mailbox Access:** An email account with IMAP enabled. (If using Gmail, you must enable 2FA and generate an **App Password**).

## Installation & Setup

**1. Clone the repository:**
```bash
git clone [https://github.com/yourusername/wishin-i-was-phishin.git](https://github.com/yourusername/wishin-i-was-phishin.git)
cd wishin-i-was-phishin
```

2. Create and activate a virtual environment:
```Bash

python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```
3. Install dependencies:
```Bash

pip install -r requirements.txt
```
4. Configure the environment:
Copy the example environment file and fill in your credentials.
```Bash

cp .env.example .env
```
5. Discover your IMAP Folders (Crucial for Spam detection):**
Because different email providers use hidden internal names for their folders (e.g., Gmail uses `[Gmail]/Spam`, while Inbox.lv uses `INBOX/spam`), you need to find the exact namespace your provider uses. 

Run the included discovery tool:
```bash
python check_folders.py
```

The script will output the exact internal folder names for your account. Copy the names of your Inbox and Spam folders, and update the IMAP_FOLDERS variable in your .env file as a comma-separated list:
Example: IMAP_FOLDERS="INBOX,INBOX/spam"

## Usage
To run the WIWP daemon locally, execute the main script from your terminal:

python main.py

You should see console output indicating the bot has successfully logged into Discord, initialized the local SQLite database, and started the continuous SOC Pipeline Loop.
## Deployment (Raspberry Pi / Linux)
WIWP is highly lightweight and optimized to run seamlessly on a Raspberry Pi or a small Linux VPS. To ensure it runs continuously in the background and automatically restarts upon system reboot, it is highly recommended to daemonize the script using systemd.
1. Create a systemd service file:

sudo nano /etc/systemd/system/wiwp.service

2. Paste the following configuration snippet (adjust paths and user as necessary):

[Unit]
Description=WIWP Phishing Triage Daemon
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/wishin-i-was-phishin
ExecStart=/home/pi/wishin-i-was-phishin/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target

3. Enable and start your new background service:

sudo systemctl daemon-reload
sudo systemctl enable wiwp.service
sudo systemctl start wiwp.service

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the LICENSE file for details.


