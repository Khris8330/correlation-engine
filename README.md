# Correlation Engine

An advanced network threat intelligence tool that combines real-time network anomaly data with active attack surface analysis to produce correlated, prioritised threat assessments for every device on your network.

Built as a companion to the [Network Anomaly Detector](https://github.com/Khris8330/network-anomaly-detector).

---

## Features

- **Cross-tool correlation** — ingests device and alert data from the Network Anomaly Detector and combines it with its own findings
- **Attack surface analysis** — runs nmap port scans on every discovered device to identify:
  - Open ports and running services
  - OS fingerprinting
  - Security misconfigurations
- **Misconfiguration detection** — automatically flags:
  - Telnet, FTP, and other unencrypted services
  - Exposed databases (MySQL, MongoDB, Redis, Elasticsearch)
  - RDP and VNC remote access exposure
  - SMB exposure (ransomware attack vector)
  - HTTP without HTTPS
- **Threat scoring** — every device receives a correlation score (0–100) based on:
  - Anomaly detector alerts (new device, IP spoof, missing device)
  - Attack surface findings (open ports, misconfigurations)
  - Device behaviour (reconnect frequency, unknown vendor)
- **Unified dashboard** — displays correlated threat intelligence across three tabs:
  - Correlations — prioritised threat list with expandable details
  - Devices — all tracked devices from the anomaly detector
  - Anomaly Alerts — full alert history
- **Attack surface scan page** — detailed per-device breakdown of open ports, services, and misconfigurations
- **Auto-updating** — re-correlates all devices every 5 minutes automatically

---

## Threat Levels

| Level | Score | Meaning |
|---|---|---|
| **NONE** | 0–9 | No significant threats detected |
| **LOW** | 10–34 | Minor concerns, monitor the device |
| **MEDIUM** | 35–59 | Notable findings, investigate soon |
| **HIGH** | 60–79 | Serious threats, act promptly |
| **CRITICAL** | 80–100 | Immediate action required |

---

## Requirements

- Python 3.10+
- Linux (tested on Kali Linux)
- nmap installed on the system
- Root privileges for nmap OS detection and service fingerprinting
- [Network Anomaly Detector](https://github.com/Khris8330/network-anomaly-detector) must have run at least once

---

## Installation

```bash
git clone https://github.com/Khris8330/correlation-engine.git
cd correlation-engine
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Install nmap:
```bash
sudo apt install nmap -y
```

### Install python-nmap system-wide (required for sudo):
```bash
sudo pip install python-nmap --break-system-packages
```

---

## Usage

Make sure the Network Anomaly Detector has run at least once first, then:

```bash
sudo python dashboard.py
```

Then open your browser and go to:
http://127.0.0.1:5001
Note: runs on port **5001** so it doesn't clash with the anomaly detector on port 5000.

---

## Dashboard

- **Correlations tab** — every device ranked by threat score with expandable attack surface and anomaly alert details
- **Devices tab** — all devices tracked by the anomaly detector with reconnect counts and known status
- **Anomaly Alerts tab** — full alert history pulled from the anomaly detector database
- **Attack Surface Scans page** — detailed per-device breakdown of open ports, services, OS detection, and misconfigurations

---

## Project Structure:
correlation-engine/
├── dashboard.py              # Flask web dashboard + correlation thread
├── correlation_engine.py     # Core correlation logic and scoring
├── attack_surface.py         # nmap port scanning and misconfiguration checks
├── database.py               # SQLite database layer + anomaly detector reader
├── network_utils.py          # Local IP and subnet detection
├── data/
│   └── correlation.db        # SQLite database (auto-created)
└── templates/
├── index.html            # Main correlation dashboard
└── scans.html            # Attack surface scan results
---

## How It Works

1. On startup the database is initialised and the correlation engine launches as a background thread
2. The engine reads all devices and alerts from the anomaly detector's database
3. For each device, nmap runs a port scan detecting open ports, services, and OS
4. Misconfigurations are checked against a list of known dangerous patterns
5. All findings are combined into a correlation score per device
6. Results are saved to the correlation database and displayed on the dashboard
7. The entire process repeats every 5 minutes

---

## Architecture
Network Anomaly Detector
↓
Discovers devices
Detects anomalies
Saves to network.db
↓
Correlation Engine
↓
Reads network.db
Runs nmap per device
Checks misconfigurations
Calculates threat scores
Saves to correlation.db
↓
Unified Dashboard (port 5001)
---

## Planned Features

- OpenVAS integration for CVE-level vulnerability detection
- Login and authentication for dashboard access
- Email/SMS alerting for critical threats
- Export findings to PDF report

---

## Legal Disclaimer

This tool is intended for use on networks you own or have explicit written permission to scan. Unauthorised network scanning is illegal in most jurisdictions. The author assumes no responsibility for misuse.

---

## Author

**Khris8330**
