# 🛡️ Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=for-the-badge)
![Internship](https://img.shields.io/badge/CodeAlpha-Cybersecurity%20Internship-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)

> **Task 4 of CodeAlpha Cybersecurity Internship**
> A Python-based Network Intrusion Detection System (NIDS) that monitors live network traffic and automatically detects malicious activity, attacks, and suspicious behaviour in real time.

---

## 📌 About the Project

This project is a **Network Intrusion Detection System (NIDS)** built using Python and the Scapy library. It continuously monitors network traffic and raises alerts when it detects known attack patterns such as port scans, brute-force attempts, ICMP floods, ARP spoofing, and DNS exfiltration.

The system assigns severity levels (CRITICAL, HIGH, MEDIUM, LOW) to each detected threat and saves all alerts to a JSON log file for further analysis.

---

## ✨ Features

- 🔍 **Port Scan Detection** — detects SYN, NULL, XMAS and FIN scans
- 🔐 **Brute-Force Detection** — monitors SSH, RDP, FTP, Telnet login attempts
- 🌊 **ICMP Flood Detection** — detects ping flood / DoS attacks
- 🎭 **ARP Spoofing Detection** — catches ARP poisoning / man-in-the-middle attacks
- 📡 **DNS Exfiltration Detection** — flags unusually long DNS subdomains
- 📦 **Large Payload Anomaly** — detects abnormally large packets (tunneling/DoS)
- 🚨 **Severity Levels** — CRITICAL / HIGH / MEDIUM / LOW alerts
- 📊 **Session Summary** — full statistics at end of monitoring session
- 💾 **JSON Alert Logging** — all alerts saved to `ids_alerts.json`
- 🎮 **Demo Mode** — simulate attacks without admin rights

---

## 🛠️ Technologies Used

| Tool | Purpose |
|------|---------|
| Python 3.7+ | Programming language |
| Scapy | Live packet capture and analysis |
| Collections | Packet and IP statistics tracking |
| Threading | Concurrent alert handling |
| JSON | Alert log file storage |
| Argparse | Command line arguments |
| Npcap (Windows) | Packet capture driver |

---

## ⚙️ Installation & Setup

### Step 1 — Clone the repository
```bash
git clone https://github.com/sakshipatel-07/CodeAlpha_network-ids.git
cd CodeAlpha_network-ids
```

### Step 2 — Install required library
```bash
pip install scapy
```

### Step 3 — Windows only: Install Npcap
Download and install Npcap from https://npcap.com/#download

> ✅ During installation tick: **"Install Npcap in WinPcap API-compatible mode"**

> ✅ Restart your computer after installation

---

## 🚀 How to Run

### Demo Mode (No admin required — works on all systems)
```bash
python network-ids.py --demo
```

### Live Monitoring — Windows (Run CMD as Administrator)
```bash
python network-ids.py -c 100
```

### Live Monitoring — Linux / Mac
```bash
sudo python3 network-ids.py -c 100
```

### With Filters
```bash
# Monitor only TCP traffic
python network-ids.py -c 100 -f "tcp"

# Monitor only UDP traffic
python network-ids.py -c 100 -f "udp"

# Specify a network interface
python network-ids.py -i eth0 -c 200

# Unlimited monitoring (until Ctrl+C)
python network-ids.py -c 0
```

---

## 📋 Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--demo` | Run in demo mode with simulated attacks | Off |
| `-c`, `--count` | Number of packets to monitor (0 = unlimited) | 0 |
| `-i`, `--interface` | Network interface to monitor | All |
| `-f`, `--filter` | BPF filter string | None |

---

## 📸 Sample Output

```
═══════════════════════════════════════════════════════════════════
   🛡️  CodeAlpha – Network IDS  (Task 4)  DEMO MODE
═══════════════════════════════════════════════════════════════════
  Simulating malicious network events...
─────────────────────────────────────────────────────────────────

[CRITICAL] 14:32:05.123
  Rule  : Port Scan Detected
  Src   : 10.0.0.99  →  Dst: multiple
  Detail: 16 unique ports probed in 10s

[HIGH] 14:32:05.124
  Rule  : Brute-Force Attempt
  Src   : 45.33.32.156  →  Dst: :22
  Detail: 10 connection attempts to SSH in 5s

[HIGH] 14:32:05.125
  Rule  : ICMP Flood / Ping Flood
  Src   : 172.16.0.50  →  Dst: broadcast/target
  Detail: 31 ICMP packets in 5s

[HIGH] 14:32:05.126
  Rule  : NULL Scan
  Src   : 10.0.0.77  →  Dst: :80
  Detail: TCP packet with NO flags set – likely NULL scan (nmap -sN)

[HIGH] 14:32:05.127
  Rule  : XMAS Scan
  Src   : 10.0.0.77  →  Dst: :443
  Detail: FIN+PSH+URG set – likely XMAS scan (nmap -sX)

[CRITICAL] 14:32:05.128
  Rule  : ARP Spoofing / Poisoning
  Src   : 192.168.1.1  →  Dst: LAN
  Detail: IP 192.168.1.1 changed MAC: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66

[MEDIUM] 14:32:05.129
  Rule  : Possible DNS Exfiltration
  Src   : 192.168.1.20  →  Dst: DNS
  Detail: Unusually long subdomain (70 chars): AAAAAAAAAA...

═══════════════════════════════════════════════════════════════════
  📊  IDS SESSION SUMMARY
═══════════════════════════════════════════════════════════════════
  Total packets  : 150
  TCP            : 80
  UDP            : 30
  ICMP           : 31
  DNS queries    : 1
  Alerts raised  : 7

    CRITICAL      2
    HIGH          4
    MEDIUM        1

  ✅  Alerts saved → ids_alerts.json
═══════════════════════════════════════════════════════════════════
```

---

## 💾 Alert Log File (ids_alerts.json)

All detected threats are automatically saved to `ids_alerts.json`:

```json
[
  {
    "time": "14:32:05.123",
    "severity": "CRITICAL",
    "rule": "Port Scan Detected",
    "src": "10.0.0.99",
    "dst": "multiple",
    "detail": "16 unique ports probed in 10s"
  },
  {
    "time": "14:32:05.124",
    "severity": "HIGH",
    "rule": "Brute-Force Attempt",
    "src": "45.33.32.156",
    "dst": ":22",
    "detail": "10 connection attempts to SSH in 5s"
  }
]
```

---

## 🚨 Detection Rules

| Alert | Severity | Trigger Condition |
|-------|----------|-------------------|
| Port Scan Detected | CRITICAL | 15+ unique ports probed in 10 seconds |
| Brute-Force Attempt | HIGH | 10+ connection attempts to SSH/RDP/FTP in 5 seconds |
| ICMP Flood | HIGH | 30+ ICMP packets from same source in 5 seconds |
| NULL Scan | HIGH | TCP packet with zero flags set |
| XMAS Scan | HIGH | TCP packet with FIN+PSH+URG flags |
| FIN Scan | MEDIUM | TCP packet with only FIN flag set |
| ARP Spoofing | CRITICAL | IP address mapped to a new MAC address |
| DNS Exfiltration | MEDIUM | DNS subdomain longer than 50 characters |
| Large Payload | LOW | Packet payload exceeds 65000 bytes |

---

## 📁 Project Structure

```
CodeAlpha_network-ids/
│
├── network-ids.py       # Main IDS program
├── ids_alerts.json      # Auto-generated alert log file
└── README.md            # Project documentation
```

---

## 🔐 Monitored Services (Brute-Force Detection)

| Port | Service |
|------|---------|
| 22 | SSH |
| 23 | Telnet |
| 21 | FTP |
| 3389 | RDP (Remote Desktop) |
| 5900 | VNC |
| 25 | SMTP |
| 110 | POP3 |
| 143 | IMAP |

---

## ⚠️ Disclaimer

> This tool is built for **educational purposes only** as part of the CodeAlpha Cybersecurity Internship. Only use it on networks you own or have explicit permission to monitor. Unauthorized network monitoring is illegal and unethical.

---



⭐ If you found this project helpful, please give it a star!
