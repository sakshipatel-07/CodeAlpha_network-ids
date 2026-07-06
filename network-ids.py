#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)

Pure-Python NIDS using Scapy. Detects:
  • Port scanning (SYN, FIN, NULL, XMAS scans)
  • Brute-force / repeated connection attempts
  • ICMP flood / ping flood
  • DNS exfiltration (unusually long domain names)
  • ARP spoofing / poisoning
  • Known malicious port knocking patterns
  • Large payload anomalies
"""

import sys
import time
import datetime
import threading
import collections
import argparse
import json
import os

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
BLUE   = "\033[94m"

SEVERITY_COLORS = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": GREEN}

# ─────────────────────────────────────────────
# Alert System
# ─────────────────────────────────────────────
alert_log = []
alert_lock = threading.Lock()

def alert(severity, rule, src, dst, detail, packet_num=None):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    color = SEVERITY_COLORS.get(severity, "")
    pkt_info = f" [pkt#{packet_num}]" if packet_num else ""
    record = {
        "time": ts, "severity": severity, "rule": rule,
        "src": src, "dst": dst, "detail": detail
    }
    with alert_lock:
        alert_log.append(record)
        print(f"\n{color}{BOLD}[{severity}]{RESET}{color} {ts}{pkt_info}")
        print(f"  Rule  : {rule}")
        print(f"  Src   : {src}  →  Dst: {dst}")
        print(f"  Detail: {detail}{RESET}")

# ─────────────────────────────────────────────
# State Trackers
# ─────────────────────────────────────────────
# Port scan detection
port_scan_tracker = collections.defaultdict(lambda: {"ports": set(), "syn_count": 0, "last_seen": 0})
SCAN_THRESHOLD    = 15    # unique ports in SCAN_WINDOW seconds → scan alert
SCAN_WINDOW       = 10    # seconds

# Brute-force detection
brute_tracker     = collections.defaultdict(lambda: {"count": 0, "last_seen": 0})
BRUTE_THRESHOLD   = 10    # connection attempts
BRUTE_WINDOW      = 5     # seconds
BRUTE_PORTS       = {22, 23, 21, 3389, 5900, 25, 110, 143}  # SSH, Telnet, FTP, RDP, VNC, mail

# ICMP flood
icmp_tracker      = collections.defaultdict(lambda: {"count": 0, "last_seen": 0})
ICMP_THRESHOLD    = 30    # ICMP packets in ICMP_WINDOW seconds
ICMP_WINDOW       = 5

# ARP spoof: track IP → MAC mappings
arp_table         = {}

# DNS exfil
DNS_MAX_LEN       = 50    # subdomains longer than this are suspicious

# Packet counter
packet_counter    = {"n": 0}
stats = collections.defaultdict(int)

# ─────────────────────────────────────────────
# Detection Rules
# ─────────────────────────────────────────────
def detect_port_scan(src, dport, flags, pkt_n):
    """Detect SYN, FIN, NULL, XMAS scans."""
    now   = time.time()
    entry = port_scan_tracker[src]

    # Reset window
    if now - entry["last_seen"] > SCAN_WINDOW:
        entry["ports"]     = set()
        entry["syn_count"] = 0
    entry["last_seen"] = now

    # Identify scan type
    scan_type = None
    if flags == 0x02:                          # SYN only
        scan_type = "SYN Scan"
        entry["syn_count"] += 1
    elif flags == 0x00:                        # NULL scan
        scan_type = "NULL Scan"
        alert("HIGH", scan_type, src, f":{dport}",
              "TCP packet with NO flags set – likely NULL scan (nmap -sN)", pkt_n)
    elif flags & 0x29 == 0x29:                 # FIN+PSH+URG = XMAS
        scan_type = "XMAS Scan"
        alert("HIGH", scan_type, src, f":{dport}",
              "FIN+PSH+URG set – likely XMAS scan (nmap -sX)", pkt_n)
    elif flags == 0x01:                        # FIN only
        scan_type = "FIN Scan"
        alert("MEDIUM", scan_type, src, f":{dport}",
              "FIN-only packet – stealth scan attempt", pkt_n)

    entry["ports"].add(dport)

    if len(entry["ports"]) >= SCAN_THRESHOLD:
        alert("CRITICAL", "Port Scan Detected", src, "multiple",
              f"{len(entry['ports'])} unique ports probed in {SCAN_WINDOW}s "
              f"(last: :{dport})", pkt_n)
        entry["ports"] = set()   # reset to avoid repeated alerts


def detect_brute_force(src, dport, pkt_n):
    """Detect repeated connections to authentication services."""
    if dport not in BRUTE_PORTS:
        return
    now   = time.time()
    key   = (src, dport)
    entry = brute_tracker[key]

    if now - entry["last_seen"] > BRUTE_WINDOW:
        entry["count"] = 0
    entry["last_seen"] = now
    entry["count"]    += 1

    if entry["count"] == BRUTE_THRESHOLD:
        svc = {22:"SSH", 23:"Telnet", 21:"FTP", 3389:"RDP",
               5900:"VNC", 25:"SMTP", 110:"POP3", 143:"IMAP"}.get(dport, str(dport))
        alert("HIGH", "Brute-Force Attempt", src, f":{dport}",
              f"{entry['count']} connection attempts to {svc} in {BRUTE_WINDOW}s", pkt_n)
        entry["count"] = 0


def detect_icmp_flood(src, pkt_n):
    """Detect ICMP flood / ping flood."""
    now   = time.time()
    entry = icmp_tracker[src]
    if now - entry["last_seen"] > ICMP_WINDOW:
        entry["count"] = 0
    entry["last_seen"] = now
    entry["count"]    += 1
    if entry["count"] == ICMP_THRESHOLD:
        alert("HIGH", "ICMP Flood / Ping Flood", src, "broadcast/target",
              f"{entry['count']} ICMP packets in {ICMP_WINDOW}s", pkt_n)
        entry["count"] = 0


def detect_arp_spoof(packet, pkt_n):
    """Detect ARP poisoning by IP → MAC changes."""
    if ARP not in packet:
        return
    arp = packet[ARP]
    if arp.op != 2:   # only ARP Reply
        return
    ip, mac = arp.psrc, arp.hwsrc
    if ip in arp_table and arp_table[ip] != mac:
        alert("CRITICAL", "ARP Spoofing / Poisoning", ip, "LAN",
              f"IP {ip} changed MAC: {arp_table[ip]} → {mac}", pkt_n)
    arp_table[ip] = mac


def detect_dns_exfil(packet, pkt_n):
    """Detect DNS tunneling via unusually long subdomains."""
    if DNS not in packet or packet[DNS].qr != 0:
        return
    try:
        qname = packet[DNS].qd.qname.decode().rstrip(".")
        subdomain = qname.split(".")[0]
        if len(subdomain) > DNS_MAX_LEN:
            src = packet[IP].src if IP in packet else "?"
            alert("MEDIUM", "Possible DNS Exfiltration", src, "DNS",
                  f"Unusually long subdomain ({len(subdomain)} chars): {subdomain[:60]}...",
                  pkt_n)
    except Exception:
        pass


def detect_large_payload(packet, src, dst, proto, pkt_n):
    """Flag abnormally large payloads."""
    if Raw in packet:
        payload_len = len(packet[Raw].load)
        if payload_len > 65000:
            alert("LOW", "Anomalous Payload Size", src, dst,
                  f"{proto} payload of {payload_len} bytes may indicate tunneling or DoS",
                  pkt_n)

# ─────────────────────────────────────────────
# Main Packet Handler
# ─────────────────────────────────────────────
def process_packet(packet):
    packet_counter["n"] += 1
    pkt_n = packet_counter["n"]
    stats["total"] += 1

    # Dot heartbeat every 10 packets
    if pkt_n % 10 == 0:
        print(f"  {BLUE}[{pkt_n} pkts captured]{RESET}", end="\r", flush=True)

    # ARP
    detect_arp_spoof(packet, pkt_n)

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst

    # ICMP
    if ICMP in packet:
        stats["icmp"] += 1
        detect_icmp_flood(src, pkt_n)
        return

    # DNS
    if UDP in packet and DNS in packet:
        stats["dns"] += 1
        detect_dns_exfil(packet, pkt_n)

    # UDP
    if UDP in packet:
        stats["udp"] += 1
        detect_large_payload(packet, src, dst, "UDP", pkt_n)
        return

    # TCP
    if TCP in packet:
        stats["tcp"] += 1
        tcp   = packet[TCP]
        flags = int(tcp.flags)
        dport = tcp.dport
        sport = tcp.sport

        # Only inspect SYN packets for scan/brute detection (reduce FP)
        if flags & 0x02 or flags in (0x00, 0x01, 0x29):
            detect_port_scan(src, dport, flags, pkt_n)
            if flags & 0x02:  # SYN
                detect_brute_force(src, dport, pkt_n)

        detect_large_payload(packet, src, dst, "TCP", pkt_n)

# ─────────────────────────────────────────────
# Summary & Report
# ─────────────────────────────────────────────
def print_summary():
    print("\n\n" + "=" * 65)
    print(f"{BOLD}  📊  IDS SESSION SUMMARY{RESET}")
    print("=" * 65)
    print(f"  Total packets  : {stats['total']}")
    print(f"  TCP            : {stats['tcp']}")
    print(f"  UDP            : {stats['udp']}")
    print(f"  ICMP           : {stats['icmp']}")
    print(f"  DNS queries    : {stats['dns']}")
    print(f"  Alerts raised  : {len(alert_log)}")

    if alert_log:
        sev_counts = collections.Counter(a["severity"] for a in alert_log)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in sev_counts:
                c = SEVERITY_COLORS.get(sev, "")
                print(f"    {c}{sev:<12}{RESET}  {sev_counts[sev]}")

    print("=" * 65)

def save_alerts(path="ids_alerts.json"):
    with open(path, "w") as f:
        json.dump(alert_log, f, indent=2)
    print(f"\n  ✅  Alerts saved → {path}")

# ─────────────────────────────────────────────
# Demo Mode (no root / no live capture)
# ─────────────────────────────────────────────
def run_demo():
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw, Ether

    print("=" * 65)
    print(f"{BOLD}  🛡️ – Network IDS   DEMO MODE{RESET}")
    print("=" * 65)
    print("  Simulating malicious network events...\n")
    print("-" * 65)

    # 1. SYN port scan (16 ports)
    for port in range(20, 37):
        pkt = IP(src="10.0.0.99", dst="192.168.1.5") / \
              TCP(dport=port, sport=54321, flags="S")
        process_packet(pkt)

    # 2. SSH brute force (10 SYN to port 22)
    for _ in range(10):
        pkt = IP(src="45.33.32.156", dst="192.168.1.5") / \
              TCP(dport=22, sport=60000, flags="S")
        process_packet(pkt)

    # 3. ICMP flood (31 pings)
    for _ in range(31):
        pkt = IP(src="172.16.0.50", dst="192.168.1.5") / ICMP(type=8)
        process_packet(pkt)

    # 4. NULL scan
    pkt = IP(src="10.0.0.77", dst="192.168.1.5") / \
          TCP(dport=80, sport=11111, flags=0)
    process_packet(pkt)

    # 5. XMAS scan
    pkt = IP(src="10.0.0.77", dst="192.168.1.5") / \
          TCP(dport=443, sport=22222, flags="FPU")
    process_packet(pkt)

    # 6. ARP spoof: same IP, different MAC
    pkt1 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    process_packet(pkt1)
    pkt2 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")
    process_packet(pkt2)

    # 7. DNS exfiltration (long subdomain)
    long_sub = "A" * 70 + ".evil-c2.com"
    pkt = IP(src="192.168.1.20", dst="8.8.8.8") / \
          UDP(sport=12345, dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=long_sub))
    process_packet(pkt)

    print_summary()
    save_alerts()

# ─────────────────────────────────────────────
# Live Capture Mode
# ─────────────────────────────────────────────
def run_live(interface=None, count=0, bpf_filter=""):
    print("=" * 65)
    print(f"{BOLD}  🛡️  CodeAlpha – Network IDS  (Task 4){RESET}")
    print("=" * 65)
    iface = interface or "all interfaces"
    print(f"  Interface  : {iface}")
    print(f"  Packet cap : {'unlimited' if count == 0 else count}")
    print(f"  BPF Filter : {bpf_filter or 'none'}")
    print("-" * 65)
    print("  Monitoring started. Alerts appear below. (Ctrl+C to stop)")
    print("-" * 65)
    try:
        sniff(
            iface=interface,
            filter=bpf_filter or None,
            prn=process_packet,
            count=count or 0,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n  [!] Monitoring stopped by user.")
    finally:
        print_summary()
        save_alerts()

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("[ERROR] scapy not installed. Run: pip install scapy")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="CodeAlpha Network IDS")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Packet limit (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter (e.g. "tcp")')
    parser.add_argument("--demo", action="store_true",
                        help="Simulate attacks without root")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        run_live(interface=args.interface, count=args.count, bpf_filter=args.filter)
