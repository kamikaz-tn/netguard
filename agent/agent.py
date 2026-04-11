#!/usr/bin/env python3
"""
netguard/agent/agent.py
─────────────────────────
NetGuard Local Agent

This script runs on the USER'S MACHINE (not the server).
It has access to the local network and does the real scanning.
Results are sent to the NetGuard backend API.

Why a local agent?
  A web server can't see your home network — it lives on the internet.
  This agent runs locally, scans your LAN, and reports findings
  to the backend which stores them and pushes alerts to your browser.

Usage:
  python agent.py --scan                  # run one scan now
  python agent.py --watch --interval 300  # scan every 5 minutes
  python agent.py --help                  # show all options

Requirements:
  pip install requests python-nmap scapy python-dotenv
  On Linux/Mac: run with sudo for ARP scanning
  On Windows: run as Administrator
"""

import os
import sys
import json
import time
import socket
import hashlib
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path


import requests
from dotenv import load_dotenv

# ── Optional imports (graceful degradation) ────────────────────────────────────
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap not found. Install with: pip install python-nmap")
    print("   Port scanning will be disabled.\n")

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0   # suppress scapy output
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  scapy not found. Install with: pip install scapy")
    print("   ARP scanning will use ping fallback (less accurate).\n")

# ── Load config ────────────────────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / '.env')

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
AGENT_SECRET = os.getenv("AGENT_SECRET", "change_this_shared_secret")
USER_ID = int(os.getenv("USER_ID", "0"))
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "")   # auto-detect if empty
SCAN_TYPE = os.getenv("SCAN_TYPE", "full")        # quick | full

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("netguard-agent.log"),
    ]
)
log = logging.getLogger("netguard-agent")


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def get_local_network() -> str:
    """Auto-detect the local network range (e.g. 192.168.1.0/24)."""
    try:
        # Connect to external IP to find our interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 subnet (works for most home routers)
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


VENDOR_MAP = {
    "00:1A:2B": "Apple, Inc.",
    "A4:83:E7": "Apple, Inc.",
    "2C:4D:54": "Samsung Electronics",
    "A8:9C:ED": "TP-Link Technologies",
    "B4:F0:AB": "Realtek Semiconductor",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "VirtualBox / Oracle",
}

PORT_RISK_DB = {
    21:    {"service": "FTP",         "risk": "high"},
    22:    {"service": "SSH",         "risk": "medium"},
    23:    {"service": "Telnet",      "risk": "critical"},
    80:    {"service": "HTTP",        "risk": "medium"},
    135:   {"service": "RPC",         "risk": "high"},
    139:   {"service": "NetBIOS",     "risk": "high"},
    443:   {"service": "HTTPS",       "risk": "low"},
    445:   {"service": "SMB",         "risk": "critical"},
    1234:  {"service": "RAT",         "risk": "critical"},
    3389:  {"service": "RDP",         "risk": "critical"},
    4444:  {"service": "Metasploit",  "risk": "critical"},
    5555:  {"service": "ADB",         "risk": "critical"},
    5900:  {"service": "VNC",         "risk": "high"},
    6666:  {"service": "IRC/Malware", "risk": "critical"},
    12345: {"service": "NetBus",      "risk": "critical"},
    31337: {"service": "BackOrifice", "risk": "critical"},
}

SUSPICIOUS_PORTS = {4444, 31337, 1234, 5555, 9999, 6666, 12345, 54321}
CRITICAL_PORTS   = {23, 21, 135, 139, 445, 3389, 5900}


def lookup_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    return VENDOR_MAP.get(prefix, "Unknown Vendor")


# ══════════════════════════════════════════════════════════════════════════════
# SCANNING
# ══════════════════════════════════════════════════════════════════════════════

def arp_scan(network_range: str) -> List[Dict[str, str]]:
    """Discover live hosts via ARP. Returns [{ip, mac}, ...]."""
    if SCAPY_AVAILABLE:
        return _arp_scan_scapy(network_range)
    else:
        return _arp_scan_ping(network_range)


def _arp_scan_scapy(network_range: str) -> List[Dict[str, str]]:
    log.info(f"ARP scanning {network_range} via Scapy...")
    try:
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=3, verbose=False)
        hosts = [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in answered]
        log.info(f"ARP scan found {len(hosts)} hosts")
        return hosts
    except PermissionError:
        log.error("ARP scan requires root/sudo. Falling back to ping sweep.")
        return _arp_scan_ping(network_range)
    except Exception as e:
        log.error(f"ARP scan error: {e}")
        return []


def _arp_scan_ping(network_range: str) -> List[Dict[str, str]]:
    """Ping sweep fallback — no root required but no MAC addresses."""
    import ipaddress
    import subprocess

    log.info(f"Ping sweeping {network_range}...")
    network = ipaddress.ip_network(network_range, strict=False)
    hosts = []

    for ip in list(network.hosts())[:254]:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                hosts.append({"ip": str(ip), "mac": ""})
        except Exception:
            pass

    log.info(f"Ping sweep found {len(hosts)} hosts")
    return hosts


def port_scan(ip: str, scan_type: str = "full") -> List[Dict[str, Any]]:
    """Scan open ports on a host. Returns list of port dicts."""
    if not NMAP_AVAILABLE:
        log.warning(f"Nmap not available, skipping port scan for {ip}")
        return []

    nm = nmap.PortScanner()
    args = "-F --open" if scan_type == "quick" else "-sV --open -T4"

    log.info(f"  Port scanning {ip} ({scan_type})...")
    try:
        nm.scan(hosts=ip, arguments=args)
    except Exception as e:
        log.error(f"  Nmap error on {ip}: {e}")
        return []

    if ip not in nm.all_hosts():
        return []

    ports = []
    for proto in ["tcp", "udp"]:
        if proto not in nm[ip]:
            continue
        for port_num, port_data in nm[ip][proto].items():
            if port_data["state"] != "open":
                continue
            risk_info = PORT_RISK_DB.get(port_num, {"service": "Unknown", "risk": "low"})
            version = f"{port_data.get('product','')} {port_data.get('version','')}".strip()
            ports.append({
                "port": port_num,
                "protocol": proto,
                "state": "open",
                "service": port_data.get("name") or risk_info["service"],
                "version": version,
                "is_suspicious": port_num in SUSPICIOUS_PORTS,
                "is_critical": port_num in CRITICAL_PORTS,
                "risk_level": risk_info["risk"],
            })

    return sorted(ports, key=lambda p: p["port"])


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def guess_os(mac: str, open_ports: List[int]) -> str:
    vendor = lookup_vendor(mac).lower()
    if "apple" in vendor:       return "macOS / iOS"
    if "samsung" in vendor:     return "Android / Tizen"
    if "raspberry" in vendor:   return "Linux (Raspberry Pi)"
    if "tp-link" in vendor:     return "Router / Embedded Linux"
    if 3389 in open_ports:      return "Windows (RDP detected)"
    if 445 in open_ports:       return "Windows"
    if 22 in open_ports:        return "Linux / Unix"
    return "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def run_scan(network_range: str, scan_type: str = "full") -> List[Dict]:
    """
    Full scan pipeline:
    1. ARP discover hosts
    2. Port scan each host
    3. Enrich with vendor, OS, risk
    """
    log.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info(f"Starting {scan_type} scan on {network_range}")
    log.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    raw_hosts = arp_scan(network_range)
    if not raw_hosts:
        log.warning("No hosts found. Check network range and permissions.")
        return []

    devices = []
    for host in raw_hosts:
        ip = host["ip"]
        mac = host.get("mac", "").upper()
        vendor = lookup_vendor(mac)

        log.info(f"Scanning {ip} ({vendor or 'unknown vendor'})...")

        ports = port_scan(ip, scan_type)
        open_port_nums = [p["port"] for p in ports]
        hostname = resolve_hostname(ip)

        # Determine threat status from ports
        has_critical = any(p["risk_level"] == "critical" for p in ports)
        status = "threat" if has_critical else "unknown"

        device = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "os_guess": guess_os(mac, open_port_nums),
            "status": status,
            "ports": ports,
            "risk_score": 0.0,
        }
        devices.append(device)
        log.info(f"  → {len(ports)} open ports, status: {status}")

    log.info(f"Scan complete. {len(devices)} devices found.")
    return devices


# ══════════════════════════════════════════════════════════════════════════════
# BACKEND COMMUNICATION
# ══════════════════════════════════════════════════════════════════════════════

def push_to_backend(devices: List[Dict], network_range: str) -> bool:
    """POST scan results to the NetGuard backend API."""
    if not USER_ID:
        log.error("USER_ID not set in .env — cannot push to backend")
        return False

    payload = {
        "agent_secret": AGENT_SECRET,
        "user_id": USER_ID,
        "network_range": network_range,
        "devices": devices,
    }

    try:
        url = f"{BACKEND_URL}/api/scan/agent"
        log.info(f"Pushing results to {url}...")
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        log.info(f"✅ Backend accepted results: scan ID {data.get('id')}, "
                 f"risk score {data.get('risk_score')}/100, "
                 f"{data.get('threats_found')} threats")
        return True
    except requests.ConnectionError:
        log.error(f"Cannot connect to backend at {BACKEND_URL}. Is it running?")
        return False
    except requests.HTTPError as e:
        log.error(f"Backend rejected results: {e.response.status_code} — {e.response.text}")
        return False
    except Exception as e:
        log.error(f"Unexpected error pushing to backend: {e}")
        return False


def save_local(devices: List[Dict], network_range: str):
    """Save scan results to a local JSON file as backup."""
    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = {
        "timestamp": datetime.now().isoformat(),
        "network_range": network_range,
        "devices": devices,
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    log.info(f"💾 Results saved locally: {filename}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard Local Agent — scans your network and reports to the backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --scan
  python agent.py --scan --range 192.168.0.0/24 --type quick
  python agent.py --watch --interval 300
  python agent.py --scan --local-only
        """
    )

    parser.add_argument("--scan", action="store_true",
                        help="Run a single scan and exit")
    parser.add_argument("--watch", action="store_true",
                        help="Run continuously, scanning on interval")
    parser.add_argument("--interval", type=int, default=300,
                        help="Seconds between scans in watch mode (default: 300)")
    parser.add_argument("--range", type=str, default="",
                        help="Network range to scan (e.g. 192.168.1.0/24). Auto-detected if not set.")
    parser.add_argument("--type", choices=["quick", "full"], default="full",
                        help="Scan type: quick (top 100 ports) or full (top 1000 + version detection)")
    parser.add_argument("--local-only", action="store_true",
                        help="Save results locally only, don't push to backend")
    parser.add_argument("--check-env", action="store_true",
                        help="Check environment and dependencies, then exit")

    args = parser.parse_args()

    # ── Environment check ────────────────────────────────────────────────────
    if args.check_env:
        print("\n=== NetGuard Agent — Environment Check ===\n")
        print(f"Backend URL:    {BACKEND_URL}")
        print(f"User ID:        {USER_ID or '❌ NOT SET (edit .env)'}")
        print(f"Agent Secret:   {'✅ Set' if AGENT_SECRET != 'change_this_shared_secret' else '⚠️  Using default — change in .env'}")
        print(f"Nmap:           {'✅ Available' if NMAP_AVAILABLE else '❌ Not installed (pip install python-nmap)'}")
        print(f"Scapy:          {'✅ Available' if SCAPY_AVAILABLE else '⚠️  Not installed (pip install scapy) — ping fallback active'}")
        network = get_local_network()
        print(f"Detected LAN:   {network}")
        print()
        return

    # ── Determine network range ───────────────────────────────────────────────
    network = args.range or NETWORK_RANGE or get_local_network()
    scan_type = args.type or SCAN_TYPE

    print(f"""
╔══════════════════════════════════════════╗
║         NetGuard Local Agent v1.0        ║
╚══════════════════════════════════════════╝
  Backend:  {BACKEND_URL}
  Network:  {network}
  Scan:     {scan_type}
  Mode:     {"watch (every " + str(args.interval) + "s)" if args.watch else "single scan"}
""")

    def do_scan():
        devices = run_scan(network, scan_type)
        if not devices:
            return

        if args.local_only:
            save_local(devices, network)
        else:
            success = push_to_backend(devices, network)
            if not success:
                log.info("Saving locally as fallback...")
                save_local(devices, network)

    # ── Single scan ───────────────────────────────────────────────────────────
    if args.scan:
        do_scan()
        return

    # ── Watch mode ────────────────────────────────────────────────────────────
    if args.watch:
        log.info(f"Watch mode active — scanning every {args.interval}s. Press Ctrl+C to stop.")
        while True:
            do_scan()
            log.info(f"Next scan in {args.interval} seconds...")
            time.sleep(args.interval)
        return

    # ── No args ───────────────────────────────────────────────────────────────
    parser.print_help()


if __name__ == "__main__":
    main()
