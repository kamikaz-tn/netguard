#!/usr/bin/env python3
"""
netguard/agent/agent.py
─────────────────────────
NetGuard Local Agent
 
Usage:
  python agent.py --scan                  # run one scan and exit
  python agent.py --watch --interval 300  # scan every 5 minutes + poll for kicks
  python agent.py --help                  # show all options
 
Requirements:
  pip install requests python-nmap scapy python-dotenv
  On Linux/Mac: run with sudo
  On Windows: run as Administrator
"""
 
import os
import sys
import json
import time
import socket
import platform
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
 
import requests
from dotenv import load_dotenv
 
# ── Optional imports ───────────────────────────────────────────────────────────
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap not found. Install with: pip install python-nmap")
 
try:
    from scapy.all import ARP, Ether, srp, sendp, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  scapy not found. Install with: pip install scapy")
 
# ── Load config ────────────────────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / '.env')
 
BACKEND_URL   = os.getenv("BACKEND_URL",   "https://netguard-production-4f1d.up.railway.app")
AGENT_SECRET  = os.getenv("AGENT_SECRET",  "change_this_shared_secret")
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "")
SCAN_TYPE     = os.getenv("SCAN_TYPE",     "full")
 
# ── FIX 1: USER_ID — use None as sentinel, not 0 ─────────────────────────────
_user_id_raw = os.getenv("USER_ID", "").strip()
USER_ID: Optional[int] = int(_user_id_raw) if _user_id_raw.isdigit() else None
 
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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"
 
 
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""
 
 
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
    54321: {"service": "BO2K",        "risk": "critical"},
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
    if SCAPY_AVAILABLE:
        return _arp_scan_scapy(network_range)
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
    """
    FIX 2: Cross-platform ping sweep.
    Linux/Mac uses -c (count) and -W (timeout seconds).
    Windows uses -n (count) and -w (timeout milliseconds).
    """
    import ipaddress
    import subprocess
    log.info(f"Ping sweeping {network_range}...")
 
    is_windows = platform.system().lower() == "windows"
    network = ipaddress.ip_network(network_range, strict=False)
    hosts = []
 
    for ip in list(network.hosts())[:254]:
        try:
            if is_windows:
                cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
 
            result = subprocess.run(
                cmd,
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
    if not NMAP_AVAILABLE:
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
# KICK — ARP DEAUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════
 
def arp_deauth(target_mac: str, target_ip: str, network_range: str, count: int = 10) -> bool:
    if not SCAPY_AVAILABLE:
        log.error("Scapy is required for ARP deauth. Install with: pip install scapy")
        return False
 
    try:
        import ipaddress
        network = ipaddress.ip_network(network_range, strict=False)
        gateway_ip = str(list(network.hosts())[0])
    except Exception:
        gateway_ip = network_range.rsplit(".", 1)[0] + ".1"
 
    log.info(f"Executing ARP deauth on {target_ip} ({target_mac}), spoofing gateway {gateway_ip}")
 
    try:
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
        )
        log.info(f"Sending {count} ARP deauth packets to {target_ip}...")
        sendp(packet, count=count, inter=0.1, verbose=False)
        log.info(f"ARP deauth complete for {target_ip} ({target_mac})")
        return True
    except PermissionError:
        log.error("ARP deauth requires root/Administrator privileges.")
        return False
    except Exception as e:
        log.error(f"ARP deauth failed: {e}")
        return False
 
 
def resolve_ip_for_mac(target_mac: str, network_range: str) -> Optional[str]:
    """
    FIX 3: Use arp_scan() instead of calling _arp_scan_scapy() directly.
    This ensures the ping fallback is used when Scapy is unavailable.
    """
    log.info(f"Resolving IP for MAC {target_mac}...")
    hosts = arp_scan(network_range)   # ← was: _arp_scan_scapy(network_range)
    for host in hosts:
        if host.get("mac", "").upper() == target_mac.upper():
            return host["ip"]
    return None
 
 
# ══════════════════════════════════════════════════════════════════════════════
# KICK COMMAND POLLING
# ══════════════════════════════════════════════════════════════════════════════
 
def poll_and_execute_kicks(network_range: str):
    # FIX 1 continued: USER_ID is None when not set, not 0
    if USER_ID is None:
        log.warning("USER_ID not set in .env — skipping kick poll")
        return
 
    try:
        url = f"{BACKEND_URL}/api/devices/agent/commands"
        resp = requests.get(
            url,
            params={"agent_secret": AGENT_SECRET, "user_id": USER_ID},
            timeout=10,
        )
        resp.raise_for_status()
        commands = resp.json().get("commands", [])
    except Exception as e:
        log.warning(f"Could not fetch kick commands: {e}")
        return
 
    if not commands:
        return
 
    log.info(f"Found {len(commands)} pending kick command(s)")
 
    for cmd in commands:
        kick_id    = cmd["id"]
        target_mac = cmd["mac_address"]
        target_ip  = cmd.get("target_ip")
 
        log.info(f"Processing kick #{kick_id}: MAC={target_mac}, IP={target_ip or 'unknown'}")
 
        if not target_ip:
            target_ip = resolve_ip_for_mac(target_mac, network_range)
            if not target_ip:
                log.warning(f"Could not find IP for MAC {target_mac} — device may already be offline")
                _report_kick_result(kick_id, "failed", "Could not resolve IP for target MAC")
                continue
 
        success = arp_deauth(target_mac, target_ip, network_range)
        status  = "done" if success else "failed"
        message = "ARP deauth executed successfully" if success else "ARP deauth failed — check permissions"
        _report_kick_result(kick_id, status, message)
 
 
def _report_kick_result(kick_id: int, status: str, message: str):
    try:
        url = f"{BACKEND_URL}/api/devices/agent/kick-result"
        resp = requests.post(url, json={
            "agent_secret": AGENT_SECRET,
            "kick_id": kick_id,
            "status": status,
            "message": message,
        }, timeout=10)
        resp.raise_for_status()
        log.info(f"Kick #{kick_id} reported as '{status}'")
    except Exception as e:
        log.error(f"Failed to report kick result: {e}")
 
 
# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
 
def run_scan(network_range: str, scan_type: str = "full") -> List[Dict]:
    log.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info(f"Starting {scan_type} scan on {network_range}")
    log.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
 
    raw_hosts = arp_scan(network_range)
    if not raw_hosts:
        log.warning("No hosts found. Check network range and permissions.")
        return []
 
    scanned_devices = []
    for host in raw_hosts:
        ip     = host["ip"]
        mac    = host.get("mac", "").upper()
        vendor = lookup_vendor(mac)
 
        log.info(f"Scanning {ip} ({vendor or 'unknown vendor'})...")
 
        ports = port_scan(ip, scan_type)
        open_port_nums = [p["port"] for p in ports]
        hostname = resolve_hostname(ip)
 
        # FIX 4: Use "safe" when no threats found — "unknown" means the device
        # was never evaluated, which is misleading and clutters the dashboard.
        has_critical = any(p["risk_level"] == "critical" for p in ports)
        has_high     = any(p["risk_level"] == "high" for p in ports)
        if has_critical:
            status = "threat"
        elif has_high:
            status = "warning"
        else:
            status = "safe"
 
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
        scanned_devices.append(device)
        log.info(f"  -> {len(ports)} open ports, status: {status}")
 
    log.info(f"Scan complete. {len(scanned_devices)} devices found.")
    return scanned_devices
 
 
# ══════════════════════════════════════════════════════════════════════════════
# BACKEND COMMUNICATION
# ══════════════════════════════════════════════════════════════════════════════
 
def push_to_backend(devices: List[Dict], network_range: str) -> bool:
    # FIX 1 continued: check None explicitly
    if USER_ID is None:
        log.error("USER_ID not set in agent/.env — add USER_ID=1 (your account's user ID)")
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
        log.info(
            f"Backend accepted: scan ID {data.get('id')}, "
            f"risk score {data.get('risk_score')}/100, "
            f"{data.get('threats_found')} threats"
        )
        return True
    except requests.ConnectionError:
        log.error(f"Cannot connect to backend at {BACKEND_URL} — is it running?")
        return False
    except requests.HTTPError as e:
        log.error(f"Backend rejected results: {e.response.status_code} — {e.response.text}")
        return False
    except Exception as e:
        log.error(f"Unexpected error pushing to backend: {e}")
        return False
 
 
def save_local(devices: List[Dict], network_range: str):
    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = {
        "timestamp": datetime.now().isoformat(),
        "network_range": network_range,
        "devices": devices,
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    log.info(f"Results saved locally: {filename}")
 
 
# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
 
def main():
    parser = argparse.ArgumentParser(
        description="NetGuard Local Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --scan
  python agent.py --scan --range 192.168.0.0/24 --type quick
  python agent.py --watch --interval 300
  python agent.py --scan --local-only
        """
    )
 
    parser.add_argument("--scan",       action="store_true", help="Run a single scan and exit")
    parser.add_argument("--watch",      action="store_true", help="Run continuously on interval")
    parser.add_argument("--interval",   type=int, default=300, help="Seconds between scans (default: 300)")
    parser.add_argument("--range",      type=str, default="", help="Network range (e.g. 192.168.1.0/24)")
    parser.add_argument("--type",       choices=["quick", "full"], default="full")
    parser.add_argument("--local-only", action="store_true", help="Save locally, don't push to backend")
    parser.add_argument("--check-env",  action="store_true", help="Check environment and exit")
 
    args = parser.parse_args()
 
    if args.check_env:
        print("\n=== NetGuard Agent — Environment Check ===\n")
        print(f"Backend URL:    {BACKEND_URL}")
        print(f"User ID:        {USER_ID if USER_ID is not None else 'NOT SET ⚠️'}")
        print(f"Agent Secret:   {'Set ✓' if AGENT_SECRET != 'change_this_shared_secret' else 'Using default ⚠️'}")
        print(f"Nmap:           {'Available ✓' if NMAP_AVAILABLE else 'Not installed ⚠️'}")
        print(f"Scapy:          {'Available ✓' if SCAPY_AVAILABLE else 'Not installed ⚠️'}")
        print(f"Platform:       {platform.system()}")
        print(f"Detected LAN:   {get_local_network()}")
        return
 
    network   = args.range or NETWORK_RANGE or get_local_network()
    scan_type = args.type or SCAN_TYPE
 
    print(f"""
╔══════════════════════════════════════════╗
║         NetGuard Local Agent v1.1        ║
╚══════════════════════════════════════════╝
  Backend:  {BACKEND_URL}
  Network:  {network}
  Scan:     {scan_type}
  Mode:     {"watch (every " + str(args.interval) + "s)" if args.watch else "single scan"}
  Kick:     {"enabled (polling backend)" if args.watch and not args.local_only else "disabled"}
""")
 
    def do_cycle():
        """One full cycle: scan + push + check for kicks."""
        found = run_scan(network, scan_type)
        if found:
            if args.local_only:
                save_local(found, network)
            else:
                success = push_to_backend(found, network)
                if not success:
                    save_local(found, network)
        # FIX 5: only poll kicks when NOT in local-only mode
        if not args.local_only:
            poll_and_execute_kicks(network)
 
    if args.scan:
        do_cycle()   # reuse do_cycle to avoid duplicated logic
        return
 
    if args.watch:
        log.info(f"Watch mode — scanning every {args.interval}s. Press Ctrl+C to stop.")
        while True:
            do_cycle()
            log.info(f"Next cycle in {args.interval}s...")
            time.sleep(args.interval)
        return
 
    parser.print_help()
 
 
if __name__ == "__main__":
    main()
 