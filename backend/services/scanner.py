"""
netguard/backend/services/scanner.py
──────────────────────────────────────
Network scanning engine.

Responsibilities:
  1. ARP scan — discover all live hosts + MAC addresses (uses Scapy)
  2. Port scan — detect open ports + service banners (uses python-nmap)
  3. Risk analysis — flag suspicious/backdoor ports, calculate risk score
  4. OS fingerprinting — best-effort OS guess from nmap

NOTE: This service requires the app to run with elevated privileges (sudo)
for ARP scanning, OR it can receive data from the local agent instead.
"""

import asyncio
import socket
from typing import List, Dict, Any, Optional
from datetime import datetime

from models.schemas import DeviceInfo, PortInfo
from core.config import settings

# ── Try importing network libs ────────────────────────────────────────────────
# These are optional — the app works in "agent mode" without them.
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── Known vendor prefixes (MAC OUI lookup) ────────────────────────────────────
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

# ── Service risk database ─────────────────────────────────────────────────────
PORT_RISK_DB: Dict[int, Dict[str, str]] = {
    21:    {"service": "FTP", "risk": "high", "reason": "Unencrypted file transfer — credentials sent in plain text"},
    22:    {"service": "SSH", "risk": "medium", "reason": "Secure shell — safe if properly configured, risk if exposed to internet"},
    23:    {"service": "Telnet", "risk": "critical", "reason": "Unencrypted remote shell — all traffic including passwords is plain text"},
    25:    {"service": "SMTP", "risk": "medium", "reason": "Mail server — should not be open on home networks"},
    80:    {"service": "HTTP", "risk": "medium", "reason": "Unencrypted web server"},
    135:   {"service": "RPC", "risk": "high", "reason": "Windows RPC — major attack surface for lateral movement"},
    139:   {"service": "NetBIOS", "risk": "high", "reason": "Legacy Windows networking — often exploitable"},
    443:   {"service": "HTTPS", "risk": "low", "reason": "Encrypted web server — generally safe"},
    445:   {"service": "SMB", "risk": "critical", "reason": "Windows file sharing — EternalBlue ransomware vector (WannaCry)"},
    1234:  {"service": "Unknown", "risk": "critical", "reason": "Common RAT (Remote Access Trojan) port"},
    3306:  {"service": "MySQL", "risk": "high", "reason": "Database exposed on network — should never be public"},
    3389:  {"service": "RDP", "risk": "critical", "reason": "Remote Desktop — primary target for brute force and ransomware"},
    4444:  {"service": "Metasploit", "risk": "critical", "reason": "Default Metasploit Framework listener — strong indicator of compromise"},
    5555:  {"service": "ADB/Cerberus", "risk": "critical", "reason": "Android Debug Bridge or Cerberus RAT"},
    5900:  {"service": "VNC", "risk": "high", "reason": "Remote desktop — often runs without proper auth"},
    6666:  {"service": "IRC/Malware", "risk": "critical", "reason": "Associated with IRC botnets and malware C2"},
    8080:  {"service": "HTTP-Alt", "risk": "medium", "reason": "Alternate HTTP — could be a proxy or dev server"},
    8888:  {"service": "HTTP-Alt", "risk": "medium", "reason": "Common C2 or dev server port"},
    9999:  {"service": "Unknown", "risk": "high", "reason": "Common C2 communication port"},
    12345: {"service": "NetBus", "risk": "critical", "reason": "NetBus RAT — classic backdoor trojan"},
    31337: {"service": "Back Orifice", "risk": "critical", "reason": "Back Orifice RAT — 'elite' hacker port, likely malicious"},
    54321: {"service": "BO2K", "risk": "critical", "reason": "Back Orifice 2000 — Windows RAT"},
}


def lookup_vendor(mac: str) -> str:
    """Best-effort vendor lookup from MAC OUI prefix."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    return VENDOR_MAP.get(prefix, "Unknown Vendor")


def get_port_risk(port: int) -> Dict[str, str]:
    """Return risk info for a given port number."""
    return PORT_RISK_DB.get(port, {
        "service": "Unknown",
        "risk": "low",
        "reason": "No known risk associated with this port"
    })


def calculate_risk_score(devices: List[DeviceInfo]) -> float:
    """
    Calculate a 0-100 network risk score.
    Weights:
      - Critical port open: +20 per port (max 60)
      - High risk port: +10 per port (max 30)
      - Unknown device: +5 per device (max 15)
      - Backdoor port: +25 (max once)
    """
    score = 0.0
    backdoor_found = False

    for device in devices:
        if device.status == "unknown":
            score = min(score + 5, score + 15)

        for port in device.ports:
            if port.risk_level == "critical":
                score += 20
                if port.port in settings.suspicious_ports and not backdoor_found:
                    score += 25
                    backdoor_found = True
            elif port.risk_level == "high":
                score += 10
            elif port.risk_level == "medium":
                score += 3

    return round(min(score, 100), 1)


# ── ARP Discovery ─────────────────────────────────────────────────────────────
async def arp_scan(network_range: str) -> List[Dict[str, str]]:
    """
    Discover live hosts via ARP broadcast.
    Returns list of {ip, mac} dicts.

    Requires Scapy + root/sudo. Falls back to ping sweep if unavailable.
    """
    if not SCAPY_AVAILABLE:
        return await _ping_sweep_fallback(network_range)

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _arp_scan_sync, network_range)


def _arp_scan_sync(network_range: str) -> List[Dict[str, str]]:
    """Synchronous ARP scan — runs in thread pool to avoid blocking."""
    try:
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered, _ = srp(packet, timeout=3, verbose=False)

        hosts = []
        for sent, received in answered:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper()
            })
        return hosts
    except Exception as e:
        raise RuntimeError(f"ARP scan failed: {e}. Try running with sudo.")


async def _ping_sweep_fallback(network_range: str) -> List[Dict[str, str]]:
    """
    Fallback when Scapy is unavailable — uses system ping.
    Less reliable but works without root.
    """
    import ipaddress
    network = ipaddress.ip_network(network_range, strict=False)
    hosts = []

    async def ping_host(ip: str):
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", str(ip),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode == 0:
            hosts.append({"ip": str(ip), "mac": ""})

    # Limit to /24 for speed
    ips = list(network.hosts())[:254]
    tasks = [ping_host(str(ip)) for ip in ips]
    await asyncio.gather(*tasks)
    return hosts


# ── Port Scanning ─────────────────────────────────────────────────────────────
async def port_scan(ip: str, scan_type: str = "full") -> List[PortInfo]:
    """
    Scan open ports on a single host using nmap.
    scan_type:
      "quick" — top 100 ports, no version detection
      "full"  — top 1000 ports + version detection
    """
    if not NMAP_AVAILABLE:
        return []

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _port_scan_sync, ip, scan_type)


def _port_scan_sync(ip: str, scan_type: str) -> List[PortInfo]:
    """Synchronous nmap scan — runs in thread pool."""
    nm = nmap.PortScanner()

    if scan_type == "quick":
        args = "-F --open"                   # fast scan, top 100 ports
    else:
        args = "-sV --open -T4"              # version detection, top 1000 ports

    try:
        nm.scan(hosts=ip, arguments=args)
    except Exception as e:
        raise RuntimeError(f"Nmap scan failed for {ip}: {e}")

    ports: List[PortInfo] = []

    if ip not in nm.all_hosts():
        return ports

    host_data = nm[ip]

    for proto in ["tcp", "udp"]:
        if proto not in host_data:
            continue
        for port_num, port_data in host_data[proto].items():
            if port_data["state"] != "open":
                continue

            risk_info = get_port_risk(port_num)
            service_name = port_data.get("name", risk_info["service"])
            version = f"{port_data.get('product','')} {port_data.get('version','')}".strip()

            ports.append(PortInfo(
                port=port_num,
                protocol=proto,
                state="open",
                service=service_name,
                version=version,
                is_suspicious=port_num in settings.suspicious_ports,
                is_critical=port_num in settings.critical_ports,
                risk_level=risk_info["risk"],
            ))

    return sorted(ports, key=lambda p: p.port)


# ── OS Fingerprint ────────────────────────────────────────────────────────────
def guess_os(mac: str, open_ports: List[int]) -> str:
    """
    Heuristic OS guess based on MAC vendor + open ports.
    A rough approximation — nmap OS detection needs root.
    """
    vendor = lookup_vendor(mac).lower()

    if "apple" in vendor:
        return "macOS / iOS"
    if "samsung" in vendor:
        return "Android / Tizen"
    if "raspberry" in vendor:
        return "Linux (Raspberry Pi OS)"
    if "tp-link" in vendor or "netgear" in vendor or "asus" in vendor:
        return "Router / Embedded Linux"

    # Guess from ports
    if 3389 in open_ports:
        return "Windows (RDP detected)"
    if 445 in open_ports and 135 in open_ports:
        return "Windows"
    if 22 in open_ports and 80 not in open_ports:
        return "Linux / Unix"

    return "Unknown"


# ── Full Scan Pipeline ────────────────────────────────────────────────────────
async def run_full_scan(
    network_range: str,
    scan_type: str = "full",
    trusted_macs: Optional[List[str]] = None,
) -> List[DeviceInfo]:
    """
    Orchestrates the full scan:
    1. ARP sweep to find live hosts
    2. Port scan each host in parallel
    3. Enrich with vendor, OS guess, risk level
    4. Mark known/trusted vs unknown devices
    """
    trusted_macs = [m.upper() for m in (trusted_macs or [])]

    # Step 1 — discover hosts
    raw_hosts = await arp_scan(network_range)

    # Step 2 — port scan all hosts concurrently (limit concurrency)
    semaphore = asyncio.Semaphore(5)   # max 5 concurrent nmap processes

    async def scan_host(host: Dict[str, str]) -> DeviceInfo:
        async with semaphore:
            ip = host["ip"]
            mac = host.get("mac", "").upper()
            vendor = lookup_vendor(mac)

            ports = await port_scan(ip, scan_type)
            open_port_nums = [p.port for p in ports]

            # Determine trust status
            if mac in trusted_macs:
                status = "trusted"
            elif any(p.risk_level == "critical" for p in ports):
                status = "threat"
            elif not mac:
                status = "unknown"
            else:
                status = "unknown"

            # Attempt hostname resolution
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""

            return DeviceInfo(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                os_guess=guess_os(mac, open_port_nums),
                status=status,
                ports=ports,
                risk_score=0.0,   # per-device score calculated after
            )

    devices = await asyncio.gather(*[scan_host(h) for h in raw_hosts])
    return list(devices)
