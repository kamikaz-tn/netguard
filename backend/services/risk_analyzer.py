"""
netguard/backend/services/risk_analyzer.py
────────────────────────────────────────────
Converts raw scan results into structured findings with:
  - Severity classification
  - Human-readable descriptions
  - Remediation advice
  - Overall risk score
"""

from typing import List
from models.schemas import DeviceInfo, ScanFindingOut
from services.scanner import PORT_RISK_DB, calculate_risk_score
from core.config import settings


REMEDIATION_DB = {
    "backdoor_port": (
        "Immediately isolate the device from the network. "
        "Run a full malware scan on that machine. "
        "Check for unauthorized processes: `netstat -tulnp | grep {port}`. "
        "If you cannot explain why this port is open, treat the machine as compromised."
    ),
    "telnet": (
        "Disable Telnet on your router: log into the router admin panel "
        "(usually 192.168.1.1), find 'Remote Management' or 'Telnet' settings and disable it. "
        "Use SSH instead if remote access is needed."
    ),
    "smb": (
        "If SMB is not needed, disable it: on Windows run `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` "
        "in an admin PowerShell. Ensure Windows is up to date to patch EternalBlue (MS17-010)."
    ),
    "rdp": (
        "Disable RDP if not needed (System Properties → Remote → uncheck 'Allow Remote Connections'). "
        "If needed, enable Network Level Authentication, use a non-standard port, and use a VPN."
    ),
    "ftp": (
        "Replace FTP with SFTP or FTPS. Disable FTP on the device. "
        "If using a NAS, check its admin settings for FTP server options."
    ),
    "unknown_device": (
        "Investigate this device: check your router's DHCP client list to see when it connected. "
        "If you don't recognize it, use the Kick option to deauthenticate it, "
        "then change your Wi-Fi password immediately."
    ),
    "rpc": (
        "RPC should not be reachable across the network. "
        "Enable Windows Firewall and ensure it blocks inbound connections on port 135. "
        "Apply all Windows security updates."
    ),
    "vnc": (
        "Set a strong VNC password. Restrict VNC access to localhost only "
        "and tunnel it through SSH if remote access is needed. "
        "Disable VNC if not actively used."
    ),
    "open_port_generic": (
        "Verify this port is intentionally open. If you don't recognize the service, "
        "find the process using it: `lsof -i :{port}` (Linux/Mac) or "
        "`netstat -ano | findstr :{port}` (Windows). Disable the service if unneeded."
    ),
}


def analyze_devices(devices: List[DeviceInfo]) -> List[ScanFindingOut]:
    """
    Run all security checks on scan results.
    Returns a list of findings sorted by severity.
    """
    findings: List[ScanFindingOut] = []

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for device in devices:
        # ── Check 1: Unknown device ──────────────────────────────────────────
        if device.status == "unknown":
            findings.append(ScanFindingOut(
                host_ip=device.ip,
                host_mac=device.mac or None,
                port=None,
                service=None,
                severity="high",
                category="unknown_device",
                description=(
                    f"Unrecognized device found at {device.ip} "
                    f"(MAC: {device.mac or 'unknown'}, Vendor: {device.vendor}). "
                    "This device has not been marked as trusted."
                ),
                remediation=REMEDIATION_DB["unknown_device"],
            ))

        # ── Check 2: Per-port analysis ────────────────────────────────────────
        for port in device.ports:
            port_info = PORT_RISK_DB.get(port.port, {})
            risk = port_info.get("risk", "low")
            reason = port_info.get("reason", "")

            if risk not in ("critical", "high", "medium"):
                continue   # skip low-risk ports to keep findings actionable

            # Determine category
            if port.port in settings.suspicious_ports:
                category = "backdoor_port"
                remediation = REMEDIATION_DB["backdoor_port"].replace("{port}", str(port.port))
            elif port.port == 23:
                category = "telnet"
                remediation = REMEDIATION_DB["telnet"]
            elif port.port == 445:
                category = "smb"
                remediation = REMEDIATION_DB["smb"]
            elif port.port == 3389:
                category = "rdp"
                remediation = REMEDIATION_DB["rdp"]
            elif port.port == 21:
                category = "ftp"
                remediation = REMEDIATION_DB["ftp"]
            elif port.port == 135:
                category = "rpc"
                remediation = REMEDIATION_DB["rpc"]
            elif port.port == 5900:
                category = "vnc"
                remediation = REMEDIATION_DB["vnc"]
            else:
                category = "open_port"
                remediation = REMEDIATION_DB["open_port_generic"].replace("{port}", str(port.port))

            version_str = f" (version: {port.version})" if port.version else ""

            findings.append(ScanFindingOut(
                host_ip=device.ip,
                host_mac=device.mac or None,
                port=port.port,
                service=port.service,
                severity=risk,
                category=category,
                description=(
                    f"Port {port.port}/{port.protocol} ({port.service}{version_str}) "
                    f"is open on {device.ip}. {reason}"
                ),
                remediation=remediation,
            ))

    # Sort by severity
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    return findings


def compute_network_risk_score(devices: List[DeviceInfo], findings: List[ScanFindingOut]) -> float:
    """
    Compute a single 0-100 network risk score from findings.
    """
    score = 0.0
    severity_weights = {
        "critical": 25,
        "high": 12,
        "medium": 5,
        "low": 1,
        "info": 0,
    }

    for finding in findings:
        weight = severity_weights.get(finding.severity, 0)
        score += weight

    return round(min(score, 100), 1)
