#!/usr/bin/env python3
"""
netguard/agent/agent.py
─────────────────────────
NetGuard Local Agent v1.2

Improvements in this version:
  - ARP scan: increased timeout, multiple retries, inter-packet delay
  - Added ping sweep fallback that runs IN PARALLEL with ARP for better coverage
  - Rich device fingerprinting: 200+ MAC OUI prefixes, port-based OS detection,
    hostname pattern matching, Nmap OS hints → identifies iPhones, Androids,
    Smart TVs, laptops, routers, printers, gaming consoles, etc.
  - Device type + icon returned to backend for dashboard display

Usage:
  python agent.py --scan                  # run one scan and exit
  python agent.py --watch --interval 300  # continuous watch mode
  python agent.py --check-env             # verify setup
  python agent.py --help

Requirements:
  pip install requests python-nmap scapy python-dotenv
  Windows: run as Administrator
  Linux/Mac: run with sudo
"""

import os
import sys
import json
import time
import socket
import platform
import argparse
import logging
import ipaddress
import subprocess
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

# ── Optional imports ───────────────────────────────────────────────────────────
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("WARNING: python-nmap not found. Port scanning disabled.")

try:
    from scapy.all import ARP, Ether, srp, sendp, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy not found. ARP scanning disabled, using ping fallback.")

# ── Load config ────────────────────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / '.env')

BACKEND_URL   = os.getenv("BACKEND_URL",   "https://netguard-production-4f1d.up.railway.app")
AGENT_TOKEN   = os.getenv("AGENT_TOKEN",   "") or os.getenv("AGENT_SECRET", "")  # AGENT_SECRET fallback for old .env files
if not AGENT_TOKEN:
    print("ERROR: AGENT_TOKEN env var is required. Generate one from the dashboard (Agent Setup page) and put it in agent/.env.")
    sys.exit(1)
AGENT_HEADERS = {"X-Agent-Token": AGENT_TOKEN}
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "")
SCAN_TYPE     = os.getenv("SCAN_TYPE",     "full")

# USER_ID is no longer required — the backend derives it from the agent token.
# Kept for backward-compat with older code paths that still reference it.
_user_id_raw = os.getenv("USER_ID", "").strip()
USER_ID: Optional[int] = int(_user_id_raw) if _user_id_raw.isdigit() else None

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("netguard-agent.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("netguard-agent")


# ==============================================================================
# MAC OUI DATABASE — 200+ prefixes for device identification
# ==============================================================================

# Format: "XX:XX:XX" -> (vendor, device_type, icon)
# Device types: router, phone, laptop, desktop, tablet, tv, printer,
#               console, iot, camera, nas, vm, unknown
OUI_DB: Dict[str, Tuple[str, str, str]] = {
    # Apple
    "00:1A:2B": ("Apple",          "laptop",  "laptop"),
    "00:03:93": ("Apple",          "laptop",  "laptop"),
    "00:0A:27": ("Apple",          "laptop",  "laptop"),
    "00:0A:95": ("Apple",          "laptop",  "laptop"),
    "00:11:24": ("Apple",          "laptop",  "laptop"),
    "00:14:51": ("Apple",          "laptop",  "laptop"),
    "00:16:CB": ("Apple",          "laptop",  "laptop"),
    "00:17:F2": ("Apple",          "laptop",  "laptop"),
    "00:19:E3": ("Apple",          "laptop",  "laptop"),
    "00:1B:63": ("Apple",          "laptop",  "laptop"),
    "00:1C:B3": ("Apple",          "laptop",  "laptop"),
    "00:1D:4F": ("Apple",          "laptop",  "laptop"),
    "00:1E:52": ("Apple",          "laptop",  "laptop"),
    "00:1E:C2": ("Apple",          "laptop",  "laptop"),
    "00:1F:5B": ("Apple",          "laptop",  "laptop"),
    "00:1F:F3": ("Apple",          "laptop",  "laptop"),
    "00:21:E9": ("Apple",          "laptop",  "laptop"),
    "00:22:41": ("Apple",          "laptop",  "laptop"),
    "00:23:12": ("Apple",          "laptop",  "laptop"),
    "00:23:32": ("Apple",          "laptop",  "laptop"),
    "00:23:6C": ("Apple",          "laptop",  "laptop"),
    "00:23:DF": ("Apple",          "laptop",  "laptop"),
    "00:24:36": ("Apple",          "laptop",  "laptop"),
    "00:25:00": ("Apple",          "laptop",  "laptop"),
    "00:25:4B": ("Apple",          "laptop",  "laptop"),
    "00:25:BC": ("Apple",          "laptop",  "laptop"),
    "00:26:08": ("Apple",          "laptop",  "laptop"),
    "00:26:4A": ("Apple",          "laptop",  "laptop"),
    "00:26:B0": ("Apple",          "laptop",  "laptop"),
    "00:26:BB": ("Apple",          "laptop",  "laptop"),
    "04:0C:CE": ("Apple iPhone",   "phone",   "phone"),
    "04:15:52": ("Apple iPhone",   "phone",   "phone"),
    "04:26:65": ("Apple",          "laptop",  "laptop"),
    "04:48:9A": ("Apple iPhone",   "phone",   "phone"),
    "04:52:F3": ("Apple iPhone",   "phone",   "phone"),
    "04:54:53": ("Apple iPhone",   "phone",   "phone"),
    "04:69:F8": ("Apple iPhone",   "phone",   "phone"),
    "04:D3:CF": ("Apple iPhone",   "phone",   "phone"),
    "04:E5:36": ("Apple iPhone",   "phone",   "phone"),
    "04:F1:3E": ("Apple iPhone",   "phone",   "phone"),
    "08:00:07": ("Apple",          "laptop",  "laptop"),
    "08:6D:41": ("Apple iPhone",   "phone",   "phone"),
    "0C:74:C2": ("Apple iPhone",   "phone",   "phone"),
    "10:40:F3": ("Apple iPhone",   "phone",   "phone"),
    "18:E7:F4": ("Apple iPhone",   "phone",   "phone"),
    "1C:91:48": ("Apple iPhone",   "phone",   "phone"),
    "20:78:F0": ("Apple iPhone",   "phone",   "phone"),
    "24:A2:E1": ("Apple iPhone",   "phone",   "phone"),
    "28:6A:BA": ("Apple iPhone",   "phone",   "phone"),
    "28:E0:2C": ("Apple iPhone",   "phone",   "phone"),
    "2C:1F:23": ("Apple iPhone",   "phone",   "phone"),
    "34:15:9E": ("Apple iPhone",   "phone",   "phone"),
    "38:0F:4A": ("Apple iPhone",   "phone",   "phone"),
    "3C:15:C2": ("Apple iPhone",   "phone",   "phone"),
    "40:33:1A": ("Apple iPhone",   "phone",   "phone"),
    "44:00:10": ("Apple iPhone",   "phone",   "phone"),
    "44:2A:60": ("Apple iPhone",   "phone",   "phone"),
    "48:43:7C": ("Apple iPhone",   "phone",   "phone"),
    "4C:57:CA": ("Apple iPhone",   "phone",   "phone"),
    "50:BC:96": ("Apple iPhone",   "phone",   "phone"),
    "54:72:4F": ("Apple iPhone",   "phone",   "phone"),
    "58:40:4E": ("Apple iPhone",   "phone",   "phone"),
    "5C:96:9D": ("Apple iPhone",   "phone",   "phone"),
    "60:03:08": ("Apple iPhone",   "phone",   "phone"),
    "60:69:44": ("Apple iPhone",   "phone",   "phone"),
    "60:F8:1D": ("Apple iPhone",   "phone",   "phone"),
    "64:20:0C": ("Apple iPhone",   "phone",   "phone"),
    "64:A3:CB": ("Apple iPhone",   "phone",   "phone"),
    "68:96:7B": ("Apple iPhone",   "phone",   "phone"),
    "6C:40:08": ("Apple iPhone",   "phone",   "phone"),
    "6C:70:9F": ("Apple iPhone",   "phone",   "phone"),
    "70:56:81": ("Apple iPhone",   "phone",   "phone"),
    "70:EC:E4": ("Apple iPhone",   "phone",   "phone"),
    "74:1B:B2": ("Apple iPhone",   "phone",   "phone"),
    "78:4F:43": ("Apple iPhone",   "phone",   "phone"),
    "7C:11:BE": ("Apple iPhone",   "phone",   "phone"),
    "7C:6D:62": ("Apple iPhone",   "phone",   "phone"),
    "80:E6:50": ("Apple iPhone",   "phone",   "phone"),
    "84:38:35": ("Apple iPhone",   "phone",   "phone"),
    "84:78:8B": ("Apple iPhone",   "phone",   "phone"),
    "88:19:08": ("Apple iPhone",   "phone",   "phone"),
    "8C:85:90": ("Apple iPhone",   "phone",   "phone"),
    "90:27:E4": ("Apple iPhone",   "phone",   "phone"),
    "90:3C:92": ("Apple iPhone",   "phone",   "phone"),
    "98:01:A7": ("Apple iPhone",   "phone",   "phone"),
    "A4:83:E7": ("Apple iPhone",   "phone",   "phone"),
    "A4:B1:97": ("Apple iPhone",   "phone",   "phone"),
    "A4:D9:31": ("Apple iPhone",   "phone",   "phone"),
    "A8:20:66": ("Apple iPhone",   "phone",   "phone"),
    "A8:5C:2C": ("Apple iPhone",   "phone",   "phone"),
    "A8:86:DD": ("Apple iPhone",   "phone",   "phone"),
    "AC:1F:74": ("Apple iPhone",   "phone",   "phone"),
    "AC:BC:32": ("Apple iPhone",   "phone",   "phone"),
    "B0:34:95": ("Apple iPhone",   "phone",   "phone"),
    "B4:18:D1": ("Apple iPhone",   "phone",   "phone"),
    "B8:09:8A": ("Apple iPhone",   "phone",   "phone"),
    "B8:53:AC": ("Apple iPhone",   "phone",   "phone"),
    "BC:3B:AF": ("Apple iPhone",   "phone",   "phone"),
    "C0:D0:12": ("Apple iPhone",   "phone",   "phone"),
    "C4:B3:01": ("Apple iPhone",   "phone",   "phone"),
    "C8:2A:14": ("Apple iPhone",   "phone",   "phone"),
    "C8:D0:83": ("Apple iPhone",   "phone",   "phone"),
    "CC:08:8D": ("Apple iPhone",   "phone",   "phone"),
    "D0:23:DB": ("Apple iPhone",   "phone",   "phone"),
    "D4:61:9D": ("Apple iPhone",   "phone",   "phone"),
    "D4:90:9C": ("Apple iPhone",   "phone",   "phone"),
    "D8:BB:2C": ("Apple iPhone",   "phone",   "phone"),
    "DC:2B:2A": ("Apple iPhone",   "phone",   "phone"),
    "E0:5F:45": ("Apple iPhone",   "phone",   "phone"),
    "E4:25:E7": ("Apple iPhone",   "phone",   "phone"),
    "E8:04:0B": ("Apple iPhone",   "phone",   "phone"),
    "EC:35:86": ("Apple iPhone",   "phone",   "phone"),
    "F0:B4:79": ("Apple iPhone",   "phone",   "phone"),
    "F0:DB:F8": ("Apple iPhone",   "phone",   "phone"),
    "F4:F1:5A": ("Apple iPhone",   "phone",   "phone"),
    "F8:27:93": ("Apple iPhone",   "phone",   "phone"),
    "FC:25:3F": ("Apple iPhone",   "phone",   "phone"),

    # Samsung
    "00:07:AB": ("Samsung",        "phone",   "phone"),
    "00:12:47": ("Samsung",        "phone",   "phone"),
    "00:15:99": ("Samsung",        "phone",   "phone"),
    "00:17:C9": ("Samsung",        "phone",   "phone"),
    "00:1A:8A": ("Samsung",        "phone",   "phone"),
    "00:1B:98": ("Samsung",        "phone",   "phone"),
    "00:1C:43": ("Samsung",        "phone",   "phone"),
    "00:1D:25": ("Samsung",        "phone",   "phone"),
    "00:1E:7D": ("Samsung",        "phone",   "phone"),
    "00:1F:CC": ("Samsung",        "phone",   "phone"),
    "00:21:19": ("Samsung",        "phone",   "phone"),
    "00:23:39": ("Samsung",        "phone",   "phone"),
    "00:24:54": ("Samsung",        "phone",   "phone"),
    "00:26:37": ("Samsung",        "phone",   "phone"),
    "2C:4D:54": ("Samsung",        "phone",   "phone"),
    "34:23:BA": ("Samsung Galaxy", "phone",   "phone"),
    "38:01:46": ("Samsung Galaxy", "phone",   "phone"),
    "3C:5A:37": ("Samsung Galaxy", "phone",   "phone"),
    "40:0E:85": ("Samsung Galaxy", "phone",   "phone"),
    "50:01:BB": ("Samsung Galaxy", "phone",   "phone"),
    "54:88:0E": ("Samsung Galaxy", "phone",   "phone"),
    "58:C3:8B": ("Samsung Galaxy", "phone",   "phone"),
    "5C:3C:27": ("Samsung Smart TV","tv",     "tv"),
    "60:6B:BD": ("Samsung Smart TV","tv",     "tv"),
    "78:1F:DB": ("Samsung Galaxy", "phone",   "phone"),
    "84:25:DB": ("Samsung Galaxy", "phone",   "phone"),
    "90:18:7C": ("Samsung Galaxy", "phone",   "phone"),
    "A0:0B:BA": ("Samsung Galaxy", "phone",   "phone"),
    "B0:72:BF": ("Samsung Galaxy", "phone",   "phone"),
    "C0:BD:D1": ("Samsung Galaxy", "phone",   "phone"),
    "CC:07:AB": ("Samsung Galaxy", "phone",   "phone"),
    "D0:17:6A": ("Samsung Smart TV","tv",     "tv"),
    "D0:22:BE": ("Samsung Galaxy", "phone",   "phone"),
    "F4:42:8F": ("Samsung Galaxy", "phone",   "phone"),

    # Huawei
    "00:18:82": ("Huawei",         "phone",   "phone"),
    "00:1E:10": ("Huawei",         "phone",   "phone"),
    "00:25:9E": ("Huawei",         "router",  "router"),
    "04:02:1F": ("Huawei",         "phone",   "phone"),
    "04:F9:38": ("Huawei",         "phone",   "phone"),
    "08:19:A6": ("Huawei",         "phone",   "phone"),
    "10:47:80": ("Huawei",         "phone",   "phone"),
    "20:08:ED": ("Huawei",         "phone",   "phone"),
    "28:31:52": ("Huawei",         "phone",   "phone"),
    "2C:AB:00": ("Huawei",         "phone",   "phone"),
    "34:6B:D3": ("Huawei",         "phone",   "phone"),
    "38:37:8B": ("Huawei",         "router",  "router"),
    "40:4D:8E": ("Huawei",         "phone",   "phone"),
    "44:6E:E5": ("Huawei",         "phone",   "phone"),
    "48:00:31": ("Huawei",         "phone",   "phone"),
    "4C:8B:EF": ("Huawei",         "phone",   "phone"),
    "54:25:EA": ("Huawei",         "phone",   "phone"),
    "5C:C3:07": ("Huawei",         "phone",   "phone"),
    "68:A0:F6": ("Huawei",         "phone",   "phone"),
    "6C:8D:C1": ("Huawei",         "phone",   "phone"),
    "70:72:3C": ("Huawei",         "phone",   "phone"),
    "78:1D:BA": ("Huawei",         "phone",   "phone"),
    "80:38:BC": ("Huawei",         "phone",   "phone"),
    "84:BE:52": ("Huawei",         "phone",   "phone"),
    "90:67:1C": ("Huawei",         "phone",   "phone"),
    "A0:4C:5B": ("Huawei",         "phone",   "phone"),
    "AC:E2:15": ("Huawei",         "phone",   "phone"),
    "B0:E5:ED": ("Huawei",         "router",  "router"),
    "C8:14:79": ("Huawei",         "phone",   "phone"),
    "CC:A2:23": ("Huawei",         "phone",   "phone"),
    "D4:6A:A8": ("Huawei",         "phone",   "phone"),
    "E8:08:8B": ("Huawei",         "phone",   "phone"),
    "F4:4C:7F": ("Huawei",         "phone",   "phone"),
    "F8:4E:73": ("Huawei",         "phone",   "phone"),
    "FC:3F:7C": ("Huawei",         "phone",   "phone"),

    # Xiaomi
    "00:9E:C8": ("Xiaomi",         "phone",   "phone"),
    "04:CF:8C": ("Xiaomi",         "phone",   "phone"),
    "10:2A:B3": ("Xiaomi",         "phone",   "phone"),
    "14:F6:5A": ("Xiaomi",         "phone",   "phone"),
    "18:59:36": ("Xiaomi",         "phone",   "phone"),
    "20:82:C0": ("Xiaomi",         "phone",   "phone"),
    "28:E3:1F": ("Xiaomi",         "phone",   "phone"),
    "34:CE:00": ("Xiaomi",         "phone",   "phone"),
    "38:A4:ED": ("Xiaomi",         "phone",   "phone"),
    "3C:BD:D8": ("Xiaomi",         "phone",   "phone"),
    "4C:49:E3": ("Xiaomi",         "phone",   "phone"),
    "50:64:2B": ("Xiaomi",         "phone",   "phone"),
    "58:44:98": ("Xiaomi",         "phone",   "phone"),
    "64:09:80": ("Xiaomi",         "phone",   "phone"),
    "64:B4:73": ("Xiaomi",         "phone",   "phone"),
    "78:11:DC": ("Xiaomi",         "phone",   "phone"),
    "8C:BE:BE": ("Xiaomi",         "phone",   "phone"),
    "98:FA:9B": ("Xiaomi",         "phone",   "phone"),
    "A4:50:46": ("Xiaomi",         "phone",   "phone"),
    "AC:C1:EE": ("Xiaomi",         "phone",   "phone"),
    "B0:E2:35": ("Xiaomi",         "phone",   "phone"),
    "C4:0B:CB": ("Xiaomi",         "phone",   "phone"),
    "D4:97:0B": ("Xiaomi",         "phone",   "phone"),
    "F0:B4:29": ("Xiaomi",         "phone",   "phone"),
    "FC:64:BA": ("Xiaomi",         "phone",   "phone"),

    # Routers — TP-Link
    "00:0A:EB": ("TP-Link",        "router",  "router"),
    "00:1D:0F": ("TP-Link",        "router",  "router"),
    "00:27:19": ("TP-Link",        "router",  "router"),
    "04:8D:38": ("TP-Link",        "router",  "router"),
    "10:FE:ED": ("TP-Link",        "router",  "router"),
    "14:CC:20": ("TP-Link",        "router",  "router"),
    "18:A6:F7": ("TP-Link",        "router",  "router"),
    "1C:3B:F3": ("TP-Link",        "router",  "router"),
    "2C:D0:5A": ("TP-Link",        "router",  "router"),
    "30:B5:C2": ("TP-Link",        "router",  "router"),
    "34:E8:94": ("TP-Link",        "router",  "router"),
    "3C:84:6A": ("TP-Link",        "router",  "router"),
    "40:8D:5C": ("TP-Link",        "router",  "router"),
    "44:94:FC": ("TP-Link",        "router",  "router"),
    "50:C7:BF": ("TP-Link",        "router",  "router"),
    "54:AF:97": ("TP-Link",        "router",  "router"),
    "5C:89:9A": ("TP-Link",        "router",  "router"),
    "60:32:B1": ("TP-Link",        "router",  "router"),
    "64:66:B3": ("TP-Link",        "router",  "router"),
    "6C:72:20": ("TP-Link",        "router",  "router"),
    "70:4F:57": ("TP-Link",        "router",  "router"),
    "74:DA:38": ("TP-Link",        "router",  "router"),
    "78:44:FD": ("TP-Link",        "router",  "router"),
    "80:8F:1D": ("TP-Link",        "router",  "router"),
    "84:16:F9": ("TP-Link",        "router",  "router"),
    "90:F6:52": ("TP-Link",        "router",  "router"),
    "98:DA:C4": ("TP-Link",        "router",  "router"),
    "A4:2B:B0": ("TP-Link",        "router",  "router"),
    "A8:9C:ED": ("TP-Link",        "router",  "router"),
    "AC:84:C6": ("TP-Link",        "router",  "router"),
    "B0:4E:26": ("TP-Link",        "router",  "router"),
    "B0:BE:76": ("TP-Link",        "router",  "router"),
    "C0:4A:00": ("TP-Link",        "router",  "router"),
    "C8:3A:35": ("TP-Link",        "router",  "router"),
    "D8:07:B6": ("TP-Link",        "router",  "router"),
    "E8:DE:27": ("TP-Link",        "router",  "router"),
    "EC:08:6B": ("TP-Link",        "router",  "router"),
    "F0:D4:15": ("TP-Link",        "router",  "router"),
    "F4:F2:6D": ("TP-Link",        "router",  "router"),
    "FC:D7:33": ("TP-Link",        "router",  "router"),

    # Routers — other brands
    "00:18:F8": ("D-Link",         "router",  "router"),
    "00:1B:11": ("D-Link",         "router",  "router"),
    "00:21:91": ("D-Link",         "router",  "router"),
    "00:26:5A": ("D-Link",         "router",  "router"),
    "14:D6:4D": ("D-Link",         "router",  "router"),
    "1C:7E:E5": ("D-Link",         "router",  "router"),
    "28:10:7B": ("D-Link",         "router",  "router"),
    "34:08:04": ("D-Link",         "router",  "router"),
    "84:C9:B2": ("D-Link",         "router",  "router"),
    "B8:A3:86": ("D-Link",         "router",  "router"),
    "F0:7D:68": ("D-Link",         "router",  "router"),
    "00:0F:66": ("Netgear",        "router",  "router"),
    "00:14:6C": ("Netgear",        "router",  "router"),
    "00:1B:2F": ("Netgear",        "router",  "router"),
    "00:1E:2A": ("Netgear",        "router",  "router"),
    "00:22:3F": ("Netgear",        "router",  "router"),
    "00:24:B2": ("Netgear",        "router",  "router"),
    "00:26:F2": ("Netgear",        "router",  "router"),
    "10:0D:7F": ("Netgear",        "router",  "router"),
    "20:4E:7F": ("Netgear",        "router",  "router"),
    "2C:30:33": ("Netgear",        "router",  "router"),
    "30:46:9A": ("Netgear",        "router",  "router"),
    "44:94:FC": ("Netgear",        "router",  "router"),
    "6C:B0:CE": ("Netgear",        "router",  "router"),
    "84:1B:5E": ("Netgear",        "router",  "router"),
    "A0:21:B7": ("Netgear",        "router",  "router"),
    "C0:3F:0E": ("Netgear",        "router",  "router"),
    "E0:91:F5": ("Netgear",        "router",  "router"),
    "00:13:10": ("Linksys",        "router",  "router"),
    "00:14:BF": ("Linksys",        "router",  "router"),
    "00:18:39": ("Linksys",        "router",  "router"),
    "00:1A:70": ("Linksys",        "router",  "router"),
    "00:1C:10": ("Linksys",        "router",  "router"),
    "00:1D:7E": ("Linksys",        "router",  "router"),
    "00:1E:E5": ("Linksys",        "router",  "router"),
    "00:20:6B": ("Linksys",        "router",  "router"),
    "00:23:69": ("Linksys",        "router",  "router"),
    "00:25:9C": ("Linksys",        "router",  "router"),
    "00:26:B9": ("Linksys",        "router",  "router"),
    "20:AA:4B": ("Linksys",        "router",  "router"),
    "48:F8:B3": ("Linksys",        "router",  "router"),
    "58:6D:8F": ("Linksys",        "router",  "router"),
    "C0:C1:C0": ("Linksys",        "router",  "router"),
    "E8:08:8B": ("Linksys",        "router",  "router"),
    "00:90:4C": ("ASUS",           "router",  "router"),
    "00:1A:92": ("ASUS",           "router",  "router"),
    "10:7B:44": ("ASUS",           "router",  "router"),
    "14:DA:E9": ("ASUS",           "router",  "router"),
    "2C:FD:A1": ("ASUS",           "router",  "router"),
    "30:5A:3A": ("ASUS",           "router",  "router"),
    "40:16:7E": ("ASUS",           "router",  "router"),
    "4C:ED:FB": ("ASUS",           "router",  "router"),
    "50:46:5D": ("ASUS",           "router",  "router"),
    "6C:72:20": ("ASUS",           "router",  "router"),
    "74:D0:2B": ("ASUS",           "router",  "router"),
    "84:A9:C4": ("ASUS",           "router",  "router"),
    "88:D7:F6": ("ASUS",           "router",  "router"),
    "AC:22:0B": ("ASUS",           "router",  "router"),
    "B0:6E:BF": ("ASUS",           "router",  "router"),
    "E0:3F:49": ("ASUS",           "router",  "router"),
    "F8:32:E4": ("ASUS",           "router",  "router"),
    "FC:34:97": ("ASUS",           "router",  "router"),

    # Smart TVs
    "00:17:88": ("Philips Hue/TV", "tv",      "tv"),
    "00:1D:BA": ("Sony",           "tv",      "tv"),
    "00:24:BE": ("Sony",           "tv",      "tv"),
    "04:5D:4B": ("Sony",           "tv",      "tv"),
    "10:4F:58": ("Sony",           "tv",      "tv"),
    "20:16:D8": ("Sony",           "tv",      "tv"),
    "28:0D:FC": ("Sony",           "tv",      "tv"),
    "30:17:C8": ("Sony",           "tv",      "tv"),
    "40:B0:FA": ("Sony",           "tv",      "tv"),
    "54:42:49": ("Sony",           "tv",      "tv"),
    "70:26:05": ("Sony",           "tv",      "tv"),
    "AC:9B:0A": ("Sony",           "tv",      "tv"),
    "F0:BF:97": ("Sony",           "tv",      "tv"),
    "00:00:39": ("LG Electronics", "tv",      "tv"),
    "00:1C:62": ("LG",             "tv",      "tv"),
    "00:1E:75": ("LG",             "tv",      "tv"),
    "00:24:83": ("LG",             "tv",      "tv"),
    "00:26:E8": ("LG",             "tv",      "tv"),
    "08:D4:2B": ("LG Smart TV",    "tv",      "tv"),
    "10:68:3F": ("LG Smart TV",    "tv",      "tv"),
    "1C:08:C1": ("LG Smart TV",    "tv",      "tv"),
    "20:CF:30": ("LG Smart TV",    "tv",      "tv"),
    "28:80:23": ("LG Smart TV",    "tv",      "tv"),
    "34:4D:F7": ("LG Smart TV",    "tv",      "tv"),
    "3C:BD:3E": ("LG Smart TV",    "tv",      "tv"),
    "40:55:39": ("LG Smart TV",    "tv",      "tv"),
    "48:59:29": ("LG Smart TV",    "tv",      "tv"),
    "4C:E9:E4": ("LG Smart TV",    "tv",      "tv"),
    "50:55:27": ("LG Smart TV",    "tv",      "tv"),
    "58:A2:B5": ("LG Smart TV",    "tv",      "tv"),
    "60:84:BD": ("LG Smart TV",    "tv",      "tv"),
    "64:99:5D": ("LG Smart TV",    "tv",      "tv"),
    "78:5D:C8": ("LG Smart TV",    "tv",      "tv"),
    "A8:23:FE": ("LG Smart TV",    "tv",      "tv"),
    "B4:E6:2A": ("LG Smart TV",    "tv",      "tv"),
    "C8:08:73": ("LG Smart TV",    "tv",      "tv"),
    "CC:2D:8C": ("LG Smart TV",    "tv",      "tv"),

    # Amazon
    "00:FC:8B": ("Amazon Echo",    "iot",     "iot"),
    "08:B2:05": ("Amazon Echo",    "iot",     "iot"),
    "0C:47:C9": ("Amazon Fire TV", "tv",      "tv"),
    "10:AE:60": ("Amazon Echo",    "iot",     "iot"),
    "18:74:2E": ("Amazon Echo",    "iot",     "iot"),
    "34:D2:70": ("Amazon Echo",    "iot",     "iot"),
    "40:B4:CD": ("Amazon Echo",    "iot",     "iot"),
    "44:65:0D": ("Amazon Fire TV", "tv",      "tv"),
    "50:DC:E7": ("Amazon Echo",    "iot",     "iot"),
    "68:37:E9": ("Amazon Echo",    "iot",     "iot"),
    "74:C2:46": ("Amazon Fire TV", "tv",      "tv"),
    "84:D6:D0": ("Amazon Echo",    "iot",     "iot"),
    "A0:02:DC": ("Amazon Echo",    "iot",     "iot"),
    "B4:7C:9C": ("Amazon Echo",    "iot",     "iot"),
    "CC:F7:35": ("Amazon Echo",    "iot",     "iot"),
    "F0:27:2D": ("Amazon Fire TV", "tv",      "tv"),
    "FC:A1:83": ("Amazon Echo",    "iot",     "iot"),

    # Google / Chromecast / Nest
    "00:1A:11": ("Google",         "iot",     "iot"),
    "08:9E:08": ("Google Chromecast","tv",    "tv"),
    "14:91:82": ("Google Chromecast","tv",    "tv"),
    "1C:F2:9A": ("Google Nest",    "iot",     "iot"),
    "20:DF:B9": ("Google Chromecast","tv",    "tv"),
    "24:0F:56": ("Google Nest",    "iot",     "iot"),
    "30:FD:38": ("Google Chromecast","tv",    "tv"),
    "48:D6:D5": ("Google Chromecast","tv",    "tv"),
    "54:60:09": ("Google Nest",    "iot",     "iot"),
    "6C:AD:F8": ("Google Chromecast","tv",    "tv"),
    "80:7A:BF": ("Google Nest Hub", "iot",    "iot"),
    "A4:77:33": ("Google Chromecast","tv",    "tv"),
    "D4:F5:47": ("Google Chromecast","tv",    "tv"),
    "E4:F0:42": ("Google Chromecast","tv",    "tv"),
    "F4:F5:D8": ("Google Nest",    "iot",     "iot"),

    # Raspberry Pi
    "B8:27:EB": ("Raspberry Pi",   "iot",     "iot"),
    "DC:A6:32": ("Raspberry Pi",   "iot",     "iot"),
    "E4:5F:01": ("Raspberry Pi",   "iot",     "iot"),

    # Printers
    "00:00:48": ("Canon Printer",  "printer", "printer"),
    "00:1E:8F": ("Canon Printer",  "printer", "printer"),
    "08:00:37": ("HP Printer",     "printer", "printer"),
    "00:11:0A": ("HP Printer",     "printer", "printer"),
    "00:17:A4": ("HP Printer",     "printer", "printer"),
    "00:1F:29": ("HP Printer",     "printer", "printer"),
    "00:21:5A": ("HP Printer",     "printer", "printer"),
    "3C:D9:2B": ("HP Printer",     "printer", "printer"),
    "5C:B9:01": ("HP Printer",     "printer", "printer"),
    "00:0F:FE": ("Epson Printer",  "printer", "printer"),
    "00:26:AB": ("Epson Printer",  "printer", "printer"),
    "AC:18:26": ("Epson Printer",  "printer", "printer"),
    "00:1E:A9": ("Brother Printer","printer", "printer"),
    "00:80:77": ("Brother Printer","printer", "printer"),

    # Gaming consoles
    "00:04:1F": ("Nintendo",       "console", "console"),
    "00:09:BF": ("Nintendo",       "console", "console"),
    "00:16:56": ("Nintendo",       "console", "console"),
    "00:17:AB": ("Nintendo",       "console", "console"),
    "00:19:1D": ("Nintendo Switch","console", "console"),
    "00:1B:EA": ("Nintendo",       "console", "console"),
    "00:1F:32": ("Nintendo",       "console", "console"),
    "00:21:47": ("Nintendo",       "console", "console"),
    "00:22:D7": ("Nintendo",       "console", "console"),
    "00:24:44": ("Nintendo",       "console", "console"),
    "00:04:29": ("Sony PlayStation","console","console"),
    "00:15:C1": ("Sony PlayStation","console","console"),
    "00:19:C5": ("Sony PlayStation","console","console"),
    "00:1D:0D": ("Sony PlayStation","console","console"),
    "70:9E:29": ("Sony PlayStation 4","console","console"),
    "BC:60:A7": ("Sony PlayStation 4","console","console"),
    "F8:46:1C": ("Sony PlayStation 5","console","console"),
    "00:22:48": ("Microsoft Xbox", "console", "console"),
    "00:25:AE": ("Microsoft Xbox", "console", "console"),
    "30:59:B7": ("Microsoft Xbox", "console", "console"),
    "60:45:BD": ("Microsoft Xbox", "console", "console"),
    "7C:1E:B3": ("Microsoft Xbox", "console", "console"),
    "A8:BB:CF": ("Microsoft Xbox One","console","console"),
    "B4:AE:2B": ("Microsoft Xbox","console",  "console"),

    # NAS / Storage
    "00:11:32": ("Synology NAS",   "nas",     "nas"),
    "00:1B:A9": ("Synology NAS",   "nas",     "nas"),
    "00:24:97": ("Synology NAS",   "nas",     "nas"),
    "BC:5F:F4": ("Synology NAS",   "nas",     "nas"),
    "00:0C:29": ("QNAP NAS",       "nas",     "nas"),
    "00:08:9B": ("QNAP NAS",       "nas",     "nas"),
    "24:5E:BE": ("QNAP NAS",       "nas",     "nas"),

    # Virtual machines
    "00:50:56": ("VMware VM",      "vm",      "laptop"),
    "00:0C:29": ("VMware VM",      "vm",      "laptop"),
    "00:05:69": ("VMware VM",      "vm",      "laptop"),
    "08:00:27": ("VirtualBox VM",  "vm",      "laptop"),

    # Windows / Intel / generic laptop
    "B4:F0:AB": ("Realtek (Windows PC)", "desktop", "desktop"),
    "00:23:AE": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "00:21:6A": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "00:26:C6": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "00:1F:3B": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "10:02:B5": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "28:D2:44": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "40:A8:F0": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "5C:51:4F": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "7C:2A:31": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "8C:8D:28": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),
    "A4:C3:F0": ("Intel WiFi (Laptop)",  "laptop",  "laptop"),

    # Cameras / security
    "00:40:8C": ("Axis Camera",    "camera",  "camera"),
    "AC:CC:8E": ("Hikvision Camera","camera", "camera"),
    "C0:56:E3": ("Hikvision Camera","camera", "camera"),
    "BC:AD:28": ("Dahua Camera",   "camera",  "camera"),
    "90:02:A9": ("Dahua Camera",   "camera",  "camera"),
    "00:0D:87": ("Motorola",       "phone",   "phone"),
}

# ── Port risk database ─────────────────────────────────────────────────────────
PORT_RISK_DB = {
    21:    {"service": "FTP",         "risk": "high"},
    22:    {"service": "SSH",         "risk": "medium"},
    23:    {"service": "Telnet",      "risk": "critical"},
    25:    {"service": "SMTP",        "risk": "medium"},
    53:    {"service": "DNS",         "risk": "low"},
    80:    {"service": "HTTP",        "risk": "medium"},
    110:   {"service": "POP3",        "risk": "medium"},
    135:   {"service": "RPC",         "risk": "high"},
    139:   {"service": "NetBIOS",     "risk": "high"},
    143:   {"service": "IMAP",        "risk": "medium"},
    443:   {"service": "HTTPS",       "risk": "low"},
    445:   {"service": "SMB",         "risk": "critical"},
    515:   {"service": "LPD/Printer", "risk": "medium"},
    548:   {"service": "AFP",         "risk": "medium"},
    631:   {"service": "IPP/Printer", "risk": "low"},
    1234:  {"service": "RAT",         "risk": "critical"},
    1433:  {"service": "MSSQL",       "risk": "high"},
    1521:  {"service": "Oracle DB",   "risk": "high"},
    2049:  {"service": "NFS",         "risk": "high"},
    3306:  {"service": "MySQL",       "risk": "high"},
    3389:  {"service": "RDP",         "risk": "critical"},
    4444:  {"service": "Metasploit",  "risk": "critical"},
    5432:  {"service": "PostgreSQL",  "risk": "high"},
    5555:  {"service": "ADB",         "risk": "critical"},
    5900:  {"service": "VNC",         "risk": "high"},
    5985:  {"service": "WinRM",       "risk": "high"},
    6666:  {"service": "IRC/Malware", "risk": "critical"},
    7070:  {"service": "RealAudio",   "risk": "low"},
    8080:  {"service": "HTTP-Alt",    "risk": "medium"},
    8443:  {"service": "HTTPS-Alt",   "risk": "low"},
    8888:  {"service": "HTTP-Alt",    "risk": "medium"},
    9090:  {"service": "Openfire",    "risk": "medium"},
    9200:  {"service": "Elasticsearch","risk": "high"},
    9300:  {"service": "Elasticsearch","risk": "high"},
    12345: {"service": "NetBus",      "risk": "critical"},
    27017: {"service": "MongoDB",     "risk": "high"},
    31337: {"service": "BackOrifice", "risk": "critical"},
    54321: {"service": "BO2K",        "risk": "critical"},
}

SUSPICIOUS_PORTS = {4444, 31337, 1234, 5555, 9999, 6666, 12345, 54321}
CRITICAL_PORTS   = {23, 21, 135, 139, 445, 3389, 5900}


# ==============================================================================
# NETWORK UTILITIES
# ==============================================================================

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


# ==============================================================================
# DEVICE FINGERPRINTING
# ==============================================================================

def lookup_oui(mac: str) -> Tuple[str, str, str]:
    """
    Look up MAC OUI prefix in the database.
    Returns (vendor, device_type, icon) or ("Unknown", "unknown", "unknown")
    """
    if not mac:
        return ("Unknown", "unknown", "unknown")
    prefix = mac.upper()[:8]
    return OUI_DB.get(prefix, ("Unknown Vendor", "unknown", "unknown"))


def fingerprint_device(mac: str, open_ports: List[int], hostname: str,
                       nmap_os: str = "") -> Dict[str, str]:
    """
    Rich device fingerprinting using multiple signals:
    1. MAC OUI database (most reliable for known brands)
    2. Open port combinations (OS-specific services)
    3. Hostname pattern matching
    4. Nmap OS detection hints

    Returns dict with: vendor, device_type, icon, os_guess, label
    """
    vendor, device_type, icon = lookup_oui(mac)
    os_guess = "Unknown"
    label = vendor

    # ── 1. Hostname pattern matching ──────────────────────────────────────────
    host_lower = hostname.lower() if hostname else ""

    if any(x in host_lower for x in ["iphone", "apple", "macbook", "imac", "ipad"]):
        if "iphone" in host_lower:
            device_type, icon, os_guess, label = "phone", "phone", "iOS (iPhone)", "iPhone"
        elif "ipad" in host_lower:
            device_type, icon, os_guess, label = "tablet", "tablet", "iPadOS", "iPad"
        elif any(x in host_lower for x in ["macbook", "imac"]):
            device_type, icon, os_guess, label = "laptop", "laptop", "macOS", "Mac"

    elif any(x in host_lower for x in ["android", "samsung", "galaxy", "pixel"]):
        device_type, icon, os_guess = "phone", "phone", "Android"
        label = "Android Phone"

    elif any(x in host_lower for x in ["router", "gateway", "fritz", "livebox", "bbox",
                                         "dlink", "netgear", "tplink", "asus", "linksys"]):
        device_type, icon, os_guess = "router", "router", "Router / Embedded Linux"
        label = hostname or "Router"

    elif any(x in host_lower for x in ["printer", "print", "hp", "canon", "epson",
                                         "brother", "lexmark"]):
        device_type, icon, os_guess = "printer", "printer", "Printer Firmware"
        label = hostname or "Printer"

    elif any(x in host_lower for x in ["nas", "synology", "qnap", "drobo", "readynas"]):
        device_type, icon, os_guess = "nas", "nas", "Linux (NAS)"
        label = hostname or "NAS"

    elif any(x in host_lower for x in ["xbox", "playstation", "ps4", "ps5", "nintendo"]):
        device_type, icon, os_guess = "console", "console", "Gaming Console"
        label = hostname or "Gaming Console"

    elif any(x in host_lower for x in ["chromecast", "appletv", "firetv", "rokutv", "smarttv"]):
        device_type, icon, os_guess = "tv", "tv", "Smart TV"
        label = hostname or "Smart TV"

    elif any(x in host_lower for x in ["laptop", "notebook", "desktop", "pc-", "workstation"]):
        device_type, icon = "laptop", "laptop"

    # ── 2. Port-based OS fingerprinting ───────────────────────────────────────
    port_set = set(open_ports)

    # Windows indicators
    if {135, 139, 445} & port_set:
        os_guess = "Windows"
        if device_type in ("unknown", "desktop"):
            if 3389 in port_set:
                os_guess = "Windows (RDP enabled)"
            device_type, icon = "desktop", "desktop"
            label = label if label != "Unknown Vendor" else "Windows PC"

    # Linux indicators
    elif 22 in port_set and not {135, 139, 445} & port_set:
        if device_type == "unknown":
            os_guess = "Linux / Unix"
            device_type, icon = "desktop", "desktop"
            label = label if label != "Unknown Vendor" else "Linux Device"

    # macOS indicators
    elif {548, 5900} & port_set and 22 in port_set:
        os_guess = "macOS"
        if device_type == "unknown":
            device_type, icon = "laptop", "laptop"
            label = label if label != "Unknown Vendor" else "Mac"

    # Printer indicators
    elif {515, 631, 9100} & port_set:
        os_guess = "Printer Firmware"
        device_type, icon = "printer", "printer"
        label = label if label != "Unknown Vendor" else "Network Printer"

    # Router indicators
    elif {53, 67, 68, 80} & port_set and len(port_set) <= 5:
        if device_type == "unknown":
            os_guess = "Router / Embedded Linux"
            device_type, icon = "router", "router"
            label = label if label != "Unknown Vendor" else "Router"

    # Android ADB open
    elif 5555 in port_set:
        os_guess = "Android (ADB exposed)"
        if device_type == "unknown":
            device_type, icon = "phone", "phone"
            label = label if label != "Unknown Vendor" else "Android Device"

    # Smart TV / streaming
    elif {1900, 8008, 8009, 8080} & port_set:
        if device_type == "unknown":
            os_guess = "Smart TV / Streaming Device"
            device_type, icon = "tv", "tv"
            label = label if label != "Unknown Vendor" else "Smart TV"

    # ── 3. Nmap OS hint ───────────────────────────────────────────────────────
    if nmap_os:
        nmap_lower = nmap_os.lower()
        if "windows" in nmap_lower and os_guess == "Unknown":
            os_guess = nmap_os
            if device_type == "unknown":
                device_type, icon = "desktop", "desktop"
        elif "linux" in nmap_lower and os_guess == "Unknown":
            os_guess = nmap_os
            if device_type == "unknown":
                device_type, icon = "desktop", "desktop"
        elif "ios" in nmap_lower or "iphone" in nmap_lower:
            os_guess = "iOS (iPhone)"
            device_type, icon = "phone", "phone"
        elif "android" in nmap_lower:
            os_guess = "Android"
            device_type, icon = "phone", "phone"

    # ── 4. Final fallback ─────────────────────────────────────────────────────
    if device_type == "unknown":
        device_type, icon = "desktop", "desktop"
    if os_guess == "Unknown" and vendor not in ("Unknown", "Unknown Vendor"):
        os_guess = f"{vendor} Device"

    return {
        "vendor":      vendor,
        "device_type": device_type,
        "icon":        icon,
        "os_guess":    os_guess,
        "label":       label,
    }


# ==============================================================================
# SCANNING — IMPROVED ARP + PARALLEL PING FALLBACK
# ==============================================================================

def arp_scan(network_range: str) -> List[Dict[str, str]]:
    """
    Multi-strategy host discovery:
    1. ARP scan (primary — requires admin, most reliable)
    2. Parallel ping sweep (fallback / supplement)
    Results are merged and deduplicated by IP.
    """
    found: Dict[str, Dict] = {}  # ip -> host dict

    # Strategy 1: ARP scan
    if SCAPY_AVAILABLE:
        arp_hosts = _arp_scan_scapy(network_range)
        for h in arp_hosts:
            found[h["ip"]] = h

    # Strategy 2: Parallel ping sweep (always run — catches devices
    # that don't respond to ARP, like some phones in deep sleep)
    ping_hosts = _ping_sweep_parallel(network_range)
    for h in ping_hosts:
        if h["ip"] not in found:
            found[h["ip"]] = h  # add new, keep ARP result if we have it

    result = list(found.values())
    log.info(f"Total unique hosts discovered: {len(result)}")
    return result


def _arp_scan_scapy(network_range: str) -> List[Dict[str, str]]:
    """
    ARP scan with increased timeout and retry.
    """
    log.info(f"ARP scanning {network_range}...")
    try:
        arp   = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        # First pass: timeout=5s
        answered, _ = srp(ether / arp, timeout=5, verbose=False, retry=2, inter=0.1)
        hosts = {r.psrc: {"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in answered}

        log.info(f"ARP scan found {len(hosts)} hosts")
        return list(hosts.values())

    except PermissionError:
        log.error("ARP scan requires Administrator privileges on Windows.")
        log.error("Please right-click PowerShell and 'Run as Administrator'.")
        return []
    except Exception as e:
        log.error(f"ARP scan error: {e}")
        return []


def _ping_one(ip: str, is_windows: bool) -> Optional[str]:
    """Ping a single IP. Returns IP if alive, None otherwise."""
    try:
        if is_windows:
            cmd = ["ping", "-n", "1", "-w", "800", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return str(ip) if result.returncode == 0 else None
    except Exception:
        return None


def _ping_sweep_parallel(network_range: str, max_workers: int = 50) -> List[Dict[str, str]]:
    """
    Parallel ping sweep — pings all hosts simultaneously using threads.
    Much faster than sequential ping (254 hosts in ~2s instead of ~4min).
    """
    log.info(f"Parallel ping sweep on {network_range} ({max_workers} threads)...")
    is_windows = platform.system().lower() == "windows"

    try:
        network = ipaddress.ip_network(network_range, strict=False)
        ips = list(network.hosts())
    except Exception as e:
        log.error(f"Invalid network range: {e}")
        return []

    hosts = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ping_one, ip, is_windows): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hosts.append({"ip": result, "mac": ""})

    log.info(f"Ping sweep found {len(hosts)} responding hosts")
    return hosts


def port_scan(ip: str, scan_type: str = "full") -> List[Dict[str, Any]]:
    """Scan open ports. Returns list of port dicts."""
    if not NMAP_AVAILABLE:
        return []
    nm   = nmap.PortScanner()
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
            version   = f"{port_data.get('product','')} {port_data.get('version','')}".strip()
            ports.append({
                "port":         port_num,
                "protocol":     proto,
                "state":        "open",
                "service":      port_data.get("name") or risk_info["service"],
                "version":      version,
                "is_suspicious": port_num in SUSPICIOUS_PORTS,
                "is_critical":   port_num in CRITICAL_PORTS,
                "risk_level":    risk_info["risk"],
            })
    return sorted(ports, key=lambda p: p["port"])


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ==============================================================================
# MAIN SCAN PIPELINE
# ==============================================================================

def run_scan(network_range: str, scan_type: str = "full") -> List[Dict]:
    log.info(f"Starting {scan_type} scan on {network_range}")

    raw_hosts = arp_scan(network_range)
    if not raw_hosts:
        log.warning("No hosts found. Make sure you are running as Administrator.")
        return []

    scanned_devices = []
    for host in raw_hosts:
        ip  = host["ip"]
        mac = host.get("mac", "").upper()

        log.info(f"Scanning {ip} (MAC: {mac or 'unknown'})...")

        ports          = port_scan(ip, scan_type)
        open_port_nums = [p["port"] for p in ports]
        hostname       = resolve_hostname(ip)

        # Rich device fingerprinting
        fingerprint = fingerprint_device(mac, open_port_nums, hostname)

        # Threat status
        has_critical = any(p["risk_level"] == "critical" for p in ports)
        has_high     = any(p["risk_level"] == "high" for p in ports)
        if has_critical:
            status = "threat"
        elif has_high:
            status = "warning"
        else:
            status = "safe"

        device = {
            "ip":          ip,
            "mac":         mac,
            "hostname":    hostname,
            "vendor":      fingerprint["vendor"],
            "os_guess":    fingerprint["os_guess"],
            "device_type": fingerprint["device_type"],
            "icon":        fingerprint["icon"],
            "label":       fingerprint["label"],
            "status":      status,
            "ports":       ports,
            "risk_score":  0.0,
        }
        scanned_devices.append(device)
        log.info(f"  -> {fingerprint['label']} ({fingerprint['device_type']}) | {len(ports)} ports | {status}")

    log.info(f"Scan complete: {len(scanned_devices)} devices")
    return scanned_devices


# ==============================================================================
# KICK — ARP DEAUTHENTICATION
# ==============================================================================

def arp_deauth(target_mac: str, target_ip: str, network_range: str, count: int = 10) -> bool:
    if not SCAPY_AVAILABLE:
        log.error("Scapy required for ARP deauth.")
        return False
    try:
        network    = ipaddress.ip_network(network_range, strict=False)
        gateway_ip = str(list(network.hosts())[0])
    except Exception:
        gateway_ip = network_range.rsplit(".", 1)[0] + ".1"
    try:
        packet = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
        )
        sendp(packet, count=count, inter=0.1, verbose=False)
        log.info(f"ARP deauth complete for {target_ip}")
        return True
    except PermissionError:
        log.error("ARP deauth requires Administrator.")
        return False
    except Exception as e:
        log.error(f"ARP deauth failed: {e}")
        return False


def resolve_ip_for_mac(target_mac: str, network_range: str) -> Optional[str]:
    hosts = arp_scan(network_range)
    for host in hosts:
        if host.get("mac", "").upper() == target_mac.upper():
            return host["ip"]
    return None


def poll_and_execute_kicks(network_range: str):
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/devices/agent/commands",
            headers=AGENT_HEADERS,
            timeout=10,
        )
        resp.raise_for_status()
        commands = resp.json().get("commands", [])
    except Exception as e:
        log.warning(f"Could not fetch kick commands: {e}")
        return
    for cmd in commands:
        kick_id, target_mac, target_ip = cmd["id"], cmd["mac_address"], cmd.get("target_ip")
        if not target_ip:
            target_ip = resolve_ip_for_mac(target_mac, network_range)
            if not target_ip:
                _report_kick_result(kick_id, "failed", "Could not resolve IP")
                continue
        success = arp_deauth(target_mac, target_ip, network_range)
        _report_kick_result(kick_id, "done" if success else "failed",
                            "ARP deauth executed" if success else "ARP deauth failed")


def _report_kick_result(kick_id: int, status: str, message: str):
    try:
        requests.post(
            f"{BACKEND_URL}/api/devices/agent/kick-result",
            json={"kick_id": kick_id, "status": status, "message": message},
            headers=AGENT_HEADERS,
            timeout=10,
        ).raise_for_status()
        log.info(f"Kick #{kick_id} reported as '{status}'")
    except Exception as e:
        log.error(f"Failed to report kick result: {e}")


# ==============================================================================
# BACKEND COMMUNICATION
# ==============================================================================

def push_to_backend(devices: List[Dict], network_range: str) -> bool:
    payload = {
        "network_range": network_range,
        "devices":      devices,
    }
    try:
        resp = requests.post(f"{BACKEND_URL}/api/scan/agent", json=payload, headers=AGENT_HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        log.info(f"Scan accepted: ID {data.get('id')}, score {data.get('risk_score')}/100, {data.get('threats_found')} threats")
        return True
    except requests.ConnectionError:
        log.error(f"Cannot connect to {BACKEND_URL}")
        return False
    except requests.HTTPError as e:
        log.error(f"Backend rejected: {e.response.status_code} — {e.response.text}")
        return False
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return False


def save_local(devices: List[Dict], network_range: str):
    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({"timestamp": datetime.now().isoformat(),
                   "network_range": network_range, "devices": devices}, f, indent=2)
    log.info(f"Saved locally: {filename}")


# ==============================================================================
# CLI
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="NetGuard Local Agent v1.2")
    parser.add_argument("--scan",       action="store_true")
    parser.add_argument("--watch",      action="store_true")
    parser.add_argument("--interval",   type=int, default=300)
    parser.add_argument("--range",      type=str, default="")
    parser.add_argument("--type",       choices=["quick", "full"], default="full")
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--check-env",  action="store_true")
    args = parser.parse_args()

    if args.check_env:
        print("\n=== NetGuard Agent v1.2 — Environment Check ===\n")
        print(f"Backend URL:    {BACKEND_URL}")
        print(f"User ID:        {USER_ID if USER_ID is not None else 'NOT SET'}")
        print(f"Agent Secret:   {'Set' if AGENT_SECRET != 'change_this_shared_secret' else 'Using default'}")
        print(f"Nmap:           {'Available' if NMAP_AVAILABLE else 'Not installed'}")
        print(f"Scapy:          {'Available' if SCAPY_AVAILABLE else 'Not installed'}")
        print(f"Platform:       {platform.system()}")
        print(f"Detected LAN:   {get_local_network()}")
        return

    network   = args.range or NETWORK_RANGE or get_local_network()
    scan_type = args.type or SCAN_TYPE

    print(f"""
NetGuard Local Agent v1.2
  Backend:  {BACKEND_URL}
  Network:  {network}
  Scan:     {scan_type}
  Mode:     {"watch (" + str(args.interval) + "s)" if args.watch else "single scan"}
""")

    def do_cycle():
        devices = run_scan(network, scan_type)
        if devices:
            if args.local_only:
                save_local(devices, network)
            else:
                if not push_to_backend(devices, network):
                    save_local(devices, network)
        if not args.local_only:
            poll_and_execute_kicks(network)

    if args.scan:
        do_cycle()
        return

    if args.watch:
        log.info(f"Watch mode — every {args.interval}s")
        while True:
            do_cycle()
            time.sleep(args.interval)
        return

    parser.print_help()


if __name__ == "__main__":
    main()