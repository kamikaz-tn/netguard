"""
netguard/backend/core/config.py
────────────────────────────────
Central settings loaded from .env via pydantic-settings.
Import `settings` anywhere in the app to access config values.
"""
 
from pydantic_settings import BaseSettings
from functools import lru_cache
 
 
class Settings(BaseSettings):
    # ── API ──────────────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    app_name: str = "NetGuard API"
    app_version: str = "1.0.0"
    debug: bool = False
 
    # ── Auth ─────────────────────────────────────────────────────────────────
    secret_key: str = "netguard_super_secret_key_2026"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440   # 24 hours
 
    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./netguard.db"
 
    # ── CORS ─────────────────────────────────────────────────────────────────
    frontend_origin: str = "http://localhost:5173"
 
    # ── Agent ────────────────────────────────────────────────────────────────
    agent_secret: str = "netguard_agent_secret_2026"
 
    # ── External APIs ────────────────────────────────────────────────────────
    hibp_api_key: str = ""
    nmap_path: str = ""
    gemini_api_key: str = ""
 
    # ── Scan defaults ────────────────────────────────────────────────────────
    # Ports considered "suspicious" / known backdoor ports
    suspicious_ports: list[int] = [
        4444,   # Metasploit default listener
        31337,  # Back Orifice
        1234,   # Common RAT port
        5555,   # Android Debug Bridge / Cerberus RAT
        9999,   # Common C2 port
        6666,   # IRC / malware
        7777,   # Common RAT port
        8888,   # Common C2 port
        12345,  # NetBus RAT
        54321,  # Back Orifice 2000
    ]
 
    # Ports that should never be open on a typical home network
    critical_ports: list[int] = [
        23,    # Telnet — unencrypted
        21,    # FTP — unencrypted
        135,   # RPC — Windows attack surface
        139,   # NetBIOS
        445,   # SMB — EternalBlue exploitable
        3389,  # RDP — brute-force target
        5900,  # VNC — often misconfigured
    ]
 
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "case_sensitive": False,  # add this
    }
 
@lru_cache()
def get_settings() -> Settings:
    return Settings()
 
 
settings = get_settings()
 