"""
netguard/backend/models/schemas.py
"""
 
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, field_validator
 
 
# ── Auth ──────────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    turnstile_token: str = ""
 
    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v
 
 
class UserLogin(BaseModel):
    username: str
    password: str
 
 
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
 
 
# ── Network Scan ──────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    network_range: str = "192.168.1.0/24"
    scan_type: str = "full"
 
    @field_validator("network_range")
    @classmethod
    def validate_range(cls, v):
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid network range: {v}")
        return v
 
 
class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    is_suspicious: bool = False
    is_critical: bool = False
    risk_level: str = "low"
 
 
class DeviceInfo(BaseModel):
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    status: str = "unknown"
    ports: List[PortInfo] = []
    risk_score: float = 0.0
 
 
class ScanFindingOut(BaseModel):
    host_ip: str
    host_mac: Optional[str]
    port: Optional[int]
    service: Optional[str]
    severity: str
    category: str
    description: str
    remediation: Optional[str]
 
    class Config:
        from_attributes = True
 
 
class ScanResultOut(BaseModel):
    id: int
    network_range: str
    hosts_up: int
    total_ports: int
    threats_found: int
    risk_score: float
    created_at: datetime
    devices: List[DeviceInfo] = []
    findings: List[ScanFindingOut] = []
 
    class Config:
        from_attributes = True
 
 
# ── Agent data push ───────────────────────────────────────────────────────────
class AgentScanPayload(BaseModel):
    user_id: int
    network_range: str
    devices: List[DeviceInfo]
 
 
# ── Kick Command ──────────────────────────────────────────────────────────────
class KickRequest(BaseModel):
    mac_address: str
    target_ip: Optional[str] = None   # frontend can pass last known IP
 
 
class KickCommandOut(BaseModel):
    id: int
    mac_address: str
    target_ip: Optional[str]
    status: str
    created_at: datetime
    executed_at: Optional[datetime]
 
    class Config:
        from_attributes = True
 
 
class AgentKickResult(BaseModel):
    """Agent sends this back after executing a kick."""
    kick_id: int
    status: str        # "done" or "failed"
    message: str = ""
 
 
# ── Trusted Devices ───────────────────────────────────────────────────────────
class TrustDeviceRequest(BaseModel):
    mac_address: str
    label: Optional[str] = None
 
 
class TrustedDeviceOut(BaseModel):
    id: int
    mac_address: str
    label: Optional[str]
    vendor: Optional[str]
    last_seen_ip: Optional[str]
    is_trusted: bool
    trusted_at: datetime
 
    class Config:
        from_attributes = True
 
 
# ── Password check ────────────────────────────────────────────────────────────
class PasswordCheckRequest(BaseModel):
    hash_prefix: str
 
    @field_validator("hash_prefix")
    @classmethod
    def must_be_5_chars(cls, v):
        v = v.upper()
        if len(v) != 5:
            raise ValueError("hash_prefix must be exactly 5 characters")
        return v
 
 
class PasswordCheckResponse(BaseModel):
    pwned: bool
    count: int = 0
    message: str
 
 
# ── AI Chat ───────────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str
 
 
class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    scan_context: Optional[dict] = None
 
 
class ChatResponse(BaseModel):
    reply: str
    model: str
 
 
# ── Alerts ────────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: int
    severity: str
    message: str
    host_ip: Optional[str]
    port: Optional[int]
    is_read: bool
    created_at: datetime
 
    class Config:
        from_attributes = True