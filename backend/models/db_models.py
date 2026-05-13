"""
netguard/backend/models/db_models.py
──────────────────────────────────────
SQLAlchemy ORM models — these become the actual database tables.
 
Changes:
  - User: added avatar_url, bio, email_verified columns
  - VerificationToken: new table so tokens survive Railway restarts
"""
 
from datetime import datetime, timezone
from sqlalchemy import (
    String, Integer, Boolean, DateTime, Float, Text, ForeignKey, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base
 
 
def now_utc():
    return datetime.now(timezone.utc)
 
 
# ── User ──────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
 
    # Profile fields
    avatar_url: Mapped[str] = mapped_column(String(500), default="", server_default="")
    bio: Mapped[str] = mapped_column(Text, default="", server_default="")
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")

    # Login lockout (per-user, defends against credential stuffing where per-IP
    # rate-limit collapses behind shared CDN/NAT IPs)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Bumped on password change / explicit "log out everywhere" so existing JWTs
    # are rejected even before their TTL expires.
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
 
    scans = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("TrustedDevice", back_populates="user", cascade="all, delete-orphan")
    verification_tokens = relationship("VerificationToken", back_populates="user", cascade="all, delete-orphan")
 
 
# ── Verification Token ────────────────────────────────────────────────────────
class VerificationToken(Base):
    """
    Stores email verification tokens in the DB so they survive server restarts.
    Railway redeploys wipe in-memory state — this fixes the 'invalid token' bug.
    """
    __tablename__ = "verification_tokens"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    token: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
 
    user = relationship("User", back_populates="verification_tokens")
 
 
# ── Scan Result ───────────────────────────────────────────────────────────────
class ScanResult(Base):
    __tablename__ = "scan_results"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    network_range: Mapped[str] = mapped_column(String(50))
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    total_ports: Mapped[int] = mapped_column(Integer, default=0)
    threats_found: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    scan_data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
 
    user = relationship("User", back_populates="scans")
    findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")
 
 
# ── Scan Finding ──────────────────────────────────────────────────────────────
class ScanFinding(Base):
    __tablename__ = "scan_findings"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id"), nullable=False)
    host_ip: Mapped[str] = mapped_column(String(45))
    host_mac: Mapped[str] = mapped_column(String(20), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
 
    scan = relationship("ScanResult", back_populates="findings")
 
 
# ── Trusted Device ─────────────────────────────────────────────────────────────
class TrustedDevice(Base):
    __tablename__ = "trusted_devices"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(20), nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=True)
    vendor: Mapped[str] = mapped_column(String(100), nullable=True)
    last_seen_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=True)
    trusted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
 
    user = relationship("User", back_populates="devices")
 
 
# ── Alert ─────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    host_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
 
 
# ── Kick Command ──────────────────────────────────────────────────────────────
class KickCommand(Base):
    """
    Stores kick requests from the dashboard.
    The local agent polls for pending kicks and executes ARP deauth.
    """
    __tablename__ = "kick_commands"
 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(20), nullable=False)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | done | failed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)