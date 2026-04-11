"""
netguard/backend/models/db_models.py
──────────────────────────────────────
SQLAlchemy ORM models — these become the actual database tables.
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

    scans = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("TrustedDevice", back_populates="user", cascade="all, delete-orphan")


# ── Scan Result ───────────────────────────────────────────────────────────────
class ScanResult(Base):
    """One full network scan (triggered by user or scheduled)."""
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    network_range: Mapped[str] = mapped_column(String(50))   # e.g. 192.168.1.0/24
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    total_ports: Mapped[int] = mapped_column(Integer, default=0)
    threats_found: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    scan_data: Mapped[dict] = mapped_column(JSON)                  # full raw results
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    user = relationship("User", back_populates="scans")
    findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")


# ── Scan Finding ──────────────────────────────────────────────────────────────
class ScanFinding(Base):
    """Individual threat or notable finding within a scan."""
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id"), nullable=False)
    host_ip: Mapped[str] = mapped_column(String(45))
    host_mac: Mapped[str] = mapped_column(String(20), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))   # critical | high | medium | low | info
    category: Mapped[str] = mapped_column(String(50))   # backdoor | telnet | smb | unknown_device | etc.
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)

    scan = relationship("ScanResult", back_populates="findings")


# ── Trusted Device ─────────────────────────────────────────────────────────────
class TrustedDevice(Base):
    """Devices the user has manually confirmed as safe."""
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(20), nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=True)    # user-given name
    vendor: Mapped[str] = mapped_column(String(100), nullable=True)
    last_seen_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=True)
    trusted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    user = relationship("User", back_populates="devices")


# ── Alert ─────────────────────────────────────────────────────────────────────
class Alert(Base):
    """Real-time alerts pushed via WebSocket and stored for history."""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    host_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
