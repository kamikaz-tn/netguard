"""
netguard/backend/routers/devices.py
─────────────────────────────────────
Endpoints for managing trusted/unknown devices and kick commands.
 
Kick flow:
  1. User clicks Kick in dashboard → POST /api/devices/kick
  2. Backend stores KickCommand(status="pending") in DB
  3. Agent polls GET /api/devices/agent/commands?user_id=...  with X-Agent-Secret header
  4. Agent executes ARP deauth on target device
  5. Agent reports result → POST /api/devices/agent/kick-result  with X-Agent-Secret header
  6. Backend marks KickCommand(status="done" or "failed")
"""
 
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from typing import List
 
from core.database import get_db
from core.auth import get_current_user, require_agent
from models.db_models import TrustedDevice, KickCommand
from models.schemas import (
    TrustDeviceRequest, TrustedDeviceOut,
    KickRequest, KickCommandOut, AgentKickResult,
)
 
router = APIRouter(prefix="/api/devices", tags=["Device Management"])
 
 
# ── GET /api/devices/trusted ──────────────────────────────────────────────────
@router.get("/trusted", response_model=List[TrustedDeviceOut])
async def list_trusted_devices(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == int(current_user["user_id"])
        )
    )
    return result.scalars().all()
 
 
# ── POST /api/devices/trust ───────────────────────────────────────────────────
@router.post("/trust", response_model=TrustedDeviceOut, status_code=201)
async def trust_device(
    body: TrustDeviceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = int(current_user["user_id"])
    mac = body.mac_address.upper()
 
    existing = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.mac_address == mac,
        )
    )
    device = existing.scalar_one_or_none()
 
    if device:
        device.is_trusted = True
        device.label = body.label or device.label
        await db.flush()
        return device
 
    new_device = TrustedDevice(
        user_id=user_id,
        mac_address=mac,
        label=body.label,
    )
    db.add(new_device)
    await db.flush()
    return new_device
 
 
# ── DELETE /api/devices/trust/{mac} ──────────────────────────────────────────
@router.delete("/trust/{mac_address}", status_code=204)
async def untrust_device(
    mac_address: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = int(current_user["user_id"])
    mac = mac_address.upper()
 
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.mac_address == mac,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Trusted device not found")
 
    await db.execute(
        delete(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.mac_address == mac,
        )
    )
 
 
# ── POST /api/devices/kick ────────────────────────────────────────────────────
@router.post("/kick", response_model=KickCommandOut, status_code=201)
async def kick_device(
    body: KickRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Queue a kick command for the local agent to execute.
    The agent polls for pending commands and runs ARP deauth.
    """
    user_id = int(current_user["user_id"])
    mac = body.mac_address.upper()
 
    # Check for an existing pending kick for this MAC (avoid duplicates)
    existing = await db.execute(
        select(KickCommand).where(
            KickCommand.user_id == user_id,
            KickCommand.mac_address == mac,
            KickCommand.status == "pending",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="A kick is already pending for this device. Wait for the agent to execute it."
        )
 
    cmd = KickCommand(
        user_id=user_id,
        mac_address=mac,
        target_ip=body.target_ip,
        status="pending",
    )
    db.add(cmd)
    await db.flush()
    return cmd
 
 
# ── GET /api/devices/kicks ────────────────────────────────────────────────────
@router.get("/kicks", response_model=List[KickCommandOut])
async def list_kicks(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Return recent kick commands for the current user (for UI status display)."""
    result = await db.execute(
        select(KickCommand)
        .where(KickCommand.user_id == int(current_user["user_id"]))
        .order_by(KickCommand.created_at.desc())
        .limit(20)
    )
    return result.scalars().all()
 
 
# ── GET /api/devices/agent/commands ──────────────────────────────────────────
@router.get("/agent/commands", dependencies=[Depends(require_agent)])
async def get_agent_commands(
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent polls this endpoint to get pending kick commands.
    Authenticated via shared secret in `X-Agent-Secret` header.
    """
    result = await db.execute(
        select(KickCommand).where(
            KickCommand.user_id == user_id,
            KickCommand.status == "pending",
        )
    )
    commands = result.scalars().all()
 
    return {
        "commands": [
            {
                "id": cmd.id,
                "mac_address": cmd.mac_address,
                "target_ip": cmd.target_ip,
            }
            for cmd in commands
        ]
    }
 
 
# ── POST /api/devices/agent/kick-result ──────────────────────────────────────
@router.post("/agent/kick-result", dependencies=[Depends(require_agent)])
async def agent_kick_result(
    body: AgentKickResult,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent reports back the result of executing a kick command.
    Authenticated via shared secret in `X-Agent-Secret` header.
    """
    result = await db.execute(
        select(KickCommand).where(KickCommand.id == body.kick_id)
    )
    cmd = result.scalar_one_or_none()
    if not cmd:
        raise HTTPException(status_code=404, detail="Kick command not found")
 
    cmd.status = body.status   # "done" or "failed"
    cmd.executed_at = datetime.now(timezone.utc)
    await db.flush()
 
    return {"ok": True, "kick_id": body.kick_id, "status": body.status}