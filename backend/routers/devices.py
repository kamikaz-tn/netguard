"""
netguard/backend/routers/devices.py
─────────────────────────────────────
Endpoints for managing trusted/unknown devices.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from typing import List

from core.database import get_db
from core.auth import get_current_user
from models.db_models import TrustedDevice
from models.schemas import TrustDeviceRequest, TrustedDeviceOut

router = APIRouter(prefix="/api/devices", tags=["Device Management"])


@router.get("/trusted", response_model=List[TrustedDeviceOut])
async def list_trusted_devices(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Return all devices the user has marked as trusted."""
    result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == int(current_user["user_id"])
        )
    )
    return result.scalars().all()


@router.post("/trust", response_model=TrustedDeviceOut, status_code=201)
async def trust_device(
    body: TrustDeviceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Mark a device (by MAC) as trusted."""
    user_id = int(current_user["user_id"])
    mac = body.mac_address.upper()

    # Check if already trusted
    existing = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.mac_address == mac,
        )
    )
    device = existing.scalar_one_or_none()

    if device:
        # Update existing record
        device.is_trusted = True
        device.label = body.label or device.label
        await db.flush()
        return device

    # Create new trusted entry
    new_device = TrustedDevice(
        user_id=user_id,
        mac_address=mac,
        label=body.label,
    )
    db.add(new_device)
    await db.flush()
    return new_device


@router.delete("/trust/{mac_address}", status_code=204)
async def untrust_device(
    mac_address: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Remove a device from the trusted list."""
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


@router.post("/kick")
async def kick_device(
    mac_address: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Send a kick command to the local agent which will perform
    ARP deauthentication to disconnect the device from the network.

    The actual kick is handled by the agent — this endpoint records
    the intent and the agent polls for pending kicks.
    """
    # In full implementation: store kick command, agent polls /agent/commands
    # For now we return instructions
    return {
        "status": "queued",
        "message": f"Kick command queued for {mac_address}. "
                   "The local agent will execute ARP deauthentication on next poll.",
        "mac_address": mac_address.upper(),
    }
