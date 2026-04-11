"""
netguard/backend/routers/scan.py
──────────────────────────────────
Endpoints for triggering and retrieving network scans.

Flow:
  POST /api/scan/start    → triggers scan (or queues it for agent)
  GET  /api/scan/results  → paginated scan history
  GET  /api/scan/{id}     → single scan detail
  POST /api/scan/agent    → agent pushes completed scan data (agent-mode)
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List

from core.database import get_db
from core.auth import get_current_user, verify_agent_secret
from models.db_models import ScanResult, ScanFinding, TrustedDevice
from models.schemas import (
    ScanRequest, ScanResultOut, AgentScanPayload, DeviceInfo, ScanFindingOut
)
from services.scanner import run_full_scan
from services.risk_analyzer import analyze_devices, compute_network_risk_score
from services.websocket_manager import manager

router = APIRouter(prefix="/api/scan", tags=["Network Scanning"])


# ── Helper: save scan to DB ───────────────────────────────────────────────────
async def _persist_scan(
    db: AsyncSession,
    user_id: int,
    network_range: str,
    devices: List[DeviceInfo],
    findings: List[ScanFindingOut],
    risk_score: float,
) -> ScanResult:
    total_ports = sum(len(d.ports) for d in devices)
    threats = sum(1 for f in findings if f.severity in ("critical", "high"))

    scan = ScanResult(
        user_id=user_id,
        network_range=network_range,
        hosts_up=len(devices),
        total_ports=total_ports,
        threats_found=threats,
        risk_score=risk_score,
        scan_data={
            "devices": [d.model_dump() for d in devices],
        },
    )
    db.add(scan)
    await db.flush()

    for f in findings:
        db.add(ScanFinding(
            scan_id=scan.id,
            host_ip=f.host_ip,
            host_mac=f.host_mac,
            port=f.port,
            service=f.service,
            severity=f.severity,
            category=f.category,
            description=f.description,
            remediation=f.remediation,
        ))

    await db.flush()
    return scan


# ── POST /api/scan/start ──────────────────────────────────────────────────────
@router.post("/start", response_model=ScanResultOut)
async def start_scan(
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger a network scan from the server side.
    NOTE: In production, this should be called by the local agent,
    not the server (the server doesn't have access to the LAN).
    This endpoint works when backend + frontend are on the same LAN machine.
    """
    user_id = int(current_user["user_id"])

    # Load trusted MACs for this user
    trusted_result = await db.execute(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.is_trusted == True
        )
    )
    trusted_macs = [d.mac_address for d in trusted_result.scalars().all()]

    # Run the scan
    try:
        devices = await run_full_scan(
            network_range=body.network_range,
            scan_type=body.scan_type,
            trusted_macs=trusted_macs,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Analyze findings
    findings = analyze_devices(devices)
    risk_score = compute_network_risk_score(devices, findings)

    # Save to DB
    scan = await _persist_scan(db, user_id, body.network_range, devices, findings, risk_score)

    # Notify user via WebSocket if connected
    if findings:
        for f in findings:
            if f.severity in ("critical", "high"):
                await manager.send_to_user(user_id, {
                    "type": "alert",
                    "severity": f.severity,
                    "message": f.description,
                    "host_ip": f.host_ip,
                    "port": f.port,
                })

    return ScanResultOut(
        id=scan.id,
        network_range=scan.network_range,
        hosts_up=scan.hosts_up,
        total_ports=scan.total_ports,
        threats_found=scan.threats_found,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        devices=devices,
        findings=findings,
    )


# ── POST /api/scan/agent ──────────────────────────────────────────────────────
@router.post("/agent", response_model=ScanResultOut)
async def agent_push_scan(
    payload: AgentScanPayload,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint for the LOCAL AGENT to push scan results.
    The agent runs on the user's machine (where it has LAN access),
    scans the network, and POSTs results here.
    Authenticated via shared secret.
    """
    if not verify_agent_secret(payload.agent_secret):
        raise HTTPException(status_code=401, detail="Invalid agent secret")

    devices = payload.devices
    findings = analyze_devices(devices)
    risk_score = compute_network_risk_score(devices, findings)

    scan = await _persist_scan(
        db, payload.user_id, payload.network_range, devices, findings, risk_score
    )

    # Push alerts to user via WebSocket
    for f in findings:
        if f.severity in ("critical", "high"):
            await manager.send_to_user(payload.user_id, {
                "type": "alert",
                "severity": f.severity,
                "message": f.description,
                "host_ip": f.host_ip,
                "port": f.port,
            })

    return ScanResultOut(
        id=scan.id,
        network_range=scan.network_range,
        hosts_up=scan.hosts_up,
        total_ports=scan.total_ports,
        threats_found=scan.threats_found,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        devices=devices,
        findings=findings,
    )


# ── GET /api/scan/results ─────────────────────────────────────────────────────
@router.get("/results", response_model=List[ScanResultOut])
async def get_scan_history(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Return the N most recent scans for the authenticated user."""
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == int(current_user["user_id"]))
        .order_by(desc(ScanResult.created_at))
        .limit(limit)
    )
    scans = result.scalars().all()

    return [
        ScanResultOut(
            id=s.id,
            network_range=s.network_range,
            hosts_up=s.hosts_up,
            total_ports=s.total_ports,
            threats_found=s.threats_found,
            risk_score=s.risk_score,
            created_at=s.created_at,
        )
        for s in scans
    ]


# ── GET /api/scan/{scan_id} ───────────────────────────────────────────────────
@router.get("/{scan_id}", response_model=ScanResultOut)
async def get_scan_detail(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Return full detail of a specific scan including devices and findings."""
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == int(current_user["user_id"])
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == scan_id)
    )
    findings = [
        ScanFindingOut(
            host_ip=f.host_ip,
            host_mac=f.host_mac,
            port=f.port,
            service=f.service,
            severity=f.severity,
            category=f.category,
            description=f.description,
            remediation=f.remediation,
        )
        for f in findings_result.scalars().all()
    ]

    devices = [DeviceInfo(**d) for d in (scan.scan_data or {}).get("devices", [])]

    return ScanResultOut(
        id=scan.id,
        network_range=scan.network_range,
        hosts_up=scan.hosts_up,
        total_ports=scan.total_ports,
        threats_found=scan.threats_found,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        devices=devices,
        findings=findings,
    )
