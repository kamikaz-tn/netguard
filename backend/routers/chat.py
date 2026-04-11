"""
netguard/backend/routers/chat.py
──────────────────────────────────
AI security advisor chat endpoint.
Injects the user's latest scan context into every request
so Claude gives specific, relevant advice.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from core.database import get_db
from core.auth import get_current_user
from models.db_models import ScanResult, ScanFinding
from models.schemas import ChatRequest, ChatResponse
from services.ai_advisor import get_ai_response

router = APIRouter(prefix="/api/chat", tags=["AI Advisor"])


async def _get_scan_context(user_id: int, db: AsyncSession) -> dict | None:
    """Load the latest scan summary to inject into the AI system prompt."""
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == user_id)
        .order_by(desc(ScanResult.created_at))
        .limit(1)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        return None

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == scan.id).limit(10)
    )
    findings = [
        {
            "host_ip": f.host_ip,
            "port": f.port,
            "service": f.service,
            "severity": f.severity,
            "description": f.description,
        }
        for f in findings_result.scalars().all()
    ]

    return {
        "network_range": scan.network_range,
        "hosts_up": scan.hosts_up,
        "total_ports": scan.total_ports,
        "threats_found": scan.threats_found,
        "risk_score": scan.risk_score,
        "findings": findings,
    }


@router.post("/message", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Send a message to the AI security advisor.
    Full conversation history must be sent on each request (stateless API).
    Automatically injects the user's latest scan as context.
    """
    if not body.messages:
        raise HTTPException(status_code=422, detail="messages array cannot be empty")

    user_id = int(current_user["user_id"])

    # Use caller-provided context, or load from DB
    scan_context = body.scan_context or await _get_scan_context(user_id, db)

    try:
        reply = await get_ai_response(
            messages=body.messages,
            scan_context=scan_context,
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI service error: {str(e)}")

    return ChatResponse(
        reply=reply,
        model="claude-sonnet-4-20250514",
    )
