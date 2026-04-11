"""
netguard/backend/routers/alerts.py
────────────────────────────────────
WebSocket endpoint for real-time alerts +
REST endpoints to manage alert history.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc
from typing import List

from core.database import get_db
from core.auth import decode_token, get_current_user
from models.db_models import Alert
from models.schemas import AlertOut
from services.websocket_manager import manager

router = APIRouter(tags=["Alerts & Real-time"])


# ── WebSocket ─────────────────────────────────────────────────────────────────
@router.websocket("/ws/{user_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: int,
    token: str = Query(...),   # passed as ?token=<jwt>
):
    """
    WebSocket connection for real-time alerts.
    Authenticate via JWT passed as query param:
      ws://localhost:8000/ws/42?token=<your_jwt>

    The agent or server pushes alerts through this channel instantly
    when new threats are detected during a scan.
    """
    # Validate token before accepting connection
    try:
        payload = decode_token(token)
        token_user_id = int(payload.get("sub", -1))
        if token_user_id != user_id:
            await websocket.close(code=4001, reason="Unauthorized")
            return
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return

    await manager.connect(user_id, websocket)

    # Send a welcome ping so client knows connection is live
    await manager.send_to_user(user_id, {
        "type": "connected",
        "message": "NetGuard real-time alerts active",
    })

    try:
        while True:
            # Keep connection alive — wait for client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(user_id)


# ── GET /api/alerts ───────────────────────────────────────────────────────────
@router.get("/api/alerts", response_model=List[AlertOut])
async def get_alerts(
    unread_only: bool = False,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Return alert history for the authenticated user."""
    user_id = int(current_user["user_id"])
    query = select(Alert).where(Alert.user_id == user_id)

    if unread_only:
        query = query.where(Alert.is_read == False)

    query = query.order_by(desc(Alert.created_at)).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


# ── PATCH /api/alerts/read-all ────────────────────────────────────────────────
@router.patch("/api/alerts/read-all", status_code=204)
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Mark all alerts as read for the current user."""
    await db.execute(
        update(Alert)
        .where(Alert.user_id == int(current_user["user_id"]))
        .values(is_read=True)
    )
