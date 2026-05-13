"""
netguard/backend/core/auth.py
──────────────────────────────
JWT creation, verification, and FastAPI dependency for protected routes.
 
Token is stored in an httpOnly cookie (not localStorage) to prevent XSS theft.
"""
 
import hashlib
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database import get_db
 
COOKIE_NAME = "ng_token"
 
 
def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
 
 
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
 
 
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
 
 
def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
 
 
def _extract_token(request: Request) -> Optional[str]:
    """
    Try to extract JWT from:
      1. httpOnly cookie (preferred — XSS-safe)
      2. Authorization: Bearer header (fallback for WebSocket / agent use)
    """
    # 1. Cookie (browser requests)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
 
    # 2. Authorization header (WebSocket token= param or agent)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
 
    # 3. Query param for WebSocket (ws:// can't set cookies easily)
    token = request.query_params.get("token")
    if token:
        return token
 
    return None
 
 
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    FastAPI dependency — inject into any route to require authentication.

    Verifies the JWT signature AND checks token_version matches the User row,
    so password changes / logout-everywhere invalidate existing tokens
    before their TTL expires.
    """
    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Lazy import avoids a circular dep on db_models at module-load time.
    from models.db_models import User
    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account no longer valid")

    token_version = payload.get("tv", 0)
    if token_version != (user.token_version or 0):
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    return {
        "user_id": user_id,
        "username": payload.get("username"),
        "token_version": user.token_version or 0,
    }
 
 
def hash_agent_token(raw: str) -> str:
    """SHA-256 of the raw agent token. We store only the hash."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_agent_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hash). The raw value is shown to the user once."""
    raw = _secrets.token_urlsafe(48)
    return raw, hash_agent_token(raw)


async def require_agent(
    x_agent_token: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> int:
    """
    FastAPI dependency for agent endpoints.

    Looks up the user from the `X-Agent-Token` header (SHA-256 → User.agent_token_hash)
    and returns their user_id. The user_id NEVER comes from the request body/query —
    that prevents a compromised agent from impersonating other users.
    """
    if not x_agent_token:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Token header")

    token_hash = hash_agent_token(x_agent_token)

    # Lazy import to avoid circular dep on db_models at module load.
    from models.db_models import User
    result = await db.execute(select(User).where(User.agent_token_hash == token_hash))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid agent token")

    return user.id