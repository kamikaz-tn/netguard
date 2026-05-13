"""
netguard/backend/core/auth.py
──────────────────────────────
JWT creation, verification, and FastAPI dependency for protected routes.
 
Token is stored in an httpOnly cookie (not localStorage) to prevent XSS theft.
"""
 
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, Header, HTTPException, Request, status
from jose import JWTError, jwt

from .config import settings
 
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
    except JWTError:
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
 
 
async def get_current_user(request: Request) -> dict:
    """FastAPI dependency — inject into any route to require authentication."""
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
    return {"user_id": user_id, "username": payload.get("username")}
 
 
def verify_agent_secret(secret: str) -> bool:
    """Constant-time check of the shared secret sent by the local agent."""
    if not secret:
        return False
    return _secrets.compare_digest(secret, settings.agent_secret)


def require_agent(x_agent_secret: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency: agent endpoints must send `X-Agent-Secret` header."""
    if not verify_agent_secret(x_agent_secret or ""):
        raise HTTPException(status_code=401, detail="Invalid agent secret")