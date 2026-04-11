"""
netguard/backend/core/auth.py
──────────────────────────────
JWT creation, verification, and FastAPI dependency for protected routes.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from .config import settings

# ── OAuth2 token URL (used by Swagger UI login form) ─────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


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


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """FastAPI dependency — inject into any route to require authentication."""
    payload = decode_token(token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {"user_id": user_id, "username": payload.get("username")}


def verify_agent_secret(secret: str) -> bool:
    """Check the shared secret sent by the local agent."""
    return secret == settings.agent_secret