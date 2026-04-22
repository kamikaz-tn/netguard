"""
netguard/backend/routers/auth.py
──────────────────────────────────
User registration and login endpoints.
Sets JWT token in httpOnly cookie on success (XSS-safe).
 
Extra endpoint:
  GET /api/auth/ws-ticket  — issues a short-lived token (60s)
                             for WebSocket authentication so the main
                             JWT is never exposed in a URL query param.
"""
 
import secrets
from datetime import timedelta
 
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
 
from core.database import get_db
from core.auth import (
    verify_password, hash_password, create_access_token,
    get_current_user,
)
from core.config import settings
from models.db_models import User
from models.schemas import UserRegister, TokenResponse
 
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
 
COOKIE_NAME = "ng_token"
COOKIE_MAX_AGE = settings.access_token_expire_minutes * 60  # seconds
 
 
def _set_auth_cookie(response: Response, token: str):
    """Set JWT as an httpOnly, SameSite=Lax cookie."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,      # ← JS cannot read this cookie — XSS-safe
        samesite="lax",     # ← CSRF protection
        secure=False,       # ← set True in production (HTTPS)
        path="/",
    )
 
 
@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: UserRegister, response: Response, db: AsyncSession = Depends(get_db)):
    """Create a new user account and set auth cookie."""
    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already registered")
 
    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
 
    token = create_access_token({"sub": str(user.id), "username": user.username})
    _set_auth_cookie(response, token)
    # Return username for display; raw JWT is in the cookie only
    return TokenResponse(access_token="[httpOnly-cookie]", username=user.username)
 
 
@router.post("/login", response_model=TokenResponse)
async def login(
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login with username + password — sets httpOnly cookie, returns username."""
    result = await db.execute(select(User).where(User.username == form.username))
    user = result.scalar_one_or_none()
 
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
 
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
 
    token = create_access_token({"sub": str(user.id), "username": user.username})
    _set_auth_cookie(response, token)
    return TokenResponse(access_token="[httpOnly-cookie]", username=user.username)
 
 
@router.post("/logout", status_code=204)
async def logout(response: Response):
    """Clear the auth cookie server-side."""
    response.delete_cookie(key=COOKIE_NAME, path="/")
 
 
@router.get("/ws-ticket")
async def get_ws_ticket(current_user: dict = Depends(get_current_user)):
    """
    Issue a short-lived (60s) JWT for WebSocket authentication.
    The client places this in the ws:// URL — it never touches any storage
    and expires before it could be meaningfully replayed.
    """
    ws_token = create_access_token(
        {"sub": current_user["user_id"], "username": current_user["username"]},
        expires_delta=timedelta(seconds=60),
    )
    return {"ticket": ws_token}