"""
netguard/backend/routers/auth.py
──────────────────────────────────
User registration, login, and full profile management.
"""
 
import httpx
from datetime import timedelta
 
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address
 
from core.database import get_db
from core.auth import (
    verify_password, hash_password, create_access_token,
    get_current_user,
)
from core.config import settings
from models.db_models import User, ScanResult
from models.schemas import UserRegister, TokenResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
 
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)
 
COOKIE_NAME = "ng_token"
COOKIE_MAX_AGE = settings.access_token_expire_minutes * 60
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
 
 
# ── Pydantic schemas for profile ──────────────────────────────────────────────
 
class ProfileUpdate(BaseModel):
    username:  Optional[str]   = None
    email:     Optional[EmailStr] = None
    bio:       Optional[str]   = None
    avatar_url: Optional[str]  = None
 
class PasswordChange(BaseModel):
    current_password: str
    new_password:     str
 
class ProfileResponse(BaseModel):
    user_id:        int
    username:       str
    email:          str
    bio:            Optional[str]
    avatar_url:     Optional[str]
    email_verified: bool
    is_active:      bool
    created_at:     Optional[str]
    total_scans:    int
    total_devices:  int
    total_threats:  int
 
 
# ── Cookie helper ─────────────────────────────────────────────────────────────
 
def _set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="none",
        secure=True,
        path="/",
    )
 
 
async def verify_turnstile(token: str) -> bool:
    if not settings.turnstile_secret_key:
        return True
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TURNSTILE_VERIFY_URL,
                data={"secret": settings.turnstile_secret_key, "response": token},
                timeout=5.0,
            )
            return resp.json().get("success", False)
    except Exception:
        return False
 
 
# ── Auth endpoints ────────────────────────────────────────────────────────────
 
@router.post("/register", response_model=TokenResponse, status_code=201)
@limiter.limit("3/minute")
async def register(request: Request, body: UserRegister, response: Response, db: AsyncSession = Depends(get_db)):
    captcha_ok = await verify_turnstile(body.turnstile_token or "")
    if not captcha_ok:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed. Please try again.")
 
    existing = await db.execute(
        select(User).where((User.username == body.username) | (User.email == body.email))
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
    return TokenResponse(access_token=token, username=user.username)
 
 
@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request, response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    captcha_ok = await verify_turnstile(form.client_id or "")
    if not captcha_ok:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed. Please try again.")
 
    result = await db.execute(select(User).where(User.username == form.username))
    user = result.scalar_one_or_none()
 
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
 
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
 
    token = create_access_token({"sub": str(user.id), "username": user.username})
    _set_auth_cookie(response, token)
    return TokenResponse(access_token=token, username=user.username)
 
 
@router.post("/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="none", secure=True)
 
 
@router.get("/ws-ticket")
async def get_ws_ticket(current_user: dict = Depends(get_current_user)):
    ws_token = create_access_token(
        {"sub": current_user["user_id"], "username": current_user["username"]},
        expires_delta=timedelta(seconds=60),
    )
    return {"ticket": ws_token}
 
 
@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {"user_id": int(current_user["user_id"]), "username": current_user["username"]}
 
 
# ── Profile endpoints ─────────────────────────────────────────────────────────
 
@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the full profile of the logged-in user, including scan stats."""
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    # Aggregate scan stats for this user
    scans_result = await db.execute(
        select(ScanResult).where(ScanResult.user_id == user.id)
    )
    scans = scans_result.scalars().all()
 
    total_scans   = len(scans)
    total_devices = sum(s.hosts_up      or 0 for s in scans)
    total_threats = sum(s.threats_found or 0 for s in scans)
 
    return ProfileResponse(
        user_id        = user.id,
        username       = user.username,
        email          = user.email,
        bio            = getattr(user, "bio",            None),
        avatar_url     = getattr(user, "avatar_url",     None),
        email_verified = getattr(user, "email_verified", False),
        is_active      = user.is_active,
        created_at     = str(getattr(user, "created_at", "")) or None,
        total_scans    = total_scans,
        total_devices  = total_devices,
        total_threats  = total_threats,
    )
 
 
@router.patch("/profile")
async def update_profile(
    body: ProfileUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update username, email, bio, or avatar."""
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    # Check username uniqueness
    if body.username and body.username != user.username:
        taken = await db.execute(select(User).where(User.username == body.username))
        if taken.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already taken")
        user.username = body.username
 
    # Check email uniqueness
    if body.email and body.email != user.email:
        taken = await db.execute(select(User).where(User.email == body.email))
        if taken.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body.email
        # Reset email_verified if email changed
        if hasattr(user, "email_verified"):
            user.email_verified = False
 
    if body.bio is not None and hasattr(user, "bio"):
        user.bio = body.bio[:200]  # cap at 200 chars
 
    if body.avatar_url is not None and hasattr(user, "avatar_url"):
        user.avatar_url = body.avatar_url
 
    await db.flush()
    return {"detail": "Profile updated", "username": user.username}
 
 
@router.post("/change-password")
async def change_password(
    body: PasswordChange,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the user's password — requires current password for verification."""
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
 
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
 
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from current password")
 
    user.hashed_password = hash_password(body.new_password)
    await db.flush()
    return {"detail": "Password changed successfully"}
 
 
@router.post("/send-verification")
async def send_verification_email(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Send a verification email to the user.
    In production, integrate with SendGrid / Resend / SMTP here.
    For now, returns a stub success so the frontend flow works.
    """
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    if getattr(user, "email_verified", False):
        raise HTTPException(status_code=400, detail="Email is already verified")
 
    # TODO: generate token, store it, send email via your email provider
    # For now this is a stub — wire up your email service here
    return {"detail": f"Verification email sent to {user.email}"}
 
 
@router.delete("/account")
async def delete_account(
    current_user: dict = Depends(get_current_user),
    response: Response = None,
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete the user's account and all associated data."""
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    await db.delete(user)
    await db.flush()
 
    if response:
        response.delete_cookie(key=COOKIE_NAME, path="/", samesite="none", secure=True)
 
    return {"detail": "Account deleted"}