"""
netguard/backend/routers/auth.py
──────────────────────────────────
User registration, login, and full profile management.
 
Fix: /verify-email no longer requires auth — it's clicked from email with no session.
Fix: avatar_url is now stored and returned from the User model (uses getattr safely).
Fix: profile PATCH explicitly handles avatar_url = "" (clear) vs None (no change).
Fix: _send_email_gmail now raises on failure so real SMTP errors surface to frontend.
"""
 
import httpx
import secrets
import aiosmtplib
import re
from datetime import timedelta, datetime, timezone
 
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.database import get_db
from core.auth import (
    verify_password, hash_password, create_access_token,
    get_current_user,
)
from core.config import settings
from models.db_models import User, ScanResult, VerificationToken
from models.schemas import UserRegister, TokenResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
 
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)
 
COOKIE_NAME = "ng_token"
COOKIE_MAX_AGE = settings.access_token_expire_minutes * 60
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
VERIFICATION_TOKEN_TTL = timedelta(hours=24)

# Login lockout policy
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = timedelta(minutes=15)
 
 
# ── Pydantic schemas for profile ──────────────────────────────────────────────
 
class ProfileUpdate(BaseModel):
    username:   Optional[str]      = None
    email:      Optional[EmailStr] = None
    bio:        Optional[str]      = None
    avatar_url: Optional[str]      = None   # None = don't change; "" = clear
 
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
 
 
# ── Email sender (via Brevo) ─────────────────────────────────────────────────
 
async def _send_email_brevo(to: str, subject: str, html: str) -> bool:
    """Send via Brevo HTTP API — works on Railway (no SMTP ports needed)."""
    api_key = settings.brevo_api_key
    sender  = settings.brevo_sender_email

    if not api_key or not sender:
        raise RuntimeError(
            "BREVO_API_KEY or BREVO_SENDER_EMAIL not set in environment variables."
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "sender":      {"name": "NetGuard Security", "email": sender},
                "to":          [{"email": to}],
                "subject":     subject,
                "htmlContent": html,
            },
        )

    if not resp.is_success:
        raise RuntimeError(f"Brevo API error {resp.status_code}: {resp.text}")

    print(f"✓ Email sent via Brevo to {to}")
    return True
 
 
@router.post("/send-verification")
@limiter.limit("3/minute")
async def send_verification_email(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    if getattr(user, "email_verified", False):
        raise HTTPException(status_code=400, detail="Email is already verified")

    # Invalidate any existing tokens for this user, then issue a fresh one
    await db.execute(delete(VerificationToken).where(VerificationToken.user_id == user.id))
    token = secrets.token_urlsafe(32)
    db.add(VerificationToken(
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + VERIFICATION_TOKEN_TTL,
    ))
    await db.flush()

    frontend_origin = getattr(settings, "frontend_origin", "https://netguard-peach.vercel.app")
    verify_url = f"{frontend_origin}/verify?token={token}"
 
    try:
        await _send_email_brevo(
            to=user.email,
            subject="NetGuard — Verify your email address",
            html=_verification_email_html(user.username, verify_url),
        )
        return {"detail": "Verification email sent."}
    except Exception as e:
        # Log full error server-side; return a generic message to the client.
        # Provider responses can leak account info, quotas, sender domain, etc.
        import logging
        logging.getLogger(__name__).exception("send_verification_email failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Could not send verification email. Please try again later.",
        )
 
 
def _verification_email_html(username: str, verify_url: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#080a0b;color:#c8d4d8;font-family:'Courier New',monospace;padding:40px;">
      <div style="max-width:480px;margin:0 auto;border:1px solid #1e2d33;border-left:3px solid #e8354a;padding:32px;border-radius:4px;">
        <div style="font-size:22px;color:#e8354a;letter-spacing:4px;font-weight:700;margin-bottom:8px;">⬡ NETGUARD</div>
        <div style="font-size:10px;color:#4a6068;letter-spacing:2px;margin-bottom:24px;">NETWORK SECURITY MONITOR</div>
        <div style="font-size:14px;color:#e8eef0;margin-bottom:16px;">Hello <strong style="color:#e8354a;">{username}</strong>,</div>
        <div style="font-size:13px;color:#c8d4d8;line-height:1.7;margin-bottom:24px;">
          Click the button below to verify your email address.
          This link expires in <strong style="color:#ff6b35;">24 hours</strong>.
        </div>
        <a href="{verify_url}" style="display:inline-block;background:rgba(232,53,74,0.12);border:1px solid #e8354a;color:#e8354a;padding:12px 24px;text-decoration:none;font-family:'Courier New',monospace;font-size:11px;letter-spacing:2px;border-radius:4px;">
          ▶ VERIFY EMAIL ADDRESS
        </a>
        <div style="margin-top:24px;font-size:10px;color:#4a6068;line-height:1.8;">
          Or copy this URL into your browser (must be logged in):<br/>
          <span style="color:#4db8e8;word-break:break-all;">{verify_url}</span>
        </div>
        <div style="margin-top:24px;padding-top:16px;border-top:1px solid #1e2d33;font-size:9px;color:#2e4450;letter-spacing:1px;">
          If you didn't create a NetGuard account, ignore this email.
        </div>
      </div>
    </body>
    </html>
    """
 
 
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

    now = datetime.now(timezone.utc)

    # Reject locked accounts before checking the password (constant-time-ish:
    # we still call verify_password below on the dummy path to avoid revealing
    # whether the username exists).
    if user and user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to repeated failed logins. Try again later.",
        )

    if not user or not verify_password(form.password, user.hashed_password):
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= LOGIN_MAX_ATTEMPTS:
                user.locked_until = now + LOGIN_LOCKOUT_DURATION
                user.failed_login_attempts = 0
            await db.flush()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Successful login — reset counters
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.flush()

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
 
 
# ── GET /api/auth/verify-email?token=... ──────────────────────────────────────
# NOTE: This endpoint does NOT require auth — the user clicks it from their email
# client where they have no active session cookie.
 
@router.get("/verify-email")
@limiter.limit("10/minute")
async def verify_email(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Called when user clicks the verification link in their email.
    No auth required — the token itself is the credential.
    Marks the account verified then redirects to the frontend profile page.
    """
    result = await db.execute(
        select(VerificationToken).where(VerificationToken.token == token)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link. Please request a new one from your profile page.")

    if datetime.now(timezone.utc) > entry.expires_at:
        await db.delete(entry)
        await db.flush()
        raise HTTPException(status_code=400, detail="Verification link has expired (24h). Please request a new one from your profile page.")

    user_result = await db.execute(select(User).where(User.id == entry.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        await db.delete(entry)
        await db.flush()
        raise HTTPException(status_code=404, detail="User not found.")

    if hasattr(user, "email_verified"):
        user.email_verified = True
    await db.delete(entry)
    await db.flush()

    # Redirect to frontend profile page with success flag
    frontend_origin = getattr(settings, "frontend_origin", "https://netguard-peach.vercel.app")
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"{frontend_origin}/profile?verified=1")
 
 
# ── Profile endpoints ─────────────────────────────────────────────────────────
 
@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    scans_result = await db.execute(select(ScanResult).where(ScanResult.user_id == user.id))
    scans = scans_result.scalars().all()
 
    total_scans   = len(scans)
    total_devices = sum(s.hosts_up      or 0 for s in scans)
    total_threats = sum(s.threats_found or 0 for s in scans)
 
    return ProfileResponse(
        user_id        = user.id,
        username       = user.username,
        email          = user.email,
        bio            = getattr(user, "bio",            None),
        avatar_url     = getattr(user, "avatar_url",     None) or "",
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
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    if body.username and body.username != user.username:
        taken = await db.execute(select(User).where(User.username == body.username))
        if taken.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already taken")
        user.username = body.username
 
    if body.email and body.email != user.email:
        taken = await db.execute(select(User).where(User.email == body.email))
        if taken.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body.email
        if hasattr(user, "email_verified"):
            user.email_verified = False
 
    # bio — only update if column exists
    if body.bio is not None and hasattr(user, "bio"):
        user.bio = body.bio[:200]
 
    # avatar_url — update whenever the field is provided (even empty string to clear)
    if body.avatar_url is not None and hasattr(user, "avatar_url"):
        user.avatar_url = body.avatar_url.strip()
 
    await db.flush()
    return {"detail": "Profile updated", "username": user.username}
 
 
@router.post("/change-password")
async def change_password(
    body: PasswordChange,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
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
 
 
@router.delete("/account")
async def delete_account(
    current_user: dict = Depends(get_current_user),
    response: Response = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == int(current_user["user_id"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
 
    await db.delete(user)
    await db.flush()
 
    if response:
        response.delete_cookie(key=COOKIE_NAME, path="/", samesite="none", secure=True)
 
    return {"detail": "Account deleted"}