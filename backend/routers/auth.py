"""
netguard/backend/routers/auth.py
──────────────────────────────────
User registration and login endpoints with Cloudflare Turnstile CAPTCHA.
"""
 
import secrets
import httpx
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
COOKIE_MAX_AGE = settings.access_token_expire_minutes * 60
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
 
 
def _set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="none",
        secure=True,   # HTTPS in production
        path="/",
    )
 
 
async def verify_turnstile(token: str) -> bool:
    """Verify Turnstile token with Cloudflare API."""
    if not settings.turnstile_secret_key:
        # If no key configured, skip verification (dev mode)
        return True
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TURNSTILE_VERIFY_URL,
                data={
                    "secret": settings.turnstile_secret_key,
                    "response": token,
                },
                timeout=5.0,
            )
            result = resp.json()
            return result.get("success", False)
    except Exception:
        return False
 
 
@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: UserRegister, response: Response, db: AsyncSession = Depends(get_db)):
    """Create a new user account — verifies Turnstile CAPTCHA first."""
    # Verify captcha
    captcha_ok = await verify_turnstile(body.turnstile_token or "")
    if not captcha_ok:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed. Please try again.")
 
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
    return TokenResponse(access_token=token, username=user.username)
 
 
@router.post("/login", response_model=TokenResponse)
async def login(
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login — verifies Turnstile CAPTCHA then authenticates user."""
    # Turnstile token is passed as a custom field via client_id in OAuth2 form
    captcha_ok = await verify_turnstile(form.client_id or "")
    if not captcha_ok:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed. Please try again.")
 
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
    return TokenResponse(access_token=token, username=user.username)
 
 
@router.post("/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/")
 
 
@router.get("/ws-ticket")
async def get_ws_ticket(current_user: dict = Depends(get_current_user)):
    ws_token = create_access_token(
        {"sub": current_user["user_id"], "username": current_user["username"]},
        expires_delta=timedelta(seconds=60),
    )
    return {"ticket": ws_token}