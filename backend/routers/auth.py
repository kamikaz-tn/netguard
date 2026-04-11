"""
netguard/backend/routers/auth.py
──────────────────────────────────
User registration and login endpoints.
Returns JWT tokens on success.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from core.auth import verify_password, hash_password, create_access_token
from models.db_models import User
from models.schemas import UserRegister, TokenResponse

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: UserRegister, db: AsyncSession = Depends(get_db)):
    """Create a new user account."""

    # Check for existing username or email
    existing = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()   # get user.id before commit

    token = create_access_token({"sub": str(user.id), "username": user.username})
    return TokenResponse(access_token=token, username=user.username)


@router.post("/login", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login with username + password, returns JWT."""

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
    return TokenResponse(access_token=token, username=user.username)
