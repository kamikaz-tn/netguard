"""
netguard/backend/core/config.py
────────────────────────────────
Central settings loaded from .env via pydantic-settings.
"""
 
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from functools import lru_cache


class Settings(BaseSettings):
    # ── API ──────────────────────────────────────────────────────────────────
    app_name: str = "NetGuard API"
    app_version: str = "1.0.0"
    debug: bool = False

    # ── Auth ─────────────────────────────────────────────────────────────────
    # secret_key and agent_secret have NO defaults — must be set via env.
    # The app refuses to boot if either is missing or too short.
    secret_key: str = Field(..., min_length=32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    turnstile_secret_key: str = ""
 
    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./netguard.db"
 
    # ── CORS ─────────────────────────────────────────────────────────────────
    frontend_origin: str = "http://localhost:5173"
 
    # ── URLs (used for email verification links) ──────────────────────────────
    backend_url: str = "https://netguard-production-4f1d.up.railway.app"
 
    # ── Agent ────────────────────────────────────────────────────────────────
    agent_secret: str = Field(..., min_length=32)
 
    # ── External APIs ────────────────────────────────────────────────────────
    hibp_api_key: str = ""
    nmap_path: str = ""
    gemini_api_key: str = ""
 
    # ── Email (Resend) ────────────────────────────────────────────────────────
    # Sign up free at https://resend.com — 3,000 emails/month, no credit card
    # 1. Get your API key from resend.com/api-keys
    # 2. Add a verified sender domain (or use onboarding@resend.dev for testing)
    # 3. Set these in Railway environment variables:
    resend_api_key: str = ""
    resend_from_email: str = "NetGuard <onboarding@resend.dev>"
    gmail_user:     str = ""
    gmail_password: str = ""
    brevo_api_key:     str = ""
    brevo_sender_email: str = ""
 
    # ── Scan defaults ────────────────────────────────────────────────────────
    suspicious_ports: list[int] = [
        4444, 31337, 1234, 5555, 9999, 6666, 7777, 8888, 12345, 54321,
    ]
    critical_ports: list[int] = [
        23, 21, 135, 139, 445, 3389, 5900,
    ]
 
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "case_sensitive": False,
    }
 
 
@lru_cache()
def get_settings() -> Settings:
    return Settings()
 
 
settings = get_settings()
 