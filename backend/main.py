"""
netguard/backend/main.py
──────────────────────────
FastAPI application entry point.

Start the server:
  uvicorn main:app --reload --host 0.0.0.0 --port 8000

Swagger UI docs:
  http://localhost:8000/docs

ReDoc docs:
  http://localhost:8000/redoc
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.database import init_db
from routers import auth, scan, devices, password, chat, alerts


# ── Startup / shutdown lifecycle ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create DB tables
    await init_db()
    print(f"✅ NetGuard API started — {settings.app_name} v{settings.app_version}")
    print(f"📡 CORS allowed origin: {settings.frontend_origin}")
    yield
    # Shutdown: nothing to clean up for SQLite
    print("👋 NetGuard API shutting down")


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## NetGuard Network Security API

A full-featured network security monitoring backend with:

- 🔍 **Network scanning** — ARP host discovery + Nmap port scanning
- 🚨 **Threat detection** — Flags backdoor ports, suspicious services, unknown devices
- 🤖 **AI Advisor** — Claude-powered security guidance with scan context
- 🔐 **Password breach check** — HaveIBeenPwned k-anonymity integration
- 📡 **Real-time alerts** — WebSocket push for instant threat notifications
- 🗓️ **Scan history** — Persistent scan results and findings
    """,
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(devices.router)
app.include_router(password.router)
app.include_router(chat.router)
app.include_router(alerts.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "NetGuard API is running",
        "docs": "/docs",
        "health": "/health",
    }
