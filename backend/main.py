"""
netguard/backend/main.py
──────────────────────────
FastAPI application entry point with rate limiting.
Session 16: added CVE lookup router.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
 
from core.config import settings
from core.database import init_db
from routers import auth, scan, devices, password, chat, alerts, cve  # ← added cve
 
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    print(f"✅ NetGuard API started — {settings.app_name} v{settings.app_version}")
    print(f"📡 CORS allowed origin: {settings.frontend_origin}")
    yield
    print("👋 NetGuard API shutting down")
 
 
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
## NetGuard Network Security API
 
- 🔍 **Network scanning** — ARP host discovery + Nmap port scanning
- 🚨 **Threat detection** — Flags backdoor ports, suspicious services
- 🛡️ **CVE lookup** — NVD-powered vulnerability database per service/port
- 🤖 **AI Advisor** — Gemini-powered security guidance
- 🔐 **Password breach check** — HaveIBeenPwned k-anonymity
- 📡 **Real-time alerts** — WebSocket push notifications
    """,
    lifespan=lifespan,
)
 
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# ── CSRF defense ─────────────────────────────────────────────────────────────
# Cookies are SameSite=None, so we can't rely on the browser's built-in CSRF
# protection. Instead, require a custom header on every state-changing request.
# Browsers force a CORS preflight when a non-safelisted header is sent, and our
# CORS allowlist blocks unknown origins — so forged cross-site POSTs can't
# include this header and will fail.
_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
# Agent endpoints authenticate via X-Agent-Secret, not the session cookie,
# so they're not vulnerable to CSRF.
_CSRF_EXEMPT_PATHS = (
    "/api/scan/agent",
    "/api/devices/agent/",
)


class CSRFHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in _CSRF_SAFE_METHODS:
            return await call_next(request)
        if request.url.path.startswith(_CSRF_EXEMPT_PATHS):
            return await call_next(request)
        if not request.headers.get("x-requested-with"):
            return JSONResponse(
                status_code=403,
                content={"detail": "Missing X-Requested-With header"},
            )
        return await call_next(request)


app.add_middleware(CSRFHeaderMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://netguard-peach.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(devices.router)
app.include_router(password.router)
app.include_router(chat.router)
app.include_router(alerts.router)
app.include_router(cve.router)   # ← NEW
 
 
@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "app": settings.app_name, "version": settings.app_version}
 
 
@app.get("/", tags=["System"])
async def root():
    return {"message": "NetGuard API is running", "docs": "/docs", "health": "/health"}