# 🛡️ NetGuard — Network Security Monitor

> A full-stack web application for monitoring your local network, detecting threats,
> looking up real CVEs, and getting AI-powered remediation advice in real time.

Built as a Final Year Project (PFE) combining **software engineering** and **cybersecurity**.

🔗 **Live Demo:** https://netguard-peach.vercel.app
⚙️ **Backend API Docs:** https://netguard-production-4f1d.up.railway.app/docs

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USER'S MACHINE                        │
│                                                              │
│   ┌──────────────┐    ┌──────────────────────────────────┐  │
│   │ Local Agent  │    │         Browser                  │  │
│   │ (agent.py)   │    │   React + Vite Frontend          │  │
│   │              │    │                                  │  │
│   │ - ARP scan   │    │  ┌──────┐ ┌──────┐ ┌────────┐   │  │
│   │ - Port scan  │    │  │Dash  │ │Ports │ │AI Chat │   │  │
│   │ - OS guess   │    │  └──────┘ └──────┘ └────────┘   │  │
│   └──────┬───────┘    └──────────────┬───────────────────┘  │
│          │ POST /api/scan/agent       │ REST + WebSocket     │
└──────────┼────────────────────────────┼─────────────────────┘
           │                            │
           ▼                            ▼
┌──────────────────────────────────────────────────────────────┐
│              FastAPI Backend (Railway)                        │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │  /auth   │ │  /scan   │ │  /cve    │ │    /chat      │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────┬───────┘  │
│                                                  │          │
│  ┌─────────────────────┐   ┌────────────────┐    │          │
│  │   SQLite Database   │   │ WebSocket Mgr  │    ▼          │
│  │  (scan history,     │   │ (real-time     │  Google      │
│  │   devices, alerts)  │   │  alerts)       │  Gemini API  │
│  └─────────────────────┘   └────────────────┘              │
└──────────────────────────────────────────────────────────────┘
           │                    │
           ▼                    ▼
    HaveIBeenPwned API     NVD / CVE API
     (k-anonymity)        (vulnerability DB)
```

### Why a Local Agent?

A web server lives on the internet — it **cannot see your home LAN**.
The local agent runs on your machine, scans your network, and pushes results to the backend.
This is the same architecture used by tools like Nessus and Qualys.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Network Scanner** | ARP host discovery + Nmap port scanning with OS fingerprinting |
| 🚨 **Threat Detection** | 25+ suspicious/backdoor port flags, per-device risk scoring (0–100) |
| 🛡️ **CVE Lookup** | Real-time NVD vulnerability search per detected service/version or port |
| 🤖 **AI Advisor** | Google Gemini 2.5 Flash — gives advice based on your actual scan results |
| 🔐 **Password Breach Check** | HaveIBeenPwned via k-anonymity — password never leaves your browser |
| 📡 **Real-time Alerts** | WebSocket push notifications the moment a threat is detected |
| 📧 **Email Verification** | Brevo-powered transactional email for account verification |
| 🔒 **JWT Auth** | httpOnly cookies — no token in localStorage, XSS-resistant by design |
| 🐳 **Docker Support** | One-command local dev with Docker Compose |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- [Nmap](https://nmap.org/download) installed on your machine
- A NetGuard account — register at https://netguard-peach.vercel.app

---

### Option A — Use the Live Deployment *(Recommended)*

The backend and frontend are already deployed. You only need to run the local agent.

**1. Register an account**
Go to https://netguard-peach.vercel.app and create an account.

**2. Download the agent**
Go to the **Agent Setup** page in the dashboard — it generates a pre-filled `.env` for your account and guides you through setup.

Or download manually:
- [`agent.py`](https://raw.githubusercontent.com/kamikaz-tn/netguard/main/agent/agent.py)
- [`requirements.txt`](https://raw.githubusercontent.com/kamikaz-tn/netguard/main/agent/requirements.txt)

**3. Configure the agent**

Create a `.env` file in the same folder as `agent.py`:

```env
BACKEND_URL=https://netguard-production-4f1d.up.railway.app
AGENT_SECRET=netguard_agent_secret_2026
USER_ID=<your user ID shown in the dashboard>
NETWORK_RANGE=
SCAN_TYPE=full
```

**4. Install dependencies and run**

```powershell
pip install -r requirements.txt

# Single scan (run as Administrator on Windows):
python agent.py --scan

# Watch mode — scan every 5 minutes:
python agent.py --watch --interval 300
```

> **Why Administrator?** ARP scanning requires raw socket access.
> On Linux/Mac, use `sudo python agent.py --scan`.

**5. View results**
Open your dashboard at https://netguard-peach.vercel.app — results appear automatically.

---

### Option B — Run Locally *(Development)*

**1. Clone the repo**

```bash
git clone https://github.com/kamikaz-tn/netguard
cd netguard
```

**2. Start the backend**

```bash
# With Docker (recommended):
docker compose up --build

# Or manually:
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Create `backend/.env`:

```env
GEMINI_API_KEY=your-gemini-key
SECRET_KEY=your-random-secret
AGENT_SECRET=netguard_agent_secret_2026
DATABASE_URL=sqlite+aiosqlite:///./netguard.db
FRONTEND_ORIGIN=http://localhost:5173
```

API docs at: **http://localhost:8000/docs**

**3. Start the frontend**

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

**4. Run the agent (local mode)**

```bash
cd agent
# Edit agent/.env and set BACKEND_URL=http://localhost:8000
python agent.py --scan
```

---

## 📁 Project Structure

```
netguard/
├── backend/
│   ├── main.py                    # FastAPI app entry point + rate limiting
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── core/
│   │   ├── config.py              # Settings (pydantic-settings)
│   │   ├── database.py            # Async SQLAlchemy + session
│   │   └── auth.py                # JWT + password hashing
│   ├── models/
│   │   ├── db_models.py           # SQLAlchemy ORM tables
│   │   └── schemas.py             # Pydantic request/response schemas
│   ├── routers/
│   │   ├── auth.py                # Register / login / email verification
│   │   ├── scan.py                # Scan trigger + agent data ingestion
│   │   ├── devices.py             # Trusted devices + kick commands
│   │   ├── password.py            # HIBP k-anonymity proxy
│   │   ├── chat.py                # AI advisor (Gemini)
│   │   ├── alerts.py              # WebSocket + alert history
│   │   └── cve.py                 # NVD CVE lookup proxy (with caching)
│   └── services/
│       ├── scanner.py             # ARP + Nmap scanning engine
│       ├── risk_analyzer.py       # Threat analysis + scoring
│       ├── ai_advisor.py          # Google Gemini 2.5 Flash integration
│       └── websocket_manager.py   # Real-time alert broadcasting
│
├── agent/
│   ├── agent.py                   # Local scanning agent
│   ├── requirements.txt
│   └── .env                       # BACKEND_URL + AGENT_SECRET (never commit)
│
├── frontend/
│   ├── src/
│   │   ├── services/
│   │   │   ├── api.js             # Auth, scan, chat, WebSocket calls
│   │   │   └── cve.js             # CVE lookup helpers + severity colors
│   │   ├── pages/
│   │   │   ├── Login.jsx
│   │   │   ├── Overview.jsx
│   │   │   ├── Devices.jsx
│   │   │   ├── PortScan.jsx       # Port results + inline CVE panel
│   │   │   ├── PwnedCheck.jsx
│   │   │   ├── AIAdvisor.jsx
│   │   │   ├── AgentSetup.jsx     # Agent download + per-user .env generation
│   │   │   └── Verify.jsx         # Email verification handler
│   │   └── components/
│   │       └── Layout.jsx
│   ├── vercel.json
│   └── vite.config.js
│
└── docker-compose.yml
```

---

## 🔌 API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | ❌ | Create account |
| POST | `/api/auth/login` | ❌ | Get JWT (httpOnly cookie) |
| GET | `/api/auth/me` | ✅ | Current user info |
| GET | `/api/auth/verify-email` | Token | Verify email address |
| POST | `/api/scan/start` | ✅ | Trigger server-side scan |
| POST | `/api/scan/agent` | Secret | Agent pushes scan data |
| GET | `/api/scan/results` | ✅ | Scan history |
| GET | `/api/scan/{id}` | ✅ | Scan detail |
| GET | `/api/devices/trusted` | ✅ | Trusted device list |
| POST | `/api/devices/trust` | ✅ | Mark device as trusted |
| DELETE | `/api/devices/trust/{mac}` | ✅ | Untrust device |
| POST | `/api/devices/kick` | ✅ | Kick device (via agent) |
| POST | `/api/password/check` | ❌ | HIBP k-anonymity proxy |
| GET | `/api/password/tips` | ❌ | Password best practices |
| POST | `/api/chat/message` | ✅ | AI advisor chat |
| GET | `/api/cve/lookup` | ✅ | CVE search by service/version |
| GET | `/api/cve/port/{port}` | ✅ | CVE lookup by port number |
| GET | `/api/alerts` | ✅ | Alert history |
| PATCH | `/api/alerts/read-all` | ✅ | Mark all alerts as read |
| WS | `/ws/{user_id}?token=...` | JWT | Real-time alert stream |

---

## 🔐 Security Features

### Network Scanner
- ARP-based host discovery (Layer 2 — more reliable than ICMP ping)
- Nmap port scanning with service/version detection
- 25+ suspicious/backdoor port detection (Metasploit 4444, Back Orifice 31337, etc.)
- Per-device risk scoring (0–100)
- OS fingerprinting (heuristic)

### CVE Lookup
- Queries the NVD (National Vulnerability Database) via the CVE 2.0 API
- Results cached server-side for 1 hour to avoid NVD rate limits
- Supports lookup by service name + version, or by known port number
- Inline CVE panel in the Port Scan page with CVSS score rings

### Password Breach Check
Uses **k-anonymity** — your password never leaves your browser:
1. Browser hashes the password with SHA-1
2. Only the first 5 characters of the hash are sent to the API
3. API fetches matching hashes from HaveIBeenPwned
4. Browser checks locally whether the full hash appears in the results

### AI Advisor
Gemini is given your actual scan results as context, enabling it to give
specific advice like *"Port 4444 is open on 192.168.1.14 — here's exactly what to do."*

### Real-time Alerts
WebSocket connection pushes threat alerts to the browser instantly when
the agent detects new issues — no polling required.

### Auth & Session Security
- JWTs stored in **httpOnly cookies** — never exposed to JavaScript
- No tokens in `localStorage` or `sessionStorage`
- 24-hour token expiry
- Rate limiting (200 req/min) on all endpoints via SlowAPI

---

## 🧪 Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | React 18 + Vite | Fast dev, modern UI |
| Styling | Custom CSS (cyberpunk dark theme) | Unique look for PFE demo |
| Backend | Python 3.11 + FastAPI | Async, auto-docs, type-safe |
| Database | SQLite (aiosqlite) | Simple, zero-config |
| ORM | SQLAlchemy 2.0 (async) | Type-safe, async-native |
| Auth | JWT (python-jose) + bcrypt | Industry standard |
| Scanning | Nmap + Scapy | Industry-standard tools |
| AI | Google Gemini 2.5 Flash | Free tier, high quality |
| CVE Data | NVD API (CVE 2.0) | Official vulnerability database |
| Real-time | WebSockets | Low-latency push alerts |
| Email | Brevo (transactional) | Reliable email delivery |
| Rate Limiting | SlowAPI | Protects all endpoints |
| Containers | Docker + Compose | One-command local dev |
| CI/CD | GitHub → Railway + Vercel | Auto-deploy on push |

---

## ☁️ Deployment

| Service | Platform | URL |
|---------|----------|-----|
| Frontend | Vercel | https://netguard-peach.vercel.app |
| Backend | Railway | https://netguard-production-4f1d.up.railway.app |
| Agent | Runs locally | Pushes to Railway |

Every `git push` to `main` automatically redeploys both Railway and Vercel.

---

## 🔒 Environment Variables

**Backend (`backend/.env` or Railway dashboard):**

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing secret |
| `AGENT_SECRET` | Shared secret for agent authentication |
| `GEMINI_API_KEY` | Google AI Studio API key |
| `DATABASE_URL` | SQLite or Postgres connection string |
| `FRONTEND_ORIGIN` | CORS allowed origin |
| `BREVO_API_KEY` | Brevo email API key |
| `BREVO_SENDER_EMAIL` | Verified sender address |

> ⚠️ **Never commit secrets.** Use Railway's environment variable dashboard for production.

**Agent (`agent/.env`):**

| Variable | Description |
|----------|-------------|
| `BACKEND_URL` | Backend URL (Railway or localhost) |
| `AGENT_SECRET` | Must match the backend value |
| `USER_ID` | Your account's user ID |
| `NETWORK_RANGE` | Optional — auto-detected if blank |
| `SCAN_TYPE` | `full` or `quick` |

---

## 🎓 PFE Presentation Points

1. **Distributed architecture** — separates cloud logic from local network access
2. **Security-first design** — httpOnly cookies, k-anonymity, rate limiting
3. **Real CVE data** — live NVD integration, not hardcoded threat lists
4. **AI with context** — Gemini receives your actual topology, not generic questions
5. **Production deployment** — live CI/CD pipeline, not just a localhost demo

---

## 👤 Author

**Mehdi** — Final Year Project (PFE)
GitHub: [kamikaz-tn/netguard](https://github.com/kamikaz-tn/netguard)