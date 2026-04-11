# 🛡️ NetGuard — Network Security Monitor
 
> A full-stack web application for monitoring your local network security,
> detecting threats, and getting AI-powered remediation advice.
 
Built as a Final Year Project (PFE) combining **software engineering** and **cybersecurity**.
 
🔗 **Live Demo:** https://netguard-peach.vercel.app
⚙️ **Backend API:** https://netguard-production-4f1d.up.railway.app/docs
 
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
│  │  /auth   │ │  /scan   │ │/password │ │    /chat      │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────┬───────┘  │
│                                                  │          │
│  ┌─────────────────────┐   ┌────────────────┐    │          │
│  │   SQLite Database   │   │ WebSocket Mgr  │    ▼          │
│  │  (scan history,     │   │ (real-time     │  Google      │
│  │   devices, alerts)  │   │  alerts)       │  Gemini API  │
│  └─────────────────────┘   └────────────────┘              │
└──────────────────────────────────────────────────────────────┘
           │
           ▼
    HaveIBeenPwned API (k-anonymity)
```
 
### Why a Local Agent?
A web server lives on the internet — it **cannot see your home LAN**.
The local agent runs on your machine, scans your network, and pushes results
to the backend. This is the same architecture used by tools like Nessus and Qualys.
 
---
 
## 🚀 Quick Start
 
### Prerequisites
- Python 3.11+
- Node.js 20+
- [Nmap](https://nmap.org/download) installed on your machine
- A NetGuard account (register at https://netguard-peach.vercel.app)
 
---
 
### Option A — Use the Live Deployment (Recommended)
 
The backend and frontend are already deployed. You only need to run the local agent.
 
**1. Register an account**
Go to https://netguard-peach.vercel.app and create an account.
 
**2. Download the agent**
Go to the **Run Scan** page in the dashboard — it will guide you through downloading and running the agent, including a consent step.
 
Or download manually:
- [`agent.py`](https://raw.githubusercontent.com/kamikaz-tn/netguard/refs/heads/main/agent/agent.py)
- [`requirements.txt`](https://raw.githubusercontent.com/kamikaz-tn/netguard/refs/heads/main/agent/requirements.txt)
 
**3. Configure the agent**
 
Create a file called `.env` in the same folder as `agent.py`:
```
BACKEND_URL=https://netguard-production-4f1d.up.railway.app
AGENT_SECRET=netguard_agent_secret_2026
USER_ID=1
NETWORK_RANGE=
SCAN_TYPE=full
```
 
> Set `USER_ID` to your account's user ID (shown after login in the API).
 
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
 
### Option B — Run Locally (Development)
 
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
```
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
│   ├── main.py                    # FastAPI app entry point
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
│   │   ├── auth.py                # POST /api/auth/register|login
│   │   ├── scan.py                # POST /api/scan/start|agent, GET /api/scan/*
│   │   ├── devices.py             # GET/POST/DELETE /api/devices/*
│   │   ├── password.py            # POST /api/password/check
│   │   ├── chat.py                # POST /api/chat/message
│   │   └── alerts.py              # WebSocket /ws/{user_id}, GET /api/alerts
│   └── services/
│       ├── scanner.py             # ARP + Nmap scanning engine
│       ├── risk_analyzer.py       # Threat analysis + scoring
│       ├── ai_advisor.py          # Google Gemini 2.5 Flash integration
│       └── websocket_manager.py   # Real-time alert broadcasting
│
├── agent/
│   ├── agent.py                   # Local scanning agent (run on your machine)
│   ├── requirements.txt
│   └── .env                       # BACKEND_URL + AGENT_SECRET (never commit)
│
├── frontend/
│   ├── src/
│   │   ├── services/
│   │   │   └── api.js             # All API calls (auth, scan, chat, HIBP, WS)
│   │   ├── pages/                 # React page components
│   │   │   ├── Login.jsx
│   │   │   ├── Overview.jsx
│   │   │   ├── Devices.jsx
│   │   │   ├── PortScan.jsx
│   │   │   ├── PwnedCheck.jsx
│   │   │   ├── AIAdvisor.jsx
│   │   │   └── AgentSetup.jsx     # Agent download + setup guide
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
| POST | `/api/auth/login` | ❌ | Get JWT token |
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
| GET | `/api/alerts` | ✅ | Alert history |
| WS | `/ws/{user_id}?token=...` | JWT | Real-time alerts |
 
---
 
## 🔐 Security Features
 
### Network Scanner
- ARP-based host discovery (Layer 2 — more reliable than ping)
- Nmap port scanning with version detection
- 25+ suspicious/backdoor port detection (Metasploit 4444, Back Orifice 31337, etc.)
- Per-device risk scoring (0–100)
- OS fingerprinting (heuristic)
 
### Password Breach Check
Uses **k-anonymity** — your password never leaves your browser:
1. Browser hashes password with SHA-1
2. Only the first 5 characters of the hash are sent to the API
3. API fetches matching hashes from HaveIBeenPwned
4. Browser checks locally if the full hash is in the results
 
### AI Advisor
Gemini is given your actual scan results as context, enabling it to give
specific advice like *"Port 4444 is open on 192.168.1.14 — here's exactly what to do."*
 
### Real-time Alerts
WebSocket connection pushes threat alerts to the browser instantly when
the agent detects new issues — no polling required.
 
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
| Real-time | WebSockets | Low-latency push alerts |
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
 
## 🎓 PFE Presentation Points
 
1. **Client-Agent-Server Architecture** — why a local agent is necessary for LAN scanning
2. **k-Anonymity** — mathematical privacy guarantee for password checking
3. **ARP vs ICMP** — why ARP scanning is more reliable on LANs
4. **JWT Authentication** — stateless auth for REST APIs
5. **WebSocket vs Polling** — real-time architecture trade-offs
6. **Async Python** — how FastAPI handles concurrent scans efficiently
7. **AI Context Injection** — how scan data is embedded in the Gemini system prompt
8. **Cloud + Local hybrid** — separating concerns between cloud backend and local agent
 
---
 
## ⚠️ Known Limitations
 
- **"Run Scan" button** triggers the local agent setup guide — server-side scanning is not possible from Railway (no LAN access)
- **SQLite** resets if Railway redeploys without a persistent volume — use the agent to re-push scan data
- **Windows terminal** shows Unicode errors in agent logs — cosmetic only, scans work fine
- **Gemini free tier** may return 429 rate limit errors under heavy use — wait a few seconds and retry
 
---
 
## 🛣️ Roadmap
 
- [ ] CVE lookup per detected service version (NVD API)
- [ ] PDF report export (scan history)
- [ ] DNS leak test
- [ ] Scheduled scans (cron / Windows Task Scheduler)
- [ ] Email alerts for new threats
- [ ] Replace SQLite with PostgreSQL for persistent cloud storage
- [ ] Custom domain
 
---
 
## 📄 License
 
MIT License — free to use for your PFE and beyond.