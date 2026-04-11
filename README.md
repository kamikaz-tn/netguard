# 🛡️ NetGuard — Network Security Monitor

> A full-stack web application for monitoring your local network security,
> detecting threats, and getting AI-powered remediation advice.

Built as a Final Year Project (PFE) combining **software engineering** and **cybersecurity**.

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USER'S MACHINE                        │
│                                                              │
│   ┌──────────────┐    ┌──────────────────────────────────┐  │
│   │ Local Agent  │    │         Browser                  │  │
│   │ (agent.py)   │    │   React + Tailwind Frontend      │  │
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
│                    FastAPI Backend                            │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │  /auth   │ │  /scan   │ │/password │ │    /chat      │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────┬───────┘  │
│                                                  │          │
│  ┌─────────────────────┐   ┌────────────────┐    │          │
│  │   SQLite Database   │   │ WebSocket Mgr  │    ▼          │
│  │  (scan history,     │   │ (real-time     │  Anthropic   │
│  │   devices, alerts)  │   │  alerts)       │  Claude API  │
│  └─────────────────────┘   └────────────────┘              │
└──────────────────────────────────────────────────────────────┘
           │
           ▼
    HaveIBeenPwned API (k-anonymity)
    NVD CVE Database (planned)
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
- Docker & Docker Compose
- nmap installed: `sudo apt install nmap` / `brew install nmap`

### 1. Clone and configure

```bash
git clone https://github.com/yourusername/netguard
cd netguard
```

**Backend config:**
```bash
cd backend
cp .env.example .env
# Edit .env and set:
#   ANTHROPIC_API_KEY=sk-ant-...
#   SECRET_KEY=$(openssl rand -hex 32)
#   AGENT_SECRET=some_random_string
```

**Agent config:**
```bash
cd agent
cp .env.example .env
# Edit .env and set:
#   BACKEND_URL=http://localhost:8000
#   AGENT_SECRET=same_string_as_backend
#   USER_ID=1   (set after registering)
```

### 2. Start the backend

```bash
# With Docker (recommended):
docker compose up --build

# Or manually:
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: **http://localhost:8000/docs**

### 3. Start the frontend

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### 4. Run the agent

```bash
cd agent
pip install -r requirements.txt

# Check your setup first:
python agent.py --check-env

# Run a single scan:
sudo python agent.py --scan

# Or watch mode (scan every 5 minutes):
sudo python agent.py --watch --interval 300
```

> **Why sudo?** ARP scanning requires raw socket access. On Linux/Mac this needs root.
> On Windows, run as Administrator.

---

## 📁 Project Structure

```
netguard/
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .env.example
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
│       ├── ai_advisor.py          # Anthropic Claude integration
│       └── websocket_manager.py   # Real-time alert broadcasting
│
├── agent/
│   ├── agent.py                   # Local scanning agent (run on your machine)
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── services/
│   │   │   └── api.js             # All API calls (auth, scan, chat, HIBP, WS)
│   │   ├── pages/                 # React page components
│   │   └── components/            # Reusable UI components
│   └── Dockerfile
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
- Per-device risk scoring
- OS fingerprinting (heuristic)

### Password Breach Check
Uses **k-anonymity** — your password never leaves your browser:
1. Browser hashes password with SHA-1
2. Only first 5 characters of hash sent to API
3. API fetches matching hashes from HaveIBeenPwned
4. Browser checks locally if full hash is in the results

### AI Advisor
Claude is given your actual scan results as context, enabling it to give
specific advice like "Port 4444 is open on 192.168.1.14 on your network —
here's exactly what to do."

### Real-time Alerts
WebSocket connection pushes threat alerts to the browser instantly when
the agent detects new issues — no polling required.

---

## 🧪 Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | React + Vite + Tailwind | Fast dev, modern UI |
| Backend | Python + FastAPI | Async, auto-docs, type-safe |
| Database | SQLite → PostgreSQL | Simple for dev, swap for prod |
| ORM | SQLAlchemy (async) | Type-safe, async-native |
| Auth | JWT (python-jose) + bcrypt | Industry standard |
| Scanning | Nmap + Scapy | Industry-standard tools |
| AI | Anthropic Claude | Best-in-class reasoning |
| Real-time | WebSockets | Low-latency push alerts |
| Containers | Docker + Compose | One-command deployment |

---

## 🎓 PFE Presentation Points

1. **Client-Agent-Server Architecture** — why a local agent is necessary
2. **k-Anonymity** — mathematical privacy guarantee for password checking
3. **ARP vs ICMP** — why ARP scanning is more reliable on LANs
4. **JWT Authentication** — stateless auth for REST APIs
5. **WebSocket vs Polling** — real-time architecture trade-offs
6. **Async Python** — how FastAPI handles concurrent scans efficiently
7. **AI Context Injection** — how scan data is embedded in the system prompt

---

## 🛣️ Roadmap

- [ ] CVE lookup per detected service version (NVD API)
- [ ] PDF report export (scan history)
- [ ] DNS leak test
- [ ] Scheduled scans (cron)
- [ ] Email alerts for new threats
- [ ] Router API integration (TP-Link, ASUS) for real device kicking
- [ ] PostgreSQL + Redis for production deployment
- [ ] Mobile app (React Native)

---

## 📄 License

MIT License — free to use for your PFE and beyond.
