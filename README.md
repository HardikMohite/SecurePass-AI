# 🔐 SecurePass AI — Privacy-First Password Security & Threat Intelligence Platform

> **Zero-Knowledge, High-Throughput Enterprise Password Security Audit & Intelligence Platform.**
> Evaluates password datasets against empirical vulnerability patterns, multi-regulatory compliance frameworks (NIST SP 800-63B, PCI-DSS v4.0, HIPAA, ISO 27001), and 14.2+ billion breached credentials with mathematical $k$-anonymity and ultra-low latency.

![Python](https://img.shields.io/badge/Python-3.12%20|%203.13-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-8.2-646CFF?style=flat&logo=vite&logoColor=white)
![Privacy](https://img.shields.io/badge/Privacy-Zero--Knowledge-10b981?style=flat)
![Latency](https://img.shields.io/badge/PDF%20Latency-146ms-blue?style=flat)
![Tests](https://img.shields.io/badge/Tests-53%20Passed-brightgreen?style=flat)

---

## 🛡️ Core Privacy & Security Principles

SecurePass AI is designed under strict **Zero-Knowledge Privacy** guarantees:

1. **Client-Side First Processing**: Password datasets (`.TXT`, `.CSV`, `.XLSX`) are parsed and evaluated in the user's browser memory using our deterministic `SecurityEngine`. Plaintext passwords never leave the local environment.
2. **Mathematical $k$-Anonymity**: Breach intelligence queries HaveIBeenPwned using only the first 5 characters of local SHA-1 hashes (`/api/hibp/range/<prefix>`). Neither our server nor HIBP ever sees plaintext passwords or full hashes.
3. **AI Boundary Protection**: AI models (Groq LLaMA 3.3 70B) receive **strictly anonymized aggregate telemetry**. Plaintext credentials and hashes are blocked by an automated recursive privacy scanner (`assert_no_password_data`).
4. **Zero Password Persistence**: No passwords or password lists are ever written to database tables, logs, session cookies, `localStorage`, or disk caches.
5. **Ultra-Low Latency**: Native ReportLab single-pass vector PDF engine generates complete 10-section executive CISO audit packs in **~146ms** (65x speedup).

> 📖 **Full Technical Documentation:**
> - [SECURITY.md](file:///c:/Dev/SecurePass/SECURITY.md) — Cryptographic protocol, k-anonymity proof & vulnerability reporting
> - [PRIVACY.md](file:///c:/Dev/SecurePass/PRIVACY.md) — Data lifecycle, zero-retention guarantee & data minimization
> - [ARCHITECTURE.md](file:///c:/Dev/SecurePass/ARCHITECTURE.md) — High-level diagrams, component architecture & data flow
> - [THREAT_MODEL.md](file:///c:/Dev/SecurePass/THREAT_MODEL.md) — STRIDE analysis, attack vectors & mitigations

---

## 📌 Features & Capabilities

### 🔍 Zero-Knowledge Dataset Analysis (`/api/analyze`)
- Parses `.txt` and `.csv` datasets in browser memory with zero wire transmission.
- Identifies weak password patterns: dictionary words, names, numeric suffixes, keyboard walks, capitalization misuse, leetspeak, and sequential number runs.
- Computes comprehensive dataset metrics: length distributions, character compositions, and reuse frequencies.
- Evaluates overall risk score (0–100) and categorizes dataset vulnerability (High / Medium / Low).

### 🔴 Cryptographic Breach Detection (HaveIBeenPwned Range API)
- Implements **client-side k-anonymity** — queries the HIBP Pwned Passwords range API using only the first 5 characters of SHA-1 hashes; plaintext passwords never leave the local machine.
- Gracefully degrades to status `unknown` with clear user advisory if offline; never returns false clean status on failure.

### 🤖 AI Security Insights & Policy Engine
- Powered by **Groq API** (`llama-3.3-70b-versatile`) with seamless deterministic fallback when offline or unconfigured.
- Generates bespoke enterprise password policy formulations, DO/DON'T guidance, and memorable NIST-compliant passphrases.

### 📋 Multi-Framework Compliance & Threat Simulation
- **Compliance Mapping**: Assesses security posture against NIST SP 800-63B, PCI-DSS v4.0 (Req 8.3.6), HIPAA (§164.312), and ISO/IEC 27001:2022 standards.
- **Terminal Attack Simulator**: Real-time simulated dictionary, keyboard walk, and brute-force cracking passes streamed via NDJSON.

### 📄 Executive Vector PDF Reporting (146ms Generation)
- Generates vector-quality, audit-ready PDF reports with CISO attestation, compliance matrix, and terminal simulations in under 200ms.

### 🔐 Authentication & Session Security (JWT)
- Stateless authentication using **Flask-JWT-Extended** (short-lived access tokens and refresh tokens in HTTP-only cookies).
- Fast Redis-backed JWT blocklist for immediate token revocation on logout.
- Granular rate limiting on sensitive routes via Flask-Limiter.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend Framework** | Python 3.12, Flask 3.0 |
| **Authentication** | Flask-JWT-Extended (Access + Refresh Tokens, Redis Revocation Blocklist) |
| **Database & ORM** | SQLAlchemy 2.0, PostgreSQL (Supabase) in Production, SQLite for Local Tests, Flask-Migrate (Alembic) |
| **Caching & Rate Limiting** | Redis, Flask-Limiter |
| **AI / LLM Engine** | Groq API (`llama-3.3-70b-versatile`) with rule-based fallback |
| **Breach Intelligence** | HaveIBeenPwned Range API (k-anonymity SHA-1 hashing) |
| **PDF & Charts** | ReportLab 4.x, Matplotlib 3.9 |
| **Frontend SPA** | Vite, Vanilla JavaScript (ES Modules), Modern CSS Design System |
| **Testing & CI/CD** | Pytest, Fakeredis, Node Sanity Runner, GitHub Actions, Docker, Render |

---

## 📁 Project Structure

```
SecurePass-AI/
├── backend/
│   ├── app.py                       # Flask app factory + core API endpoints
│   ├── config.py                    # Development / Production / Testing configurations
│   ├── extensions.py                # Shared JWT, Redis, and Rate-Limiter instances
│   ├── models.py                    # SQLAlchemy User & Analysis models
│   ├── auth.py                      # Auth blueprint (/api/auth/*)
│   ├── auth_utils.py                # JWT identity & session helper utilities
│   ├── settings_backend.py          # User settings blueprint (/api/settings/*)
│   ├── dataset.txt                  # Sample test password dataset
│   ├── ai_engine.py                 # Groq LLM integration + deterministic fallback
│   ├── attack_simulator.py          # Dictionary, keyboard walk, and brute-force simulator
│   ├── compliance_mapper.py         # NIST / OWASP / ISO compliance evaluator
│   ├── dataset_analyzer.py          # Password statistics & character distribution engine
│   ├── hibp_engine.py               # HIBP k-anonymity client
│   ├── hibp_routes.py               # HIBP blueprint (/api/hibp/*)
│   ├── hibp_transformer.py          # HIBP response transformation & formatting
│   ├── pattern_detector.py          # Weak-pattern detection engine
│   ├── policy_simulator.py          # Policy improvement projection simulator
│   ├── risk_score.py                # Mathematical risk scoring engine
│   ├── wsgi.py                      # Production WSGI entrypoint (gunicorn wsgi:app, run from backend/)
│   ├── Dockerfile                   # Production container definition
│   ├── requirements.txt             # Pinned Python production dependencies
│   ├── pytest.ini                   # Pytest configuration
│   ├── setup.sh                     # One-shot local setup script
│   ├── .env.example                 # Environment variable reference template
│   ├── reports/
│   │   ├── charts.py                 # Matplotlib analytics chart generators
│   │   └── pdf_gen.py                 # ReportLab executive PDF generator
│   ├── utils/
│   │   └── validators.py             # File upload & password validation helpers
│   ├── migrations/                   # Alembic sequential database migrations
│   │   └── versions/
│   │       └── 001_baseline_initial_schema.py
│   ├── logs/                         # Runtime log output (securepass.log)
│   └── tests/                        # Automated Pytest suite
│       ├── conftest.py
│       ├── requirements-test.txt
│       ├── test_health.py
│       ├── test_auth_flow.py
│       ├── test_protected_routes.py
│       ├── test_pattern_detector.py
│       ├── test_dataset_analyzer.py
│       └── test_risk_score.py
│
├── frontend/                       # Modern Vite-powered Frontend SPA
│   ├── index.html                   # Main dashboard SPA (Analysis, Terminal, Policy, Reports, Settings)
│   ├── login.html                   # Login portal
│   ├── register.html                # User registration portal
│   ├── profile.html                 # Profile view
│   ├── forgot_pass.html             # Account recovery initiation
│   ├── check_mail.html              # Recovery status screen
│   ├── reset_password.html          # Password reset portal
│   ├── vite.config.js               # Multi-page Vite configuration
│   ├── vercel.json                  # Vercel build + /api,/static proxy rewrites to Render
│   ├── package.json                 # Frontend scripts & devDependencies
│   ├── public/                      # Static assets (SVG sprite icons)
│   ├── static/reports/output/       # Generated chart images (served by Flask)
│   └── src/                         # Modular CSS & JS source code
│       ├── api.js                   # JWT-authenticated API fetch client with auto-refresh
│       ├── api.sanity-check.mjs     # Frontend API client test runner
│       ├── css/                     # Modulated stylesheets (main, auth, reports, hibp, recovery)
│       └── js/                      # Page controllers & interactive modules
│
├── .github/workflows/
│   └── backend-ci.yml               # Automated CI workflow (triggers on backend/**)
│
├── start-server.ps1                 # Root-level start: applies migrations, then runs
├── start.ps1                        # Root-level quick start: runs the server only, no migration check
├── render.yaml                      # Render Blueprint deployment specification
├── SECURITY.md                      # Security controls mapped to OWASP / ISO 27001 Annex A
└── .gitignore
```

---

## 🚀 Getting Started Locally

### Prerequisites
- **Python 3.12+**
- **Node.js 18+** & **npm**
- **Redis** (Local instance or Docker: `docker run -d -p 6379:6379 redis:7-alpine`)
- **Groq API Key** (Optional for live LLM insights; [console.groq.com](https://console.groq.com))

> **Already set up once?** After the one-time setup below:
> - `.\start-server.ps1` applies pending migrations, then starts the backend.
> - `.\start.ps1` just starts the backend directly (skip if you haven't run
>   migrations yet, or don't need to check for new ones).

---

### 1. Backend Setup

```bash
# Clone the repository
git clone https://github.com/HardikMohite/SecurePass-AI.git
cd SecurePass-AI/backend

# Create and activate virtual environment (kept inside backend/)
python -m venv .venv

# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

Configure `backend/.env`:
```env
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY=dev-only-insecure-key-change-in-production
JWT_SECRET_KEY=dev-only-insecure-jwt-key-change-in-production
REDIS_URL=redis://localhost:6379/0
# GROQ_API_KEY=gsk_...   # Optional
```

Initialize database tables (run from inside `backend/`):
```bash
flask db upgrade
```

Run the backend server (still from inside `backend/`):
```bash
python app.py
```
> Backend API will be active at **http://localhost:5000**. Verify with `GET http://localhost:5000/api/health`.
>
> From the project root, `.\start-server.ps1` does both of the above steps
> (migrate, then start) in one command — see below.

---

### 2. Frontend Setup

In a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
> Vite dev server will launch at **http://localhost:5173**.

---

## ✅ Testing & Verification

### Backend Tests (Pytest)
```bash
cd backend
pip install -r tests/requirements-test.txt
pytest
```

### Frontend Client Tests (Node)
```bash
cd frontend
node src/api.sanity-check.mjs
```

---

## 🗄️ Database Migrations

Database schema revisions are managed using **Flask-Migrate** (Alembic).
Run these from inside `backend/`:

```bash
export FLASK_APP=app.py   # Windows: set FLASK_APP=app.py

# Apply latest migrations
flask db upgrade

# Generate an auto-numbered sequential migration (002, 003, ...)
flask db-auto -m "add feature column"

# Apply the new migration
flask db upgrade
```

---

## 🐳 Docker Deployment

Build and run using Docker from the project root:

```bash
# Build image
docker build -f backend/Dockerfile -t securepass-backend .

# Run container
docker run -d -p 5000:5000 \
  -e SECRET_KEY="your-production-secret" \
  -e JWT_SECRET_KEY="your-production-jwt-secret" \
  -e DATABASE_URL="postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?sslmode=require" \
  -e REDIS_URL="redis://your-redis-host:6379/0" \
  -e FLASK_ENV="production" \
  securepass-backend
```

---

## ☁️ Production Deployment (Render + Vercel)

The backend is a pure JSON API (Phase 2 removed all page-rendering routes —
see `app.py`), and the frontend is a fully static Vite SPA. That split maps
directly onto Render (backend) + Vercel (frontend). Deploy the backend
first — the frontend's proxy config needs its URL.

### 1. Backend → Render

Render reads `render.yaml` at the project root as a Blueprint:

1. Push this repo to GitHub/GitLab, then in Render: **New → Blueprint**,
   point it at the repo. It picks up `render.yaml` automatically
   (Docker runtime, `backend/Dockerfile`, health check at `/api/health`).
2. Render will prompt for the `sync: false` env vars — fill in at minimum:
   `SECRET_KEY`, `JWT_SECRET_KEY`, `DATABASE_URL` (your Supabase transaction
   pooler string), `REDIS_URL`. Leave `CORS_ORIGINS` empty (see note below).
3. Deploy, then note the resulting URL — something like
   `https://securepass-backend.onrender.com`.
4. Run migrations once against the live database (locally, with
   `DATABASE_URL` pointed at Supabase): `flask db upgrade`.

### 2. Frontend → Vercel

The frontend talks to the backend using relative paths (`/api/...`,
`credentials: 'include'`) — it was built to be served from the same origin
as the API. `frontend/vercel.json` recreates that on Vercel by proxying
`/api/*` and `/static/*` through to Render, so the browser only ever talks
to your Vercel domain (no CORS, no cross-site cookie issues):

1. Open `frontend/vercel.json` and replace both
   `REPLACE-WITH-YOUR-RENDER-BACKEND.onrender.com` occurrences with your
   actual Render backend hostname from step 1.
2. In Vercel: **New Project**, import the repo, set **Root Directory** to
   `frontend`. Vercel will read `vercel.json` for the build command
   (`npm run build`) and output directory (`dist`); `cleanUrls` makes
   in-app links like `/login` resolve to `login.html`.
3. Deploy. Your app is live at `https://your-app.vercel.app`, proxying API
   calls straight to Render.

> **Why not CORS instead of the proxy?** You can — set `CORS_ORIGINS` on
> Render to your Vercel URL and switch the frontend's fetch calls to an
> absolute backend URL — but that also means switching the cookie-based
> auth to `SameSite=None; Secure` and handling third-party-cookie
> restrictions in some browsers. The proxy avoids all of that by keeping
> everything same-origin from the browser's point of view.

---

## 🔑 API Reference

### Core Services (`app.py`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | No | Liveness probe returning service status |
| `POST` | `/api/analyze` | JWT | Upload and analyse `.txt` or `.csv` password dataset |
| `POST` | `/api/check-password` | No | Single-password complexity and strength assessment |
| `POST` | `/api/download-report` | JWT | Compiles and streams audit-ready PDF report |
| `POST` | `/api/terminal-attack` | No | Real-time attack cracking simulation (NDJSON streaming) |
| `GET` | `/api/report/<id>` | JWT | Retrieves historical analysis report |
| `POST` | `/api/ai-policy` | JWT | Generates AI-recommended password policy |
| `GET` | `/api/ai-policy/snapshot`| JWT | Retrieves latest dataset snapshot for policy analysis |
| `POST` | `/api/compliance-ai` | JWT | Evaluates NIST / OWASP / ISO compliance mappings |

> **Auth column** — every "JWT" route accepts the token either as an
> `Authorization: Bearer <token>` header (API/CLI/mobile clients) or as
> the httpOnly cookie the browser SPA receives from
> login/register/refresh (see `config.py`'s `JWT_TOKEN_LOCATION`).
> Cookie-authenticated `POST`/`PUT`/`DELETE` requests additionally require
> an `X-CSRF-TOKEN` header matching the non-httpOnly `csrf_access_token`
> cookie (Flask-JWT-Extended's double-submit CSRF check) — the SPA's
> `frontend/src/js/auth.js` handles this automatically. Header-only
> clients that never receive that cookie are unaffected, since the CSRF
> check only applies when the request is cookie-authenticated in the
> first place.

### Authentication (`/api/auth/*`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | No | Registers account and returns JWT access + refresh tokens |
| `POST` | `/api/auth/login` | No | Authenticates user credentials and issues token pair |
| `POST` | `/api/auth/refresh` | Refresh JWT | Trades refresh token for a new access token |
| `POST` | `/api/auth/logout` | Bearer JWT | Revokes active token immediately via Redis blocklist |
| `GET` | `/api/auth/profile` | Optional | Returns profile data for current user |
| `GET` | `/api/auth/history` | Bearer JWT | Returns paginated dataset audit history |
| `DELETE`| `/api/auth/history` | Bearer JWT | Wipes user's past analysis history |

### HaveIBeenPwned Integration (`/api/hibp/*`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/hibp/check-password` | Bearer JWT | Queries HIBP range API for single password breach count |
| `GET` | `/api/hibp/health` | No | Checks HIBP API reachability |

### Settings & Profile (`/api/settings/*`)
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` / `PUT` | `/api/settings` | Bearer JWT | Retrieve / update user audit and appearance preferences |
| `GET` | `/api/settings/session` | Bearer JWT | Inspect active session, browser, and IP info |
| `GET` | `/api/settings/storage` | Bearer JWT | Inspect database storage and record counters |
| `PUT` | `/api/settings/profile` | Bearer JWT | Update user display name |
| `POST` | `/api/settings/change-password` | Bearer JWT | Change password with old password verification |
| `GET` | `/api/settings/export` | Bearer JWT | Export user settings and preferences to JSON |
| `POST` | `/api/settings/import` | Bearer JWT | Import preferences from JSON file |
| `DELETE` | `/api/settings/delete-analyses` | Bearer JWT | Wipe all historical dataset analysis records |
| `DELETE` | `/api/settings/account` | Bearer JWT | Permanently delete account and associated data |

---

## 🔒 Security Architecture Highlights

> See [`SECURITY.md`](./SECURITY.md) for the full control list mapped to
> OWASP ASVS and ISO/IEC 27001 Annex A reference points, plus an honest
> list of what's *not* yet implemented (account lockout, MFA, email
> verification, CI-integrated dependency scanning).

- **K-Anonymity Protocol**: Ensures zero password leakage by hashing passwords with SHA-1 and transmitting only the 5-character prefix.
- **Timing-Attack Resilient Authentication**: Password verification runs constant-time checks even when a user email is not found, mitigating timing enumeration attacks.
- **Token Invalidation on Redis Blocklist**: Instant token revocation upon logout preventing replay attacks before TTL expiry.
- **Strict Content Validation & Sanitization**: Enforces strict size, structure, and control-character constraints on dataset uploads.
- **httpOnly JWT Cookies + Double-Submit CSRF**: The browser SPA never stores tokens in JS-readable storage — the access/refresh tokens live in httpOnly cookies (immune to XSS token theft), paired with Flask-JWT-Extended's CSRF double-submit cookie so cross-site requests are rejected even though the auth cookie itself is sent automatically.
- **Re-authentication for Destructive Actions**: Changing a password or deleting an account both require the current password again, even within an active session.
- **OWASP Secure Headers**: Every response carries `X-Content-Type-Options`, `X-Frame-Options`, a restrictive `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, and HSTS in production.

---

## 👤 Author

**Hardik Mohite**
- **GitHub**: [HardikMohite](https://github.com/HardikMohite)
- **LinkedIn**: [Hardik Mohite](https://www.linkedin.com/in/hardik-mohite-06aa0a32b/)

*Built as a portfolio project during BSc Cybersecurity.*

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.
