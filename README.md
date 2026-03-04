# 🔐 SecurePass AI

> AI-powered password security analysis platform — built for security teams, red teamers, and compliance officers.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat)

---

## 📌 What is SecurePass AI?

SecurePass AI is a full-stack web application that analyses password datasets for security weaknesses, breach exposure, and compliance gaps. Upload a list of passwords and get back a detailed security report powered by AI — in seconds.

Built as a cybersecurity portfolio project demonstrating real-world concepts including k-anonymity breach checking, compliance mapping, AI-generated policy recommendations, and rate-limited REST APIs.

---

## ✨ Features

### 🔍 Dataset Analysis
- Upload `.txt` or `.csv` password files (up to 16 MB / 10,000 passwords)
- Detects **7 pattern types**: dictionary words, keyboard walks, sequential numbers, name-based, date patterns, repeated characters, common words
- Calculates per-password and dataset-wide **risk scores**
- Risk distribution breakdown — High / Medium / Low

### 🔴 Breach Detection (HaveIBeenPwned)
- Checks passwords against **12+ billion breached credentials**
- Uses **k-anonymity** — only the first 5 characters of the SHA-1 hash are sent, passwords never leave your machine in plaintext
- Severity classification: Critical / High / Medium / Low
- Breach rate statistics and severity distribution charts

### 🤖 AI Security Insights
- Powered by **Groq LLM API** (llama3-based models)
- Generates contextual security recommendations based on your specific dataset
- Recommends a custom **password policy** tailored to your risk profile
- Provides DO / DON'T password examples

### 📋 Compliance Mapping
- Maps your password security posture against:
  - **NIST SP 800-63B** — Digital Identity Guidelines
  - **OWASP** — Application Security risks
  - **ISO/IEC 27001** — Information Security Management
- Status: Compliant / Partial Compliance / Non-Compliant

### 📄 PDF Report Generation
- Downloadable security report with charts, insights, and compliance status
- Generated with ReportLab — no external services required

### 🔎 Quick Password Checker
- Single password strength analysis
- Live strength meter with requirement checklist
- Optional HIBP breach check per password

### 🔐 Authentication
- User registration and login with **Flask-Login**
- Secure session management with HTTPOnly cookies
- Rate-limited auth endpoints (10 req/min)
- CSRF protection via Flask-WTF

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.0, Flask-Login, Flask-Limiter |
| Database | SQLite (dev) / PostgreSQL (prod) via SQLAlchemy |
| AI Engine | Groq API (LLaMA 3) |
| Breach Checking | HaveIBeenPwned Range API (k-anonymity) |
| PDF Generation | ReportLab |
| Charts | Matplotlib |
| Frontend | Vanilla HTML/CSS/JS — no frameworks |
| Fonts | Syne (display) + JetBrains Mono (body) |

---

## 📁 Project Structure

```
SecurePass/
├── app.py                          # Flask app factory + API routes
├── config.py                       # Dev / Prod / Test config classes
├── models.py                       # SQLAlchemy User + Analysis models
├── auth.py                         # Auth blueprint (login, register, logout)
│
├── backend/
│   ├── ai_engine.py                # Groq LLM integration
│   ├── compliance_mapper.py        # NIST / OWASP / ISO mapping
│   ├── dataset_analyzer.py         # Core password statistics
│   ├── hibp_checker.py             # HaveIBeenPwned k-anonymity client
│   ├── hibp_routes.py              # HIBP API blueprint
│   ├── pattern_detector.py         # 7-type pattern detection engine
│   ├── policy_simulator.py         # Policy impact simulation
│   └── risk_score.py               # Risk scoring algorithm
│
├── reports/
│   ├── charts.py                   # Matplotlib chart generation
│   └── pdf_gen.py                  # ReportLab PDF builder
│
├── utils/
│   └── validators.py               # File + password input validators
│
├── frontend/
│   ├── templates/
│   │   ├── index.html              # Main dashboard
│   │   ├── login.html              # Login page
│   │   └── register.html          # Registration page
│   └── static/
│       ├── css/
│       │   ├── main.css            # Dashboard styles + CSS variables
│       │   ├── auth.css            # Auth page styles
│       │   └── hibp.css            # Breach indicator styles
│       ├── js/
│       │   ├── theme.js            # Dark / light theme toggle
│       │   ├── auth.js             # Shared auth utilities
│       │   ├── login.js            # Login page logic
│       │   ├── register.js         # Registration + strength meter
│       │   ├── hibp.js             # HIBP client + result rendering
│       │   └── script.js           # Main dashboard logic
│       └── reports/output/         # Generated charts (auto-created)
│
├── requirements.txt
├── .env                            # Environment variables (never commit)
└── .env.example                    # Template for new developers
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip
- A free [Groq API key](https://console.groq.com) (for AI insights)

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/securepass-ai.git
cd securepass-ai
```

### 2. Create a virtual environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
# Copy the example file
cp .env.example .env
```

Edit `.env` and fill in:
```env
FLASK_ENV=development
SECRET_KEY=your_generated_key_here    # python -c "import secrets; print(secrets.token_hex(32))"
SECUREPASS_GROQ_API_KEY=gsk_...       # from console.groq.com (free)
```

### 5. Run the application
```bash
python app.py
```

Open your browser at **http://localhost:5000**

---

## 🔑 API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/` | No | Main dashboard |
| `GET` | `/login` | No | Login page |
| `GET` | `/register` | No | Registration page |
| `POST` | `/api/auth/register` | No | Create account |
| `POST` | `/api/auth/login` | No | Sign in |
| `POST` | `/api/auth/logout` | Yes | Sign out |
| `GET` | `/api/auth/profile` | Yes | Get current user |
| `POST` | `/api/analyze` | Yes | Analyse password dataset |
| `POST` | `/api/check-password` | No | Single password check |
| `POST` | `/api/hibp/check-password` | No | HIBP breach check |
| `POST` | `/api/download-report` | Yes | Download PDF report |
| `GET` | `/api/csrf-token` | No | Get CSRF token |
| `GET` | `/api/health` | No | Health check |

---

## 🔒 Security Concepts Demonstrated

| Concept | Implementation |
|---|---|
| **K-anonymity** | HIBP range API — only SHA-1 prefix sent, full hash never transmitted |
| **CSRF Protection** | Flask-WTF tokens on state-changing endpoints |
| **Rate Limiting** | Flask-Limiter — 20 analyses/hour, 10 auth attempts/minute |
| **Timing-safe comparison** | `hmac.compare_digest` for credential validation |
| **Secure session cookies** | HTTPOnly, SameSite=Lax, Secure flag in production |
| **Input validation** | File type/size validation, password sanitisation |
| **Secret management** | Environment variables — no hardcoded secrets |
| **Config separation** | Dev / Prod / Test configs with different security postures |

---

## 📸 Screenshots

> Dashboard — dark mode with risk score ring and breach statistics

> Registration — live password strength meter with requirement checklist

> PDF Report — downloadable compliance and risk analysis

*(Add your screenshots to a `/screenshots` folder and update these links)*

---

## 🗺️ Roadmap

- [ ] Docker + docker-compose setup
- [ ] PostgreSQL migration guide
- [ ] Unit and integration test suite (pytest)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Redis-backed rate limiting for production
- [ ] User dashboard with analysis history
- [ ] Team / organisation accounts
- [ ] Webhook alerts for critical breach findings

---

## 📚 Learning Resources

If you want to understand the security concepts used in this project:

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Password guidelines
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [HaveIBeenPwned API Docs](https://haveibeenpwned.com/API/v3) — k-anonymity explained
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/3.0.x/security/)

---

## 👤 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/HardikMohite)
- LinkedIn: [Your LinkedIn](https://www.linkedin.com/in/hardik-mohite-06aa0a32b/)

*Built as a portfolio project during BSc Cybersecurity — Year 2*

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

> ⭐ If you found this useful, consider giving it a star on GitHub!