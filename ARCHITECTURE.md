# System Architecture Specification

**SecurePass AI** is an enterprise-grade password security audit, compliance mapping, and threat-intelligence platform. It provides instant cryptographic vulnerability evaluation and executive CISO reporting while maintaining zero-knowledge privacy.

---

## 1. High-Level Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                                 USER BROWSER                                      |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | Input: Single Password or Bulk Dataset (.TXT, .CSV, .XLSX)                |   |
|   +---------------------------------------------------------------------------+   |
|                                         |                                         |
|                                         v                                         |
|   +---------------------------------------------------------------------------+   |
|   | SecurityEngine (Browser JS Execution Thread)                              |   |
|   |  - Combinatorial Entropy & Shannon Pool                                   |   |
|   |  - Keyboard Adjacency Graph (QWERTY & Numpad)                             |   |
|   |  - Dictionary & L33tspeak Normalization                                   |   |
|   |  - Statistical Aggregator (Lengths, Compositions, Attack Scenarios)       |   |
|   +---------------------------------------------------------------------------+   |
|                                         |                                         |
|                 +-----------------------+-----------------------+                 |
|                 |                                               |                 |
|                 v (5-char SHA-1 prefix)                         v                 |
|   +-----------------------------+               +-------------------------------+ |
|   | Web Cryptography API        |               | Memory Purge Guard            | |
|   | SHA-1(pwd) -> Prefix:Suffix |               | Delete raw password array     | |
|   +-----------------------------+               +-------------------------------+ |
|                 |                                               |                 |
+-----------------|-----------------------------------------------|-----------------+
                  | (k-Anonymity query)                           | (Sanitized JSON)
                  v                                               v
+-----------------------------------------------------------------------------------+
|                           SECUREPASS AI API SERVER                                |
|                                                                                   |
|  +--------------------------------+          +---------------------------------+  |
|  | /api/hibp/range/<prefix>       |          | /api/analyze                    |  |
|  |  - Validates 5 hex chars       |          |  - assert_no_password_data()    |  |
|  |  - Proxies to HIBP API         |          |  - Compliance Mapping (NIST)    |  |
|  |  - Returns suffix ranges       |          |  - Policy Impact Simulation     |  |
|  +--------------------------------+          +---------------------------------+  |
|                                                              |                    |
|                                                              v                    |
|                                              +---------------------------------+  |
|                                              | Groq LLM API (External AI)      |  |
|                                              |  - Receives aggregate stats ONLY|  |
|                                              |  - Policy formulation & insights|  |
|                                              +---------------------------------+  |
|                                                              |                    |
|                                                              v                    |
|                                              +---------------------------------+  |
|                                              | PostgreSQL / Supabase           |  |
|                                              |  - Stores aggregate JSON ONLY   |  |
|                                              +---------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Component Breakdown

### A. Client-Side Layer (`frontend/src/js/`)
- **`security-engine.js`**: Pure deterministic engine executing in browser memory. Computes Shannon entropy, keyboard adjacency sequences, dictionary roots, character composition distributions, and attack simulations.
- **`hibp.js`**: Cryptographic k-anonymity client. Hashes passwords locally with SHA-1, queries 5-character prefixes, and matches returned suffixes locally. Purges any sensitive storage.
- **`script.js`**: Coordinates dashboard views, compliance checklists, terminal attack visualizers, and sanitized data dispatching.
- **`reports.js`**: Manages report history, inline report previews, and instant sub-250ms PDF report downloads.
- **`auth.js`**: Manages HTTP-only JWT session authentication with CSRF double-submit protection.

### B. Backend Services (`backend/`)
- **`app.py`**: Flask application factory, security headers, rate limiting (Flask-Limiter), and routing.
- **`hibp_routes.py` & `hibp_engine.py`**: K-anonymity range proxy with per-thread connection pooling and LRU caching.
- **`ai_engine.py`**: AI synthesis engine calling Groq (Llama 3.3 70B Versatile). Enforces strict prompt privacy assertions (`assert_no_password_data`).
- **`reports/pdf_gen.py`**: High-performance ReportLab vector PDF generator. Generates 10-section executive audit packs in under 250ms.
- **`utils/redaction.py`**: Sensitive key validation scanner and log filter redacting credentials from all system streams.

---

## 3. Data Flow Specification

1. **User Uploads Dataset**: Client parses `.txt` or `.csv` in memory.
2. **Local Heuristics**: `SecurityEngine.analyzeDataset()` compiles distributions.
3. **K-Anonymity Sampling**: Up to 25 unique SHA-1 prefixes are queried to sample breach exposure rates.
4. **Sanitization**: Raw passwords are deleted from local variables.
5. **API Dispatch**: `{ sanitized: true, dataset_stats: {...}, patterns: {...}, hibp: {...} }` sent to `/api/analyze`.
6. **Backend Verification**: `assert_no_password_data()` recursively verifies zero credentials or hashes are present.
7. **Compliance & Policy**: Scores mapped against NIST SP 800-63B, PCI-DSS v4.0, ISO 27001, and HIPAA.
8. **Persistence**: Sanitized metrics stored in `analyses` table under the authenticated user's ID.
9. **Report Generation**: Native vector PDF generated on demand directly from sanitized metadata in under 200ms.
