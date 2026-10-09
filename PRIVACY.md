# Privacy Architecture & Data Minimization Charter

**SecurePass AI** is engineered under the principle of **Zero-Knowledge Privacy and Total Data Minimization**.

---

## 1. Core Privacy Commitments

1. **Zero Credential Retention**:
   - We do not store, persist, or database user passwords, plain credential strings, or password lists under any circumstances.
   - When a user logs in, only their argon2/bcrypt user account hash is stored for authentication.
   - When an audit is performed on an enterprise password dataset, only non-reversible mathematical distributions and aggregate metrics are stored in the database.

2. **Zero Password Transmission to Artificial Intelligence**:
   - Third-party AI inference engines (e.g. Groq, OpenAI) **never receive plaintext passwords, raw password tokens, or individual hash entries**.
   - AI prompts are composed strictly of anonymized summary statistics (e.g. "Total evaluated: 10,000, Average length: 8.5, Walk percentage: 12%").
   - Automated recursive sanitizers (`assert_no_password_data`) inspect every payload before any external network request is dispatched.

3. **Zero Plaintext Local Storage**:
   - Web browser storage mechanisms (`localStorage`, `sessionStorage`, cookies) **never store user passwords**.
   - Caching for public breach intelligence is performed on truncated cryptographic hash prefixes only, with zero correlation to the source password.

---

## 2. Data Flow & Lifecycle

| Data Type | Ingestion Vector | Where Processed | Storage Destination | Retention Duration |
| :--- | :--- | :--- | :--- | :--- |
| **User Passwords (Audit)** | Web Browser File / Text Input | Local Browser Memory (Client-Side) | None (Never stored) | Ephemeral (Wiped immediately after metric compilation) |
| **SHA-1 Hash Prefixes (5 Hex Chars)** | Browser Web Cryptography API | Local Client & HTTPS Proxy | In-memory prefix cache (LRU) | Volatile session memory |
| **Statistical Telemetry** | Aggregate Calculation Engine | Local Browser / Application Server | PostgreSQL / Supabase `analyses` table | User-managed history (Deletable on demand) |
| **Executive Reports (PDF)** | ReportLab Vector Engine | Application Server (Isolated Sandbox) | Download Stream Buffer (Memory) | Immediate streaming disposal |
| **Account Credentials** | Registration / Login | Backend Argon2 / Bcrypt Hash | PostgreSQL `users` table | Until account deletion |

---

## 3. Client-Side Execution Boundary

Whenever possible, password processing executes locally within your browser:
- **Length, Entropy & Composition Analysis**: Computed on your device using JavaScript.
- **Pattern Matching**: Keyboard walks, dictionary roots, and repeating sequences are matched locally against pre-compiled client datasets.
- **Breach Scanning**: Your device computes cryptographic SHA-1 hashes and sends only the first 5 characters. Matching suffixes is performed locally.

---

## 4. User Rights & Data Control

- **Data Deletion**: Users can delete individual audit records or completely purge their entire audit history via the **Reports** or **Settings** views.
- **Immediate Purging**: When an audit is deleted, its aggregate statistical telemetry is removed from our database.
- **Export Rights**: Users can export their analysis records and formal compliance attestations in PDF or JSON format at any time.
