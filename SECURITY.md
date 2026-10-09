# Security Policy & Cryptographic Architecture

**SecurePass AI** is built on a foundational mandate: **User credentials must never be exposed, transmitted in plaintext to external entities, logged, or retained.**

---

## 1. Zero-Knowledge Processing Architecture

SecurePass AI implements a **Client-Side First / Zero-Knowledge** security pipeline:

1. **Client-Side Ingestion & Analysis**:
   - Files (`.TXT`, `.CSV`, `.XLSX`) and individual passwords are parsed in volatile browser memory.
   - The deterministic `SecurityEngine` evaluates length, character variety, combinatorial entropy, keyboard walks, dictionary roots, and sequence repetitions directly on the client machine.
   - Plaintext passwords never leave the user's browser memory unless the client falls back to server-side in-memory processing.

2. **Inviolable Privacy Gates**:
   - Backend APIs (`/api/analyze`, `/api/ai-policy`, `/api/compliance-ai`) validate all incoming and outgoing payloads using recursive inspection (`assert_no_password_data`).
   - Any sensitive credential field, raw password key, or full cryptographic hash causes the request to be rejected immediately with a `SecurityPrivacyViolationError`.

3. **Ephemeral Processing & Memory Purging**:
   - In automated testing or legacy fallback file ingestion, uploaded files are processed strictly in RAM and deleted immediately upon computing aggregate distributions (`del passwords`).
   - Plaintext passwords are never written to disk, scratch storage, or server logs.

---

## 2. Cryptographic k-Anonymity Protocol (HIBP)

To verify whether passwords exist in public breach corpora (14.2+ billion records) without disclosing the password:

1. **Local SHA-1 Hashing**:
   - The client computes the SHA-1 digest of the candidate password locally via the Web Cryptography API (`crypto.subtle.digest('SHA-1', ...)`):
     $$\text{SHA-1}(\text{Password}) \rightarrow \text{Prefix}_{5} \,\|\, \text{Suffix}_{35}$$
2. **Prefix-Only Query**:
   - Only the first 5 hexadecimal characters ($\text{Prefix}_{5}$) are queried from `/api/hibp/range/{prefix}` or `https://api.pwnedpasswords.com/range/{prefix}`.
   - The 5-character prefix matches approximately 500 to 1,000 distinct credential hashes in Troy Hunt's Have I Been Pwned repository, providing mathematical $k$-anonymity ($k \approx 500\text{--}1000$).
3. **Local Suffix Matching**:
   - The remote API returns a list of candidate suffixes and prevalence counts.
   - The client matches $\text{Suffix}_{35}$ against the candidate list entirely in browser memory.
   - Neither the backend server nor the HIBP API ever receives the full hash or the plaintext password.
4. **Fail-Safe Telemetry**:
   - If the HIBP service is offline, unreachable, or rate-limited, the system returns status `unknown` and alerts the user. It never gives false assurance or reports an unchecked credential as clean.

---

## 3. AI Isolation & Boundary Protection

The AI engine (Groq LLM / Llama 3.3 70B Versatile) generates corporate policy language, attack simulations, and executive recommendations:

- **AI Payload Anonymization**: The AI engine receives **only high-level statistical distributions and aggregated metadata** (e.g. `total_passwords: 1000`, `weak_passwords: 240`, `average_length: 9.2`, `dictionary_attack_pct: 18.5%`).
- **Prompt Sanitization**: Prompts are passed through `assert_no_password_data(prompt)` prior to API transmission.
- **System Instruction Hardening**: Prompts include system boundaries instructing the model to reject any credential ingestion or prompt override.
- **Schema Validation**: LLM responses are parsed as structured JSON adhering to predefined schemas, preventing arbitrary script or injection storage.

---

## 4. Log Sanitization & Redaction

The application attaches `SecureLogFilter` across Flask, Werkzeug, and root Python loggers:
- Automatically redacts passwords, tokens, API keys, and session cookies (`[REDACTED]`, `[REDACTED_TOKEN]`).
- Strips authorization headers and sensitive query parameters.
- Ensures debug logs and stack traces never leak credential data to monitoring collectors or disk.

---

## 5. Vulnerability Disclosure Policy

If you discover a security vulnerability or potential privacy leak in SecurePass AI:
1. **Do not file a public GitHub issue.**
2. Email our security team at `security@hardik.enterprise` (or repository maintainer).
3. Include detailed reproduction steps, environment details, and proof of concept.
4. We acknowledge reports within 24 hours and aim to release patches within 72 hours for critical severity issues.
