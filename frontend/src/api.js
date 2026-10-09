/**
 * api.js — SecurePass AI API client (Phase 3)
 *
 * Talks to the JWT-based backend (auth.py):
 *   POST /api/auth/login    -> { user, access_token, refresh_token }
 *   POST /api/auth/register -> { user, access_token, refresh_token }
 *   POST /api/auth/refresh  -> { access_token }   (Authorization: Bearer <refresh_token>)
 *   POST /api/auth/logout   -> revokes the current access token (+ optional refresh_token in body)
 *
 * NOT wired into login.js / register.js / auth.js yet — this is Phase 3
 * step 1, "build and sanity-check the client in isolation" per the ticket.
 * Those pages still run on the Phase 2 cookie/CSRF-based `window.Auth`.
 * Rewiring them to this module is future work.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * TOKEN STORAGE — access token vs. refresh token
 * ─────────────────────────────────────────────────────────────────────────
 * Access token: kept ONLY in the module-level `accessToken` variable below.
 * Never written to any Web Storage. It's short-lived (15 min server-side,
 * see config.py JWT_ACCESS_TOKEN_EXPIRES) so losing it on tab close/reload
 * is cheap — the refresh token gets a new one automatically.
 *
 * Refresh token: this is the harder call, and the two options the ticket
 * asked me to weigh are genuinely different in kind, not just degree.
 *
 *   httpOnly cookie (the textbook-correct answer)
 *     + Never touchable by JS, so an XSS bug on this site can't read it
 *       or ship it to an attacker's server — the single biggest reason
 *       to prefer cookies for a long-lived credential.
 *     + Browser attaches/clears it automatically; nothing for frontend
 *       code to manage.
 *     - Needs CSRF protection (SameSite=Lax/Strict + a double-submit
 *       token, or origin checks), since the browser will now send it
 *       on any request to the domain, XHR or not.
 *     - Needs backend support: the server has to *set* the cookie
 *       (Set-Cookie on login/register/refresh) and *read* it instead of
 *       expecting Authorization: Bearer <refresh_token>.
 *
 *   localStorage
 *     + Trivial to implement purely on the frontend.
 *     + Survives tab close and full page reloads, so "stay logged in"
 *       works with zero extra plumbing.
 *     - Fully readable by any JS that runs on the page — including an
 *       injected script from an XSS bug in *any* third-party code this
 *       app ever loads. A stolen refresh token is a long-lived (30-day,
 *       per JWT_REFRESH_TOKEN_EXPIRES) skeleton key, not a 15-minute
 *       inconvenience.
 *     - Persists indefinitely with no built-in expiry/cleanup.
 *
 * I checked what this backend actually supports before picking one:
 *   - config.py: JWT_TOKEN_LOCATION = ['headers']  — cookies are not a
 *     token source Flask-JWT-Extended will even look at here.
 *   - auth.py /api/auth/refresh is `@jwt_required(refresh=True)`, which
 *     reads the refresh token from the Authorization header, not a
 *     cookie — and login()/register() return refresh_token in the JSON
 *     body, not via Set-Cookie.
 *   - app.py's CORS() call does not set supports_credentials, and the
 *     root .env.example says so explicitly: "Auth uses bearer tokens
 *     (not cookies), so this does not need to enable
 *     supports_credentials." Without that flag, browsers won't send or
 *     accept cookies cross-origin (frontend on the Vite dev server,
 *     backend on Flask) even if I set one client-side.
 *
 * So an httpOnly cookie is the right *target* architecture, but it's a
 * backend/CORS change (cookie-mode JWTs + CSRF double-submit + CORS
 * credentials), not something this client can retrofit on its own — and
 * that's out of scope for a frontend-only ticket against an
 * "already migrated" backend.
 *
 * Between the two options as the backend actually exists today, I'm not
 * willing to put a 30-day bearer credential in localStorage, where any
 * dependency's XSS bug can exfiltrate it silently and it'll keep working
 * for a month. My compromise: sessionStorage. It's still JS-readable
 * (doesn't fix the core XSS exposure — I'm not pretending it's a
 * substitute for httpOnly), but it's cleared when the tab closes and
 * isn't shared across tabs, which shrinks both the exposure window and
 * the blast radius versus localStorage, for no extra backend work. If
 * `sessionStorage` isn't available (e.g. some private-browsing modes),
 * this falls back to an in-memory Map — same behavior as the access
 * token, just less convenient.
 *
 * Recommendation for a follow-up ticket: move the refresh token to an
 * httpOnly, Secure, SameSite=Strict cookie set by /api/auth/login,
 * /api/auth/register and /api/auth/refresh, add CSRF protection, and
 * flip CORS to supports_credentials with an explicit origin allowlist
 * (already exists in CORS_ORIGINS).
 */

const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  '';

const REFRESH_TOKEN_KEY = 'securepass_refresh_token';

// In-memory fallback used when sessionStorage is unavailable (SSR-ish
// contexts, this sanity-test script running under plain Node, or a
// browser private-mode that throws on storage access).
const memoryFallbackStore = new Map();

function storageGet(key) {
  try {
    if (typeof sessionStorage !== 'undefined') return sessionStorage.getItem(key);
  } catch {
    /* fall through to memory */
  }
  return memoryFallbackStore.has(key) ? memoryFallbackStore.get(key) : null;
}

function storageSet(key, value) {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(key, value);
      return;
    }
  } catch {
    /* fall through to memory */
  }
  memoryFallbackStore.set(key, value);
}

function storageRemove(key) {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(key);
      return;
    }
  } catch {
    /* fall through to memory */
  }
  memoryFallbackStore.delete(key);
}

// ── Access token: module-level only, never persisted ──────────────────────
let accessToken = null;

export function getAccessToken() {
  return accessToken;
}

function getRefreshToken() {
  return storageGet(REFRESH_TOKEN_KEY);
}

function setTokens({ access_token, refresh_token } = {}) {
  if (access_token) accessToken = access_token;
  if (refresh_token) storageSet(REFRESH_TOKEN_KEY, refresh_token);
}

export function clearTokens() {
  accessToken = null;
  storageRemove(REFRESH_TOKEN_KEY);
}

function redirectToLogin() {
  clearTokens();
  if (typeof window !== 'undefined' && window.location) {
    window.location.href = '/login.html';
  }
}

// Dedupe concurrent refreshes: if five requests 401 at once, we want one
// refresh call, not five racing to rewrite accessToken.
let refreshPromise = null;

async function refreshAccessToken() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const token = getRefreshToken();
    if (!token) throw new Error('No refresh token available');

    const res = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) throw new Error(`Refresh failed with status ${res.status}`);

    const data = await res.json().catch(() => ({}));
    if (!data.access_token) throw new Error('Refresh response missing access_token');

    accessToken = data.access_token;
    return accessToken;
  })();

  try {
    return await refreshPromise;
  } finally {
    refreshPromise = null;
  }
}

/**
 * Low-level fetch wrapper. Attaches Authorization when `auth` is true
 * (default), and on a 401 attempts exactly one refresh-and-retry before
 * giving up and redirecting to /login.html.
 *
 * @param {string} path - e.g. '/api/auth/profile'
 * @param {RequestInit & { auth?: boolean }} options
 */
export async function apiFetch(path, options = {}) {
  const { auth = true, ...rest } = options;
  const isRetry = Boolean(rest._isRetry);
  delete rest._isRetry;

  const headers = new Headers(rest.headers || {});
  if (rest.body && !headers.has('Content-Type') && !(rest.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  if (auth && accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const res = await fetch(`${API_BASE_URL}${path}`, { ...rest, headers });

  if (res.status === 401 && auth && !isRetry) {
    try {
      await refreshAccessToken();
    } catch (err) {
      redirectToLogin();
      throw err;
    }
    return apiFetch(path, { ...options, _isRetry: true });
  }

  return res;
}

/**
 * Convenience wrapper: parses JSON and throws on non-2xx (with `.status`
 * and `.data` attached), so callers can just `await apiJson(...)`.
 */
export async function apiJson(path, options = {}) {
  const res = await apiFetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(data.error || `Request failed with status ${res.status}`);
    error.status = res.status;
    error.data = data;
    throw error;
  }
  return data;
}

export async function login(email, password, remember = false) {
  const data = await apiJson('/api/auth/login', {
    method: 'POST',
    auth: false,
    body: JSON.stringify({ email, password, remember }),
  });
  setTokens(data);
  return data;
}

export async function register(email, password, username) {
  const data = await apiJson('/api/auth/register', {
    method: 'POST',
    auth: false,
    body: JSON.stringify({ email, password, username }),
  });
  setTokens(data);
  return data;
}

export async function logout() {
  try {
    await apiJson('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: getRefreshToken() }),
    });
  } finally {
    clearTokens();
  }
}

export default {
  apiFetch,
  apiJson,
  login,
  register,
  logout,
  getAccessToken,
  clearTokens,
};
