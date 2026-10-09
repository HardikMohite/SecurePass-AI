/**
 * auth.js — SecurePass AI Shared Auth Utilities
 * Wired to real Flask /api/auth/* endpoints.
 *
 * CSRF: the backend authenticates via an httpOnly JWT cookie (the token
 * itself is never readable by JS — see config.py's JWT_COOKIE_* settings
 * and auth.py's set_access_cookies calls). Flask-JWT-Extended pairs that
 * with a second, non-httpOnly cookie holding a CSRF value, specifically
 * so the frontend CAN read it and echo it back — that's the whole
 * double-submit mechanism: an attacker's cross-site request can rely on
 * the browser auto-sending the auth cookie, but can't read this cookie
 * to also attach it as a header, so the backend rejects the mismatch.
 */
window.Auth = (function () {
    'use strict';

    const API = '/api/auth';

    let _user = null;

    function getCookie(name) {
        const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        return match ? decodeURIComponent(match[1]) : null;
    }

    // Always reads fresh (not cached) — the cookie's value rotates every
    // time the access token is reissued (login, register, /auth/refresh).
    async function getCsrf() {
        return getCookie('csrf_access_token');
    }

    async function request(endpoint, options) {
        options = options || {};
        const method  = (options.method || 'GET').toUpperCase();
        const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
        // Only attach CSRF token for authenticated requests, not login/register
        if (['POST','PUT','DELETE','PATCH'].includes(method) && endpoint !== '/login' && endpoint !== '/register') {
        const tok = await getCsrf();
        if (tok) headers['X-CSRF-TOKEN'] = tok;
    }
    const res  = await fetch(API + endpoint, Object.assign({ credentials: 'include', headers }, options));
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

async function refreshToken() {
    try {
        const csrf = getCookie('csrf_refresh_token') || getCookie('csrf_access_token');
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-TOKEN'] = csrf;
        const res = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers,
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json().catch(() => ({}));
            return data;
        }
    } catch (e) {
        console.warn('Session refresh error:', e);
    }
    return null;
}

async function checkAuth() {
    // 1. Instant local storage retrieval for zero-flicker UI
    try {
        const cached = localStorage.getItem('sp_user_profile');
        if (cached) {
            const parsed = JSON.parse(cached);
            if (parsed && (parsed.email || parsed.username || parsed.id)) {
                _user = parsed;
            }
        }
    } catch {}

    // 2. Query backend to verify active session
    try {
        let r = await fetch('/api/auth/profile', { credentials: 'include' });
        let d = await r.json().catch(() => ({}));

        // If access token expired (401) or no user returned, attempt seamless refresh via refresh token
        if (r.status === 401 || !d || (!d.user && !d.email)) {
            const refreshed = await refreshToken();
            if (refreshed) {
                r = await fetch('/api/auth/profile', { credentials: 'include' });
                d = await r.json().catch(() => ({}));
            }
        }

        if (r.ok && d && (d.user || d.email)) {
            _user = d.user || d;
            try {
                localStorage.setItem('sp_user_profile', JSON.stringify(_user));
                document.documentElement.classList.add('is-auth-cached');
            } catch {}
            return _user;
        } else {
            _user = null;
            try {
                localStorage.removeItem('sp_user_profile');
                document.documentElement.classList.remove('is-auth-cached');
            } catch {}
            return null;
        }
    } catch (err) {
        console.warn('checkAuth error:', err);
        // If server temporarily unreachable, retain cached user
        if (_user) return _user;
    }
    return null;
}

async function login(identifier, password, remember) {
    const r = await request('/login', {
        method: 'POST',
        body: JSON.stringify({
            email: identifier,
            username: identifier,
            login: identifier,
            password,
            remember: !!remember
        })
    });
    if (r.ok) {
        _user = r.data.user || r.data;
        if (_user) {
            try {
                localStorage.setItem('sp_user_profile', JSON.stringify(_user));
                document.documentElement.classList.add('is-auth-cached');
            } catch {}
        }
        return { ok: true, user: _user };
    }
    return { ok: false, error: r.data.error || 'Login failed.' };
}

async function register(username, email, password) {
    const r = await request('/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
    if (r.ok) {
        _user = r.data.user || r.data;
        if (_user) {
            try {
                localStorage.setItem('sp_user_profile', JSON.stringify(_user));
                document.documentElement.classList.add('is-auth-cached');
            } catch {}
        }
        return { ok: true, user: _user };
    }
    return { ok: false, error: r.data.error || 'Registration failed.' };
}

async function logout() {
    try {
        await request('/logout', { method: 'POST' });
    } catch {}
    _user = null;
    try {
        localStorage.removeItem('sp_user_profile');
        localStorage.removeItem('sp_active_analysis');
        sessionStorage.removeItem('sp_active_analysis');
        document.documentElement.classList.remove('is-auth-cached');
    } catch {}
}

function validateEmail(e) {
        if (!e) return { valid: false, error: 'Email is required' };
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)
            ? { valid: true }
            : { valid: false, error: 'Enter a valid email address' };
    }

    function showError(msg) {
        const el = document.getElementById('errMsg');
        if (!el) return;
        el.textContent = msg; el.style.display = 'block';
    }
    function hideError() {
        const el = document.getElementById('errMsg');
        if (el) el.style.display = 'none';
    }
    function showSuccess(msg) {
        const el = document.getElementById('successMsg');
        if (!el) return;
        el.textContent = msg; el.style.display = 'block';
    }
    function hideSuccess() {
        const el = document.getElementById('successMsg');
        if (el) el.style.display = 'none';
    }

    // Profile page initialization
    async function initProfilePage() {
        const user = await checkAuth();
        if (!user) { window.location.href = '/login'; return; }

        const profileInfo = document.getElementById('profile-info');
        if (profileInfo) {
            profileInfo.innerHTML = `
                <p><strong>Username:</strong> ${user.username || '—'}</p>
                <p><strong>Email:</strong> ${user.email || '—'}</p>
            `;
        }

        const historyContainer = document.getElementById('analysis-history');
        if (historyContainer) {
            const r = await request('/history');
            if (r.ok && r.data.history) {
                if (r.data.history.length === 0) {
                    historyContainer.innerHTML = '<p>No analyses performed yet.</p>';
                } else {
                    historyContainer.innerHTML = '<ul>' + r.data.history.map(item =>
                        `<li>${item.timestamp || item.created_at}: ${item.filename} (Risk: ${item.risk_score})</li>`
                    ).join('') + '</ul>';
                }
            } else {
                historyContainer.innerHTML = '<p>Could not load analysis history.</p>';
            }
        }

        const logoutBtn = document.getElementById('logout-button');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async e => {
                e.preventDefault();
                await logout();
                window.location.href = '/login';
            });
        }
    }

    if (window.location.pathname === '/profile') {
        document.addEventListener('DOMContentLoaded', initProfilePage);
    }

    return { getCsrf, request, checkAuth, login, register, logout, validateEmail, showError, hideError, showSuccess, hideSuccess };
})();
