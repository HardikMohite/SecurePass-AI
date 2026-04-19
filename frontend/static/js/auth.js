/**
 * auth.js — SecurePass AI Shared Auth Utilities
 * Wired to real Flask /api/auth/* endpoints.
 */
window.Auth = (function () {
    'use strict';

    const API = '/api/auth';
    let _csrf = null;
    let _user = null;

    async function getCsrf() {
        if (_csrf) return _csrf;
        try {
            const r = await fetch('/api/csrf-token', { credentials: 'include' });
            const d = await r.json();
            _csrf = d.csrf_token || null;
        } catch {}
        return _csrf;
    }

    async function request(endpoint, options) {
        options = options || {};
        const method  = (options.method || 'GET').toUpperCase();
        const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
        if (['POST','PUT','DELETE','PATCH'].includes(method)) {
            const tok = await getCsrf();
            if (tok) headers['X-CSRFToken'] = tok;
        }
        const res  = await fetch(API + endpoint, Object.assign({ credentials: 'include', headers }, options));
        const data = await res.json().catch(() => ({}));
        return { ok: res.ok, status: res.status, data };
    }

    async function checkAuth() {
        try {
            const r = await fetch('/api/auth/profile', { credentials: 'include' });
            const d = await r.json().catch(() => ({}));
            if (r.ok && (d.user || d.email)) { _user = d.user || d; return _user; }
        } catch {}
        return null;
    }

    async function login(email, password, remember) {
        const r = await request('/login', { method: 'POST', body: JSON.stringify({ email, password, remember: !!remember }) });
        if (r.ok) { _user = r.data.user || r.data; return { ok: true, user: _user }; }
        return { ok: false, error: r.data.error || 'Login failed.' };
    }

    async function register(username, email, password) {
        const r = await request('/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
        if (r.ok) return { ok: true };
        return { ok: false, error: r.data.error || 'Registration failed.' };
    }

    async function logout() {
        await request('/logout', { method: 'POST' });
        _user = null;
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