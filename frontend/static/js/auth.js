/**
 * auth.js — Shared authentication utilities
 * Loaded via <script src="js/auth.js"> (no modules).
 * Exposes: window.Auth
 */
(function (global) {
  'use strict';

  /* ── API base ──────────────────────────────────────────── */
  const API_BASE = '/api/auth';

  /* ── API request helper ────────────────────────────────── */
  async function apiRequest(endpoint, options = {}) {
    const url = API_BASE + endpoint;
    const defaults = {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
    };
    const config = Object.assign({}, defaults, options);
    if (config.headers && options.headers) {
      config.headers = Object.assign({}, defaults.headers, options.headers);
    }
    try {
      const res  = await fetch(url, config);
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      console.error('Auth API error:', err);
      throw new Error('Network error. Please try again.');
    }
  }

  /* ── Validation ────────────────────────────────────────── */
  function validateEmail(email) {
    if (!email) return { valid: false, error: 'Email is required' };
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    return ok ? { valid: true, error: null }
              : { valid: false, error: 'Please enter a valid email address' };
  }

  function validatePassword(password) {
    if (!password) return { valid: false, error: 'Password is required', requirements: {}, strength: 'weak' };

    const req = {
      length:    password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number:    /[0-9]/.test(password),
      special:   /[^A-Za-z0-9]/.test(password),
    };

    const errors = [];
    if (!req.length)    errors.push('At least 8 characters required');
    if (!req.uppercase) errors.push('Add an uppercase letter');
    if (!req.lowercase) errors.push('Add a lowercase letter');
    if (!req.number)    errors.push('Add a number');

    const score =
      (req.length ? 1 : 0) + (req.uppercase ? 1 : 0) + (req.lowercase ? 1 : 0) +
      (req.number ? 1 : 0) + (req.special ? 1 : 0) +
      (password.length >= 12 ? 1 : 0) + (password.length >= 16 ? 1 : 0);

    const strength = score <= 3 ? 'weak' : score <= 5 ? 'medium' : 'strong';
    const isValid  = req.length && req.uppercase && req.lowercase && req.number;

    return { valid: isValid, error: errors[0] || null, errors, requirements: req, strength };
  }

  function validatePasswordMatch(password, confirm) {
    if (!confirm)          return { valid: false, error: 'Please confirm your password' };
    if (password !== confirm) return { valid: false, error: 'Passwords do not match' };
    return { valid: true, error: null };
  }

  /* ── UI helpers ────────────────────────────────────────── */
  function showError(msg) {
    const el = document.getElementById('errMsg');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('visible');
  }

  function hideError() {
    const el = document.getElementById('errMsg');
    if (el) el.classList.remove('visible');
  }

  function showSuccess(msg) {
    const el = document.getElementById('successMsg');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('visible');
  }

  function setLoading(btnId, textId, loading, originalText) {
    const btn = document.getElementById(btnId);
    const txt = document.getElementById(textId);
    if (!btn) return;
    btn.disabled = loading;
    if (txt) txt.textContent = loading ? 'Please wait…' : originalText;
  }

  function togglePasswordVisibility(inputId, iconEl) {
    const inp = document.getElementById(inputId);
    if (!inp) return;
    inp.type = inp.type === 'password' ? 'text' : 'password';
    if (iconEl) iconEl.textContent = inp.type === 'password' ? '👁' : '🙈';
  }

  /* ── Session storage ───────────────────────────────────── */
  function storeUser(userData) {
    try { sessionStorage.setItem('sp_user', JSON.stringify(userData)); } catch {}
  }
  function getUser() {
    try { const d = sessionStorage.getItem('sp_user'); return d ? JSON.parse(d) : null; } catch { return null; }
  }
  function clearUser() {
    try { sessionStorage.removeItem('sp_user'); } catch {}
  }

  /* ── CSRF token ────────────────────────────────────────── */
  let _csrfCache = null;
  async function getCsrf() {
    if (_csrfCache) return _csrfCache;
    try {
      const r = await fetch('/api/csrf-token');
      const d = await r.json();
      _csrfCache = d.csrf_token || null;
      return _csrfCache;
    } catch { return null; }
  }

  /* ── Debounce ──────────────────────────────────────────── */
  function debounce(fn, wait) {
    let t;
    return function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  /* ── Check auth ────────────────────────────────────────── */
  async function checkAuthentication() {
    try {
      const r = await apiRequest('/check');
      return r.ok && r.data.authenticated;
    } catch { return false; }
  }

  /* ── Expose ────────────────────────────────────────────── */
  global.Auth = {
    apiRequest,
    validateEmail,
    validatePassword,
    validatePasswordMatch,
    showError,
    hideError,
    showSuccess,
    setLoading,
    togglePasswordVisibility,
    storeUser,
    getUser,
    clearUser,
    getCsrf,
    debounce,
    checkAuthentication,
  };

})(window);