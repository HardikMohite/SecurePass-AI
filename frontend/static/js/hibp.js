/**
 * hibp.js — HaveIBeenPwned integration
 * Exposes: window.HIBP
 * Requires: auth.js (for getCsrf)
 */
(function (global) {
  'use strict';

  /* Simple non-cryptographic hash for cache keys only */
  function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      h = Math.imul(31, h) + s.charCodeAt(i) | 0;
    }
    return h.toString(36);
  }

  const cache = new Map();

  /* ── Single password check ─────────────────────────────── */
  async function checkPassword(password) {
    if (!password) return { error: 'Password required', is_breached: false, breach_count: 0 };

    const key = hashStr(password);
    if (cache.has(key)) return cache.get(key);

    try {
      const csrf = await (global.Auth ? global.Auth.getCsrf() : Promise.resolve(null));
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRFToken'] = csrf;

      const res  = await fetch('/api/hibp/check-password', {
        method: 'POST', headers,
        body: JSON.stringify({ password }),
        credentials: 'include',
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) throw new Error(data.error || 'HIBP check failed');

      cache.set(key, data);
      return data;
    } catch (err) {
      console.error('HIBP check error:', err);
      return { error: err.message, is_breached: null, breach_count: 0 };
    }
  }

  /* ── Batch check ───────────────────────────────────────── */
  async function checkBatch(passwords) {
    if (!passwords || !passwords.length) return { error: 'No passwords provided', results: [] };
    try {
      const csrf = await (global.Auth ? global.Auth.getCsrf() : Promise.resolve(null));
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRFToken'] = csrf;

      const res  = await fetch('/api/hibp/check-batch', {
        method: 'POST', headers,
        body: JSON.stringify({ passwords }),
        credentials: 'include',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Batch check failed');
      return data;
    } catch (err) {
      console.error('HIBP batch error:', err);
      return { error: err.message, results: [] };
    }
  }

  /* ── Render single result into element ─────────────────── */
  function renderResult(result, container) {
    if (!container) return;
    if (result.error) {
      container.innerHTML = `<div class="hibp-result-box hibp-error">⚠️ Unable to check: ${esc(result.error)}</div>`;
      return;
    }
    if (!result.is_breached) {
      container.innerHTML = `<div class="hibp-result-box hibp-safe">✅ Not found in any known breach database.</div>`;
      return;
    }
    const sev = (result.severity || 'low').toLowerCase();
    container.innerHTML = `
      <div class="hibp-result-box hibp-breached-${sev}">
        <div>
          <strong>${sev === 'critical' ? '🚨 CRITICAL' : sev === 'high' ? '⚠️ HIGH' : '⚠️'} — Password Compromised</strong>
          <div class="hibp-result-sub">Found in <strong>${result.breach_count.toLocaleString()}</strong> breaches. ${esc(result.recommendation || '')}</div>
        </div>
      </div>`;
  }

  /* ── Render breach stats section ───────────────────────── */
  function renderBreachStats(stats, container) {
    if (!container) return;
    if (!stats || !stats.total_checked) {
      container.innerHTML = `<p class="text-muted" style="font-size:0.82rem">HIBP check was not run for this analysis.</p>`;
      return;
    }

    const { total_checked, total_breached, total_safe, breach_percentage, severity_distribution } = stats;
    const sd = severity_distribution || {};

    const bars = [
      { label: 'Critical', count: sd.Critical || 0, color: 'var(--red)' },
      { label: 'High',     count: sd.High     || 0, color: 'var(--amber)' },
      { label: 'Medium',   count: sd.Medium   || 0, color: 'var(--amber)' },
      { label: 'Low',      count: sd.Low      || 0, color: 'var(--green)' },
      { label: 'Safe',     count: sd.Safe     || 0, color: 'var(--green)' },
    ];

    container.innerHTML = `
      <div class="breach-summary">
        <div class="breach-card">
          <div class="breach-num breached-num">${total_breached.toLocaleString()}</div>
          <div class="breach-lbl">Breached</div>
        </div>
        <div class="breach-card">
          <div class="breach-num safe-num">${total_safe.toLocaleString()}</div>
          <div class="breach-lbl">Safe</div>
        </div>
        <div class="breach-card">
          <div class="breach-num pct-num">${breach_percentage.toFixed(1)}%</div>
          <div class="breach-lbl">Breach Rate</div>
        </div>
      </div>

      <div class="hibp-severity-breakdown">
        <h4>Severity Breakdown</h4>
        <div class="severity-bars">
          ${bars.map(b => `
            <div class="severity-bar-item">
              <span class="severity-label">${b.label}</span>
              <div class="severity-track">
                <div class="severity-fill"
                     style="background:${b.color}"
                     data-target="${total_checked > 0 ? (b.count/total_checked*100).toFixed(1) : 0}">
                </div>
              </div>
              <span class="severity-pct">${total_checked > 0 ? (b.count/total_checked*100).toFixed(0) : 0}%</span>
            </div>`).join('')}
        </div>
      </div>

      <p class="hibp-note mt-12">🔒 K-anonymity used — only first 5 chars of SHA-1 hash sent. Passwords never leave your browser.</p>
    `;

    /* Animate bars after paint */
    requestAnimationFrame(function () {
      container.querySelectorAll('.severity-fill[data-target]').forEach(function (el) {
        setTimeout(function () { el.style.width = el.dataset.target + '%'; }, 80);
      });
    });
  }

  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  /* ── Expose ────────────────────────────────────────────── */
  global.HIBP = { checkPassword, checkBatch, renderResult, renderBreachStats };

})(window);