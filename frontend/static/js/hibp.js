/**
 * hibp.js — SecurePass AI HIBP Client
 * Wired to real Flask /api/hibp/* endpoints.
 */
window.HIBP = (function () {
    'use strict';

    async function checkPassword(password) {
        try {
            const csrf = await Auth.getCsrf();
            const headers = { 'Content-Type': 'application/json' };
            if (csrf) headers['X-CSRFToken'] = csrf;
            const res  = await fetch('/api/hibp/check-password', {
                method: 'POST', headers,
                body: JSON.stringify({ password }), credentials: 'include',
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) return { error: data.error || 'HIBP check failed', status: res.status };
            return data;
        } catch (err) {
            return { error: 'Network error. Please try again.' };
        }
    }

    function renderResult(result, container) {
        if (!container) return;
        if (result.error) {
            container.innerHTML = `
                <div class="hibp-result-inline hibp-unknown">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>${esc(result.error)}</span>
                </div>`;
            return;
        }
        const isBreached = result.is_breached || result.breached || result.pwned;
        if (isBreached) {
            const count = result.breach_count || result.count || 0;
            container.innerHTML = `
                <div class="hibp-result-inline hibp-breached">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <div><strong>Breached!</strong> Found in ${count.toLocaleString()} data breach${count !== 1 ? 'es' : ''}. Do not use this password.</div>
                </div>`;
        } else {
            container.innerHTML = `
                <div class="hibp-result-inline hibp-safe">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <div><strong>Not found</strong> in known data breaches.</div>
                </div>`;
        }
    }

    function renderBreachStats(stats, container) {
        if (!container || !stats) return;
        const rate     = (stats.breach_rate || 0).toFixed(1);
        const breached = (stats.total_breached || 0).toLocaleString();
        const safe     = ((stats.total_checked || 0) - (stats.total_breached || 0)).toLocaleString();
        const alertCol = stats.breach_rate > 30 ? '#ff5f57' : stats.breach_rate > 10 ? '#febc2e' : '#28c840';
        const alertMsg = stats.breach_rate > 30
            ? `CRITICAL: ${rate}% of passwords found in breach databases.`
            : stats.breach_rate > 10
                ? `WARNING: ${rate}% of passwords found in known breaches.`
                : `LOW EXPOSURE: ${rate}% of passwords in breach databases.`;

        container.innerHTML = `
            <div class="breach-stats-summary">
                <div class="breach-stat-item">
                    <div class="breach-stat-val">${breached}</div>
                    <div class="breach-stat-lbl">Breached</div>
                </div>
                <div class="breach-stat-item">
                    <div class="breach-stat-val" style="color:${alertCol}">${rate}%</div>
                    <div class="breach-stat-lbl">Breach Rate</div>
                </div>
                <div class="breach-stat-item">
                    <div class="breach-stat-val safe">${safe}</div>
                    <div class="breach-stat-lbl">Clean</div>
                </div>
            </div>
            <div class="ai-insight-item" style="color:${alertCol};border-left-color:${alertCol};font-size:12px;margin-bottom:0;">
                ${esc(alertMsg)}
                ${stats.sampled ? `<br><span style="color:var(--text-muted);font-size:11px">Based on sample of ${stats.sample_size} passwords — scaled to full dataset.</span>` : ''}
            </div>`;
    }

    function esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    return { checkPassword, renderResult, renderBreachStats };
})();