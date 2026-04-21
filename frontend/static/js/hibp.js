/**
 * hibp.js — SecurePass AI HIBP Client
 * Wired to real Flask /api/hibp/* endpoints.
 */
window.HIBP = (function () {
    'use strict';

    function esc(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    async function checkPassword(password) {
        try {
            const csrf = await Auth.getCsrf();
            const headers = { 'Content-Type': 'application/json' };
            if (csrf) headers['X-CSRFToken'] = csrf;
            const res = await fetch('/api/hibp/check-password', {
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

        // Use the 'hibp' sub-object from the API response
        const hibp = stats.hibp;
        if (!hibp || hibp.status !== 'ok') {
            // You can render a specific message if HIBP data is not available
            container.innerHTML = '<p>Breach analysis data is not available for this report.</p>';
            return;
        }

        const rate          = parseFloat(hibp.breach_rate || 0);
        const totalBreached = hibp.estimated_breached || 0;
        const totalChecked  = hibp.checked_passwords  || 0;
        const totalClean    = hibp.clean_estimated || 0;
        const totalDataset  = hibp.total_passwords || totalChecked;
        const sampled       = !!hibp.sampled;
        const sampleSize    = hibp.checked_passwords || 0;

        const sev         = hibp.severity || {};
        const sevCritical = sev.critical || 0;
        const sevHigh     = sev.high     || 0;
        const sevMedium   = sev.medium   || 0;
        const sevLow      = sev.low      || 0;
        const sevTotal    = Math.max(sevCritical + sevHigh + sevMedium + sevLow, 1);

        const exposureLevel = hibp.exposure_level || 'N/A';
        const alertCol   = exposureLevel === 'Critical' ? '#ff5f57' : exposureLevel === 'High' ? '#ff8c42' : exposureLevel === 'Medium' ? '#febc2e' : '#28c840';
        const alertLabel = exposureLevel.toUpperCase();
        const alertMsg   = `${rate.toFixed(1)}% of passwords found in known breach databases.`;

        const statCards = [
            { icon: 'alert-circle', val: totalBreached.toLocaleString(), lbl: 'COMPROMISED', col: '#ff5f57' },
            { icon: 'check-circle', val: totalClean.toLocaleString(),    lbl: 'CLEAN',       col: '#28c840' },
            { icon: 'bar-chart-2',  val: rate.toFixed(1) + '%',          lbl: 'BREACH RATE', col: alertCol  },
            { icon: 'search',       val: sampleSize.toLocaleString(),    lbl: 'CHECKED',     col: '#00e5ff' },
        ];

        const sevRows = [
            { label: 'CRITICAL', count: sevCritical, col: '#ff5f57' },
            { label: 'HIGH',     count: sevHigh,     col: '#ff8c42' },
            { label: 'MEDIUM',   count: sevMedium,   col: '#febc2e' },
            { label: 'LOW',      count: sevLow,      col: '#28c840' },
        ];

        const hasPatterns = stats.top_patterns && stats.top_patterns.length;

        // ── inline styles used for the outer two-column split so no external
        //    CSS cascade can ever collapse the right column to zero width.
        const COL = 'min-width:0;box-sizing:border-box;';
        const CARD = 'background:#161b24;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:20px 22px;';
        const MONO = "font-family:'JetBrains Mono',monospace;";
        const UPPER = 'font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;';

        container.innerHTML =
            // ── outer two-column grid, inline so nothing can override ──────
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;width:100%;box-sizing:border-box;">' +

            // ════ LEFT COLUMN ════════════════════════════════════════════
            '<div style="' + COL + 'display:flex;flex-direction:column;gap:14px;">' +

              // Alert banner
              '<div style="border:1px solid ' + alertCol + ';background:' + alertCol + '18;border-radius:10px;padding:16px 18px;">' +
                '<div style="' + UPPER + 'color:' + alertCol + ';margin-bottom:8px;">' + esc(alertLabel) + '</div>' +
                '<div style="display:flex;align-items:flex-start;gap:8px;">' +
                  '<i data-lucide="alert-circle" style="width:15px;height:15px;color:' + alertCol + ';flex-shrink:0;margin-top:2px;"></i>' +
                  '<p style="font-size:14px;font-weight:600;line-height:1.45;margin:0;word-break:break-word;">' + esc(alertMsg) + '</p>' +
                '</div>' +
                (sampled
                  ? '<div style="margin-top:10px;font-size:11px;color:#7a8a9a;line-height:1.5;">Sampled ' + sampleSize.toLocaleString() + ' of ' + totalDataset.toLocaleString() + ' passwords — results estimated for full dataset.</div>'
                  : '') +
              '</div>' +

              // 2×2 stat cards
              '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">' +
                statCards.map(function(c) {
                    return '<div style="display:flex;align-items:center;gap:12px;' + CARD + 'overflow:hidden;">' +
                        '<i data-lucide="' + esc(c.icon) + '" style="width:20px;height:20px;color:' + c.col + ';flex-shrink:0;"></i>' +
                        '<div style="min-width:0;">' +
                          '<div style="' + MONO + 'font-size:1.1rem;font-weight:700;color:' + c.col + ';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(c.val) + '</div>' +
                          '<div style="' + UPPER + 'color:#7a8a9a;margin-top:3px;">' + esc(c.lbl) + '</div>' +
                        '</div>' +
                    '</div>';
                }).join('') +
              '</div>' +

              // Exposure bar
              '<div style="' + CARD + '">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
                  '<span style="' + UPPER + 'color:#7a8a9a;">EXPOSURE</span>' +
                  '<span style="' + MONO + 'font-size:1rem;font-weight:700;color:' + alertCol + ';">' + rate.toFixed(1) + '%</span>' +
                '</div>' +
                '<div style="height:7px;background:rgba(255,255,255,0.1);border-radius:999px;overflow:hidden;">' +
                  '<div style="height:100%;width:' + Math.min(rate, 100) + '%;background:' + alertCol + ';border-radius:999px;transition:width 1.1s cubic-bezier(.4,0,.2,1);"></div>' +
                '</div>' +
              '</div>' +

            '</div>' +

            // ════ RIGHT COLUMN ════════════════════════════════════════════
            '<div style="' + COL + '">' +
              '<div style="' + CARD + 'border-top:2px solid ' + alertCol + ';">' +

                // Severity breakdown title
                '<div style="' + UPPER + 'color:#7a8a9a;margin-bottom:18px;">SEVERITY BREAKDOWN</div>' +

                // Severity rows
                '<div style="display:flex;flex-direction:column;gap:14px;">' +
                  sevRows.map(function(r) {
                      var pct = Math.round((r.count / sevTotal) * 100);
                      return '<div style="display:grid;grid-template-columns:72px 1fr 52px;align-items:center;gap:12px;">' +
                          '<span style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:' + r.col + ';">' + esc(r.label) + '</span>' +
                          '<div style="height:6px;background:rgba(255,255,255,0.08);border-radius:999px;overflow:hidden;">' +
                            '<div style="height:100%;width:' + pct + '%;min-width:4px;background:' + r.col + ';border-radius:999px;transition:width 1.1s cubic-bezier(.4,0,.2,1);"></div>' +
                          '</div>' +
                          '<span style="' + MONO + 'font-size:12px;font-weight:700;text-align:right;color:' + r.col + ';">' + r.count.toLocaleString() + '</span>' +
                      '</div>';
                  }).join('') +
                '</div>' +

                // Top patterns (if present)
                (hasPatterns
                  ? '<div style="' + UPPER + 'color:#7a8a9a;margin:22px 0 12px;">TOP PATTERNS</div>' +
                    '<div style="display:flex;flex-direction:column;gap:0;">' +
                      stats.top_patterns.slice(0, 5).map(function(p) {
                          return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:12px;">' +
                              '<span style="color:#7a8a9a;text-transform:capitalize;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;margin-right:12px;">' + esc(p.pattern || p.name || '—') + '</span>' +
                              '<span style="' + MONO + 'font-weight:700;">' + (p.count || 0).toLocaleString() + '</span>' +
                          '</div>';
                      }).join('') +
                    '</div>'
                  : '') +

              '</div>' +
            '</div>' +

            '</div>'; // end outer grid

        requestAnimationFrame(function() {
            if (window.lucide) lucide.createIcons();
        });
    }

    return { checkPassword, renderResult, renderBreachStats };
})();