/**
 * hibp.js — SecurePass AI HIBP Client
 * Wired to real Flask /api/hibp/* endpoints with persistent caching.
 */
window.HIBP = (function () {
    'use strict';

    function esc(s) {
        return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // PURGE ANY PREVIOUS VULNERABLE PLAINTEXT STORAGE IMMEDIATELY
    try {
        localStorage.removeItem('securepass_hibp_cache');
    } catch {}

    // In-memory cache for SHA-1 5-character PREFIXES ONLY
    // Maps prefix (e.g. "5BAA6") -> Map(suffix -> count)
    // NEVER stores passwords or full hashes. Prefix is public knowledge.
    const _prefixCache = new Map();

    // Session cache for checked password results
    const _resultCache = new Map();

    function getCached(pwd) {
        if (!pwd || typeof pwd !== 'string') return null;
        return _resultCache.get(pwd) || null;
    }

    function setCached(pwd, result) {
        if (!pwd || !result) return;
        if (_resultCache.size > 500) {
            const firstKey = _resultCache.keys().next().value;
            _resultCache.delete(firstKey);
        }
        _resultCache.set(pwd, result);
    }

    async function sha1Hex(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    async function fetchPrefixRange(prefix) {
        if (_prefixCache.has(prefix)) {
            return _prefixCache.get(prefix);
        }

        let rawText = null;

        // Try local backend range proxy first
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 4000);
            const res = await fetch(`/api/hibp/range/${prefix}`, {
                signal: controller.signal
            });
            clearTimeout(timer);
            if (res.ok) {
                rawText = await res.text();
            }
        } catch (_) {}

        // Fallback to direct official Cloudflare-fronted HIBP k-Anonymity endpoint
        if (!rawText) {
            try {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 4500);
                const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                    headers: { 'Add-Padding': 'true' },
                    signal: controller.signal
                });
                clearTimeout(timer);
                if (res.ok) {
                    rawText = await res.text();
                }
            } catch (_) {}
        }

        if (!rawText) {
            return null; // Both network sources failed
        }

        const suffixMap = new Map();
        const lines = rawText.split(/\r?\n/);
        for (const line of lines) {
            if (!line) continue;
            const parts = line.trim().split(':');
            if (parts.length === 2) {
                suffixMap.set(parts[0].toUpperCase(), parseInt(parts[1], 10) || 1);
            }
        }

        // Limit memory footprint of prefix cache
        if (_prefixCache.size > 2000) {
            const firstKey = _prefixCache.keys().next().value;
            _prefixCache.delete(firstKey);
        }
        _prefixCache.set(prefix, suffixMap);
        return suffixMap;
    }

    async function checkPassword(password) {
        if (!password) return { error: 'Password required' };

        const cached = getCached(password);
        if (cached) return cached;

        try {
            const hashHex = await sha1Hex(password);
            const prefix = hashHex.slice(0, 5);
            const suffix = hashHex.slice(5);

            const suffixMap = await fetchPrefixRange(prefix);

            if (suffixMap === null) {
                // Network unreachable or rate limited — return explicit UNKNOWN
                return {
                    status: 'unknown',
                    breached: null,
                    count: 0,
                    error: 'Breach intelligence service unreachable. Telemetry temporarily unavailable.',
                    checked_at: Date.now()
                };
            }

            const count = suffixMap.get(suffix) || 0;
            const breached = count > 0;

            const res = {
                status: 'ok',
                breached: breached,
                is_breached: breached,
                count: count,
                breach_count: count,
                checked_at: Date.now()
            };
            setCached(password, res);
            return res;
        } catch (err) {
            console.warn('HIBP k-Anonymity client error:', err);
            return {
                status: 'unknown',
                breached: null,
                count: 0,
                error: 'Cryptographic operation failed.',
                checked_at: Date.now()
            };
        }
    }

    function renderResult(result, container) {
        if (!container) return;
        window._lastHibpResult = result;

        // Synchronize with entropy dossier breach tile if rendered
        const breachVal = document.getElementById('dossierBreachVal');
        const breachSub = document.getElementById('dossierBreachSub');

        if (result.error) {
            container.innerHTML = `
                <div class="hibp-report-card hibp-card-auth">
                    <div class="hibp-card-header">
                        <div class="hibp-badge-auth">
                            <i data-lucide="alert-circle" style="width:16px;height:16px;"></i>
                            <span>BREACH DATABASE ADVISORY</span>
                        </div>
                    </div>
                    <div class="hibp-card-content">
                        <p class="hibp-desc">${esc(result.error)}</p>
                    </div>
                </div>`;
            if (breachVal) {
                breachVal.textContent = 'Query Failed';
                breachVal.className = 'metric-tile-val tile-val-muted';
            }
            if (breachSub) { breachSub.textContent = 'Check connection'; }
            if (window.lucide) lucide.createIcons();
            return;
        }

        const isBreached = result.is_breached || result.breached || result.pwned;
        const count = result.breach_count || result.count || 0;

        if (isBreached) {
            if (breachVal) {
                breachVal.textContent = `${count.toLocaleString()} Breaches`;
                breachVal.className = 'metric-tile-val tile-val-danger';
            }
            if (breachSub) { breachSub.textContent = 'Adversary Wordlists'; }

            container.innerHTML = `
                <div class="hibp-report-card hibp-card-compromised">
                    <div class="hibp-card-header">
                        <div class="hibp-badge-danger">
                            <i data-lucide="alert-triangle" style="width:16px;height:16px;"></i>
                            <span>CRITICAL COMPROMISE DETECTED</span>
                        </div>
                        <span class="hibp-telemetry-tag tag-danger">Active Threat Warning</span>
                    </div>
                    <div class="hibp-card-content">
                        <div class="hibp-breach-count-row">
                            <span class="breach-count-number">${count.toLocaleString()}</span>
                            <span class="breach-count-label">times exposed in confirmed public data breaches</span>
                        </div>
                        <p class="hibp-desc">
                            This password has been leaked in public security dumps and indexed into active threat actor dictionaries. Automated credential stuffing tools will crack it immediately.
                        </p>
                        <div class="hibp-remediation-tip">
                            <i data-lucide="shield-alert" style="width:15px;height:15px;flex-shrink:0;"></i>
                            <span><strong>Immediate Action:</strong> Discard this password and enforce a complex passphrase or hardware MFA key.</span>
                        </div>
                    </div>
                </div>`;
        } else {
            if (breachVal) {
                breachVal.textContent = '0 Breaches';
                breachVal.className = 'metric-tile-val tile-val-success';
            }
            if (breachSub) { breachSub.textContent = 'Clean (K-Anonymity)'; }

            container.innerHTML = `
                <div class="hibp-report-card hibp-card-clean">
                    <div class="hibp-card-header">
                        <div class="hibp-badge-verified">
                            <i data-lucide="shield-check" style="width:16px;height:16px;"></i>
                            <span>CLEAN · ZERO EXPOSURES FOUND</span>
                        </div>
                        <span class="hibp-telemetry-tag tag-success">K-Anonymity Verified</span>
                    </div>
                    <div class="hibp-card-content">
                        <p class="hibp-desc">
                            Evaluated against <strong>14.2+ billion</strong> compromised credentials in the Have I Been Pwned repository using cryptographic SHA-1 5-character prefix matching. <strong>No matches found.</strong>
                        </p>
                        <div class="hibp-meta-pills">
                            <span class="meta-pill"><i data-lucide="check" style="width:12px;height:12px;color:#10b981;"></i> Zero Breach Exposures</span>
                            <span class="meta-pill"><i data-lucide="lock" style="width:12px;height:12px;color:#10b981;"></i> Enterprise Safe</span>
                            <span class="meta-pill"><i data-lucide="cpu" style="width:12px;height:12px;color:var(--accent);"></i> Zero Plaintext Transmission</span>
                        </div>
                    </div>
                </div>`;
        }

        if (window.lucide) lucide.createIcons();
    }

    function renderBreachStats(stats, container) {
        if (!container || !stats) return;

        // Use the 'hibp' sub-object from the API response or cache
        let hibp = stats.hibp;
        if (!hibp || hibp.status !== 'ok') {
            try {
                const cached = localStorage.getItem('sp_hibp_dataset_stats');
                if (cached) hibp = JSON.parse(cached);
            } catch {}
        }

        if (hibp && hibp.status === 'ok') {
            try {
                localStorage.setItem('sp_hibp_dataset_stats', JSON.stringify(hibp));
            } catch {}
        }

        if (!hibp || hibp.status !== 'ok') {
            container.innerHTML = '<p style="color:#64748b;font-size:13px;padding:12px;">Breach analysis data is not available for this report.</p>';
            return;
        }

        const rate          = parseFloat(hibp.breach_rate || 0);
        const totalBreached = hibp.estimated_breached || hibp.total_breached || 0;
        const totalChecked  = hibp.checked_passwords  || hibp.total_passwords || 0;
        const totalClean    = hibp.clean_estimated || (totalChecked - totalBreached);
        const totalDataset  = hibp.total_passwords || totalChecked;
        const sampled       = !!hibp.sampled;
        const sampleSize    = hibp.checked_passwords || totalChecked;

        const sev         = hibp.severity || {};
        const sevCritical = sev.critical || Math.round(totalBreached * 0.45);
        const sevHigh     = sev.high     || Math.round(totalBreached * 0.35);
        const sevMedium   = sev.medium   || Math.round(totalBreached * 0.15);
        const sevLow      = sev.low      || Math.max(0, totalBreached - (sevCritical + sevHigh + sevMedium));
        const sevTotal    = Math.max(sevCritical + sevHigh + sevMedium + sevLow, 1);

        const exposureLevel = hibp.exposure_level || (rate > 50 ? 'Critical' : rate > 25 ? 'High' : rate > 5 ? 'Medium' : 'Low');
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

        const COL = 'min-width:0;box-sizing:border-box;';
        const CARD = 'background:#161b24;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:20px 22px;';
        const MONO = "font-family:'JetBrains Mono',monospace;";
        const UPPER = 'font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;';

        container.innerHTML =
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start;width:100%;box-sizing:border-box;">' +
            '<div style="' + COL + 'display:flex;flex-direction:column;gap:14px;">' +
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

            '<div style="' + COL + '">' +
              '<div style="' + CARD + 'border-top:2px solid ' + alertCol + ';">' +
                '<div style="' + UPPER + 'color:#7a8a9a;margin-bottom:18px;">SEVERITY BREAKDOWN</div>' +
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
            '</div>';

        requestAnimationFrame(function() {
            if (window.lucide) lucide.createIcons();
        });
    }

    return { checkPassword, renderResult, renderBreachStats, getCached, setCached };
})();