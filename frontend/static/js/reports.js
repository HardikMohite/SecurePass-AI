/**
 * reports.js — Feature 6: Reports Page
 * Fully wired to:
 *   GET  /api/auth/history          → list past analyses
 *   GET  /api/report/<id>           → fetch stored analysis by ID
 *   POST /api/download-report       → generate + stream PDF
 *
 * Drop this file into frontend/static/js/
 * and add <script src=".../reports.js"></script> in index.html
 * AFTER script.js.
 */
(function () {
    'use strict';

    /* ─── state ──────────────────────────────────────────────────── */
    let _expandedId   = null;   // currently open row analysis_id
    let _loading      = false;
    let _initialized  = false;

    /* ─── utils ──────────────────────────────────────────────────── */
    const $  = id => document.getElementById(id);
    const qs = s  => document.querySelector(s);

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function fmtDate(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleDateString('en-US', {
                year: 'numeric', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit',
            });
        } catch { return iso; }
    }

    function riskMeta(score) {
        const n = parseFloat(score) || 0;
        if (n >= 75) return { label: 'High Risk',   cls: 'rpt-badge--high'   };
        if (n >= 45) return { label: 'Medium Risk', cls: 'rpt-badge--medium' };
        return              { label: 'Low Risk',    cls: 'rpt-badge--low'    };
    }

    async function getCsrf() {
        try {
            const r = await fetch('/api/csrf-token');
            const d = await r.json();
            return d.csrf_token || null;
        } catch { return null; }
    }

    function toast(msg, type) {
        const c = $('toastContainer');
        if (!c) return;
        const el = document.createElement('div');
        el.className = `toast toast-${type || 'info'}`;
        el.textContent = msg;
        c.appendChild(el);
        setTimeout(() => {
            el.style.opacity = '0';
            el.style.transform = 'translateX(20px)';
            setTimeout(() => el.remove(), 320);
        }, 3500);
    }

    /* ─── API calls ──────────────────────────────────────────────── */
    async function fetchHistory() {
        const res = await fetch('/api/auth/history', { credentials: 'include' });
        if (!res.ok) {
            if (res.status === 401) throw new Error('Not logged in.');
            throw new Error(`Server error (${res.status}).`);
        }
        const data = await res.json();
        // API returns { history: [...], total, page, pages, ... }
        const items = Array.isArray(data) ? data : (data.history || []);
        console.debug('[Reports] fetchHistory →', items.length, 'items', items);
        return items;
    }

    async function fetchReportDetail(analysisId) {
        const res = await fetch(`/api/report/${analysisId}`, { credentials: 'include' });
        if (!res.ok) throw new Error(`Failed to load report (${res.status}).`);
        return res.json();
    }

    async function apiClearHistory() {
        const csrf = await getCsrf();
        const headers = {};
        if (csrf) headers['X-CSRFToken'] = csrf;
        const res = await fetch('/api/auth/history', {
            method: 'DELETE', headers, credentials: 'include',
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `Server error (${res.status})`);
        }
        return res.json();
    }

    /* ─── render helpers ─────────────────────────────────────────── */
    function buildEmptyState() {
        return `
        <div class="panel-empty-state" id="rptEmptyState">
            <i data-lucide="file-x"></i>
            <p>No reports yet.</p>
            <span>Complete an analysis on the Dashboard to generate your first security report.</span>
            <button class="btn-report rpt-cta-btn" onclick="window.showPage('dashboard')" style="margin-top:12px;">
                <i data-lucide="upload" style="width:14px;height:14px;"></i> Upload &amp; Analyse
            </button>
        </div>`;
    }

    function buildSkeleton(n) {
        return Array.from({ length: n }, () => `
        <div class="rpt-row rpt-row--skeleton">
            <div class="rpt-row-main">
                <div class="rpt-skeleton rpt-sk-icon"></div>
                <div class="rpt-row-info">
                    <div class="rpt-skeleton rpt-sk-title"></div>
                    <div class="rpt-skeleton rpt-sk-sub"></div>
                </div>
                <div class="rpt-skeleton rpt-sk-badge"></div>
                <div class="rpt-skeleton rpt-sk-num"></div>
                <div class="rpt-skeleton rpt-sk-btn"></div>
            </div>
        </div>`).join('');
    }

    function buildRow(report) {
        const { id, filename, created_at, risk_score, total_passwords } = report;
        const risk = riskMeta(risk_score);
        return `
        <div class="rpt-row" id="rpt-row-${id}" data-id="${id}">
            <div class="rpt-row-main" role="button" tabindex="0"
                 aria-expanded="false" aria-controls="rpt-detail-${id}"
                 onclick="Reports.toggleRow(${id})"
                 onkeydown="if(event.key==='Enter'||event.key===' ')Reports.toggleRow(${id})">

                <div class="rpt-file-icon">
                    <i data-lucide="file-text"></i>
                </div>

                <div class="rpt-row-info">
                    <span class="rpt-filename" title="${esc(filename)}">${esc(filename)}</span>
                    <span class="rpt-date">${fmtDate(created_at)}</span>
                </div>

                <span class="rpt-badge ${esc(risk.cls)}">${esc(risk.label)}</span>

                <div class="rpt-stat">
                    <span class="rpt-stat-num">${esc(total_passwords ?? '—')}</span>
                    <span class="rpt-stat-label">passwords</span>
                </div>

                <div class="rpt-row-score">
                    <svg class="rpt-score-ring" viewBox="0 0 36 36">
                        <circle cx="18" cy="18" r="15.9" fill="none" stroke="var(--border-2)" stroke-width="3"/>
                        <circle cx="18" cy="18" r="15.9" fill="none"
                            stroke="${scoreColor(risk_score)}"
                            stroke-width="3"
                            stroke-dasharray="${((parseFloat(risk_score)||0)/100*100).toFixed(1)} 100"
                            stroke-linecap="round"
                            transform="rotate(-90 18 18)"/>
                    </svg>
                    <span class="rpt-score-val">${Math.round(parseFloat(risk_score)||0)}</span>
                </div>

                <div class="rpt-row-actions" onclick="event.stopPropagation()">
                    <button class="rpt-dl-btn" id="rpt-dl-${id}"
                            title="Download PDF report"
                            onclick="Reports.downloadPDF(${id}, '${esc(filename)}', this)">
                        <i data-lucide="download" style="width:14px;height:14px;"></i>
                        <span>Download PDF</span>
                    </button>
                    <div class="rpt-expand-chevron" aria-hidden="true">
                        <i data-lucide="chevron-down"></i>
                    </div>
                </div>
            </div>

            <div class="rpt-detail-panel" id="rpt-detail-${id}" aria-hidden="true"></div>
        </div>`;
    }

    function scoreColor(score) {
        const n = parseFloat(score) || 0;
        if (n >= 75) return '#ff5f57';
        if (n >= 45) return '#febc2e';
        return '#00b86e';
    }

    function buildDetailPanel(detail) {
        const d  = detail.analysis_data || {};
        const ov = d.overview || {};
        const weak   = ov.weak_passwords   ?? '—';
        const medium = ov.medium_passwords ?? '—';
        const strong = ov.strong_passwords ?? '—';
        const unique = ov.unique_passwords ?? '—';
        const avgLen = ov.average_length   != null ? parseFloat(ov.average_length).toFixed(1) : '—';

        const hibp     = d.hibp || {};
        const breached = hibp.total_breached ?? null;

        const patterns  = d.patterns || {};
        const topPats   = buildTopPatterns(patterns);
        const insights  = (d.ai_insights || []).slice(0, 3);

        return `
        <div class="rpt-detail-inner">

            <!-- stat row -->
            <div class="rpt-detail-stats">
                <div class="rpt-ds-box rpt-ds--danger">
                    <span class="rpt-ds-num">${esc(weak)}</span>
                    <span class="rpt-ds-label">High Risk</span>
                </div>
                <div class="rpt-ds-box rpt-ds--warn">
                    <span class="rpt-ds-num">${esc(medium)}</span>
                    <span class="rpt-ds-label">Medium Risk</span>
                </div>
                <div class="rpt-ds-box rpt-ds--ok">
                    <span class="rpt-ds-num">${esc(strong)}</span>
                    <span class="rpt-ds-label">Low Risk</span>
                </div>
                <div class="rpt-ds-box">
                    <span class="rpt-ds-num">${esc(unique)}</span>
                    <span class="rpt-ds-label">Unique</span>
                </div>
                <div class="rpt-ds-box">
                    <span class="rpt-ds-num">${esc(avgLen)}</span>
                    <span class="rpt-ds-label">Avg Length</span>
                </div>
                ${breached !== null ? `
                <div class="rpt-ds-box rpt-ds--breach">
                    <span class="rpt-ds-num">${esc(breached)}</span>
                    <span class="rpt-ds-label">Breached</span>
                </div>` : ''}
            </div>

            <!-- patterns + insights side by side -->
            <div class="rpt-detail-cols">
                ${topPats ? `
                <div class="rpt-detail-col">
                    <h4 class="rpt-col-title"><i data-lucide="bar-chart-2"></i> Top Patterns</h4>
                    ${topPats}
                </div>` : ''}

                ${insights.length ? `
                <div class="rpt-detail-col">
                    <h4 class="rpt-col-title"><i data-lucide="sparkles"></i> AI Insights</h4>
                    <ul class="rpt-insights-list">
                        ${insights.map(ins => `<li>${esc(ins)}</li>`).join('')}
                    </ul>
                </div>` : ''}
            </div>

            <!-- action bar inside detail -->
            <div class="rpt-detail-actions">
                <button class="btn-report rpt-detail-dl-btn"
                        onclick="Reports.downloadPDF(${detail.id}, '${esc(detail.filename)}', this)">
                    <i data-lucide="download" style="width:14px;height:14px;"></i>
                    Download Full PDF Report
                </button>
            </div>
        </div>`;
    }

    function buildTopPatterns(patterns) {
        const rows = [];
        const add = (label, val, total) => {
            if (val == null || !total) return;
            const pct = Math.min(100, Math.round((val / total) * 100));
            rows.push({ label, val, pct });
        };
        const tot = patterns.total_passwords || 1;
        add('Dictionary words', patterns.dictionary_count,   tot);
        add('Common patterns',  patterns.common_patterns,    tot);
        add('No special chars', patterns.no_special,         tot);
        add('Reused',           patterns.duplicate_count,    tot);
        add('Short (< 8 chr)',  patterns.short_passwords,    tot);
        add('All lowercase',    patterns.all_lowercase,      tot);

        if (!rows.length) return '';
        return `<div class="rpt-pat-bars">
            ${rows.slice(0, 5).map(r => `
            <div class="rpt-pat-row">
                <span class="rpt-pat-label">${esc(r.label)}</span>
                <div class="rpt-pat-track">
                    <div class="rpt-pat-fill" style="width:${r.pct}%"></div>
                </div>
                <span class="rpt-pat-pct">${r.pct}%</span>
            </div>`).join('')}
        </div>`;
    }

    /* ─── main render ─────────────────────────────────────────────── */
    function renderReports(reports) {
        const container = $('reportsPageContent');
        if (!container) return;

        if (!reports || !reports.length) {
            container.innerHTML = buildEmptyState();
            if (window.lucide) lucide.createIcons();
            return;
        }

        // Build table header + rows
        container.innerHTML = `
        <div class="rpt-list-header">
            <span>File</span>
            <span></span>
            <span>Risk Level</span>
            <span>Score</span>
            <span>Passwords</span>
            <span></span>
        </div>
        <div class="rpt-list" id="rptList">
            ${reports.map(buildRow).join('')}
        </div>`;

        if (window.lucide) lucide.createIcons();
    }

    /* ─── public: toggle row expand ─────────────────────────────── */
    async function toggleRow(id) {
        const detailEl = $(`rpt-detail-${id}`);
        const rowEl    = $(`rpt-row-${id}`);
        if (!detailEl || !rowEl) return;

        const isOpen = rowEl.classList.contains('rpt-row--open');

        // Collapse any previously open row
        if (_expandedId && _expandedId !== id) {
            const prev = $(`rpt-row-${_expandedId}`);
            const prevD = $(`rpt-detail-${_expandedId}`);
            if (prev)  prev.classList.remove('rpt-row--open');
            if (prevD) { prevD.style.maxHeight = '0'; prevD.setAttribute('aria-hidden', 'true'); }
            const prevMain = prev && prev.querySelector('.rpt-row-main');
            if (prevMain) prevMain.setAttribute('aria-expanded', 'false');
        }

        if (isOpen) {
            // Collapse this row
            rowEl.classList.remove('rpt-row--open');
            detailEl.style.maxHeight = '0';
            detailEl.setAttribute('aria-hidden', 'true');
            rowEl.querySelector('.rpt-row-main').setAttribute('aria-expanded', 'false');
            _expandedId = null;
            return;
        }

        // Expand this row
        rowEl.classList.add('rpt-row--open');
        _expandedId = id;
        rowEl.querySelector('.rpt-row-main').setAttribute('aria-expanded', 'true');
        detailEl.setAttribute('aria-hidden', 'false');

        // Show loading state if not yet loaded
        if (!detailEl.dataset.loaded) {
            detailEl.innerHTML = `<div class="rpt-detail-inner rpt-detail-loading">
                <div class="rpt-spinner"></div><span>Loading report…</span>
            </div>`;
            detailEl.style.maxHeight = '120px';

            try {
                const detail = await fetchReportDetail(id);
                detailEl.innerHTML = buildDetailPanel(detail);
                detailEl.dataset.loaded = '1';
                if (window.lucide) lucide.createIcons();
            } catch (e) {
                detailEl.innerHTML = `<div class="rpt-detail-inner rpt-detail-error">
                    <i data-lucide="alert-circle"></i> ${esc(e.message)}
                </div>`;
                if (window.lucide) lucide.createIcons();
            }
        }

        // Animate to full height
        detailEl.style.maxHeight = detailEl.scrollHeight + 'px';
        // Allow growth for dynamic content
        setTimeout(() => { if (rowEl.classList.contains('rpt-row--open')) detailEl.style.maxHeight = 'none'; }, 420);
    }

    /* ─── public: download PDF ───────────────────────────────────── */
    async function downloadPDF(analysisId, filename, btn) {
        const allBtns = btn ? [btn] : [];
        // Also disable the sibling download button in the row header
        const headerBtn = $(`rpt-dl-${analysisId}`);
        if (headerBtn && !allBtns.includes(headerBtn)) allBtns.push(headerBtn);

        allBtns.forEach(b => { b.disabled = true; b.classList.add('rpt-dl-btn--loading'); });

        const origTexts = allBtns.map(b => b.innerHTML);
        allBtns.forEach(b => {
            b.innerHTML = `<i data-lucide="loader-2" style="width:14px;height:14px;" class="rpt-spin"></i> Generating…`;
        });
        if (window.lucide) lucide.createIcons();

        try {
            // Fetch the stored analysis data first
            const detail   = await fetchReportDetail(analysisId);
            const csrf     = await getCsrf();
            const headers  = { 'Content-Type': 'application/json' };
            if (csrf) headers['X-CSRFToken'] = csrf;

            // Re-use the existing /api/download-report endpoint
            // Pass full analysis_data so pdf_gen has everything it needs
            const payload  = Object.assign({}, detail.analysis_data || {}, {
                analysis_id: analysisId,
                filename:    detail.filename,
                risk_score:  detail.risk_score,
                risk_level:  detail.risk_level,
            });

            const res = await fetch('/api/download-report', {
                method: 'POST', headers, credentials: 'include',
                body: JSON.stringify(payload),
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.error || `Server error (${res.status})`);
            }

            const blob = await res.blob();
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = `securepass_report_${(filename || analysisId).replace(/[^a-z0-9._-]/gi, '_')}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);

            toast('Report downloaded.', 'success');
        } catch (e) {
            toast(e.message || 'Download failed.', 'error');
            allBtns.forEach((b, i) => { b.innerHTML = origTexts[i]; });
        } finally {
            allBtns.forEach((b, i) => {
                b.disabled = false;
                b.classList.remove('rpt-dl-btn--loading');
                if (b.classList.contains('rpt-dl-btn--loading')) b.innerHTML = origTexts[i];
                // Restore text only if still showing "Generating…"
                if (b.innerHTML.includes('Generating')) b.innerHTML = origTexts[i];
            });
            if (window.lucide) lucide.createIcons();
        }
    }

    /* ─── public: load page ──────────────────────────────────────── */
    async function loadPage(force) {
        if (_loading) return;
        if (_initialized && !force) return;

        _loading = true;
        _expandedId = null;
        _initialized = true;

        const container = $('reportsPageContent');
        if (!container) { _loading = false; return; }

        // Show skeleton while loading
        container.innerHTML = `<div class="rpt-list">${buildSkeleton(4)}</div>`;

        try {
            const history = await fetchHistory();
            // history: [{id, filename, created_at, risk_score, risk_level, total_passwords}, ...]
            renderReports(history);
        } catch (e) {
            container.innerHTML = `
            <div class="panel-empty-state">
                <i data-lucide="wifi-off"></i>
                <p>Could not load reports.</p>
                <span>${esc(e.message)}</span>
                <button class="btn-report rpt-cta-btn" onclick="Reports.loadPage(true)" style="margin-top:12px;">
                    <i data-lucide="refresh-cw" style="width:14px;height:14px;"></i> Retry
                </button>
            </div>`;
            if (window.lucide) lucide.createIcons();
        } finally {
            _loading = false;
        }
    }

    /* ─── clear all history ─────────────────────────────────────────── */
    function showClearModal() {
        const modal = $('rptClearModal');
        if (modal) modal.classList.add('rpt-modal--open');
    }

    function hideClearModal() {
        const modal = $('rptClearModal');
        if (modal) modal.classList.remove('rpt-modal--open');
    }

    async function confirmClearHistory() {
        const confirmBtn = $('rptClearConfirmBtn');
        if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Deleting…'; }
        try {
            const result = await apiClearHistory();
            hideClearModal();
            toast(result.message || 'History cleared.', 'success');
            _expandedId = null;
            _initialized = false;
            const list = $('rptList');
            if (list) {
                list.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                list.style.opacity = '0';
                list.style.transform = 'translateY(-8px)';
            }
            setTimeout(() => loadPage(true), 320);
        } catch (e) {
            toast(e.message || 'Failed to clear history.', 'error');
        } finally {
            if (confirmBtn) { confirmBtn.disabled = false; confirmBtn.textContent = 'Yes, Delete All'; }
        }
    }

    /* ─── hook into sidebar nav ──────────────────────────────────── */
    function hookNav() {
        // Intercept showPage calls for 'reports'
        const _origShowPage = window.showPage;
        window.showPage = function (name) {
            _origShowPage(name);
            if (name === 'reports') loadPage();
        };

        // Also hook direct nav-item clicks in case showPage override races
        document.querySelectorAll('[data-page="reports"]').forEach(el => {
            el.addEventListener('click', () => loadPage());
        });

        // Wire the top-level "Download PDF Report" header button
        const headerBtn = $('downloadBtnReports');
        if (headerBtn) {
            headerBtn.addEventListener('click', async () => {
                if (_expandedId) {
                    downloadPDF(_expandedId, null, headerBtn);
                } else {
                    toast('Click a report row to select it, then download.', 'info');
                }
            });
        }

        // Wire clear history button
        const clearBtn = $('rptClearBtn');
        if (clearBtn) clearBtn.addEventListener('click', showClearModal);

        // Wire modal buttons (delegated — modal injected into DOM by init)
        document.addEventListener('click', e => {
            if (e.target.id === 'rptClearConfirmBtn') confirmClearHistory();
            if (e.target.id === 'rptClearCancelBtn' || e.target.closest('#rptClearModal')?.classList.contains('rpt-modal--open') && e.target.classList.contains('rpt-modal-backdrop')) hideClearModal();
        });
        // Close on backdrop click
        const modal = $('rptClearModal');
        if (modal) {
            modal.addEventListener('click', e => {
                if (e.target === modal) hideClearModal();
            });
        }
    }

    /* ─── init ───────────────────────────────────────────────────── */
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => { hookNav(); });
        } else {
            hookNav();
        }
    }

    init();

    /* ─── public API ─────────────────────────────────────────────── */
    window.Reports = { loadPage, toggleRow, downloadPDF, showClearModal, hideClearModal, confirmClearHistory };

})();