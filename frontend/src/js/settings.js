/**
 * settings.js — SecurePass AI Settings Controller
 * Handles all real data fetch/save for the Settings panel.
 * Add a <script src="/static/js/settings.js"></script> before </body> in index.html
 */

(function () {
    'use strict';

    // ── State ─────────────────────────────────────────────────────────────── //
    let _settings = {};        // current loaded settings
    let _user     = {};        // current user profile

    // ── Compliance descriptions ───────────────────────────────────────────── //
    const COMPLIANCE_DESC = {
        nist:   'Digital Identity Guidelines for authentication and lifecycle management.',
        iso:    'ISO/IEC 27001 A.9.4 — User access management and access control policy.',
        pci:    'PCI DSS Requirement 8 — Strong password policy for cardholder data environments.',
        custom: 'Custom policy — configure thresholds and rules to fit your organisation.',
    };
    const DIGEST_DESC = {
        immediately: 'Notifications are sent the moment an event is detected.',
        daily:       'You will receive one consolidated digest every 24 hours.',
        weekly:      'All notifications are bundled into a single weekly summary email.',
        monthly:     'One monthly digest covering all alerts and reports.',
    };

    // ── Utilities ─────────────────────────────────────────────────────────── //
    function showToast(msg, type = 'ok') {
        const t = document.getElementById('settingsToast');
        if (!t) return;
        t.textContent = (type === 'ok' ? '✓ ' : '✗ ') + msg;
        t.className = `s-toast show toast-${type}`;
        clearTimeout(t._timer);
        t._timer = setTimeout(() => { t.className = 's-toast'; }, 3200);
    }

    function setFeedback(id, msg, type = 'ok') {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = msg;
        el.className = `s-feedback ${type}`;
        setTimeout(() => { el.textContent = ''; el.className = 's-feedback'; }, 3000);
    }

    function getCookie(name) {
        const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        return match ? decodeURIComponent(match[1]) : null;
    }

    function getCsrf() {
        return getCookie('csrf_access_token');
    }

    async function apiGet(url) {
        const r = await fetch(url, { credentials: 'same-origin' });
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    }

    async function apiPut(url, body) {
        const csrf = getCsrf();
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-TOKEN'] = csrf;
        const r = await fetch(url, {
            method: 'PUT',
            credentials: 'same-origin',
            headers,
            body: JSON.stringify(body),
        });
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    }

    async function apiPost(url, body) {
        const csrf = getCsrf();
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-TOKEN'] = csrf;
        const r = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers,
            body: JSON.stringify(body),
        });
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    }

    async function apiDelete(url, body) {
        const csrf = getCsrf();
        const headers = {};
        const opts = { method: 'DELETE', credentials: 'same-origin', headers };
        if (body !== undefined) {
            headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        if (csrf) headers['X-CSRF-TOKEN'] = csrf;
        const r = await fetch(url, opts);
        if (!r.ok) throw new Error(await r.text());
        return r.json();
    }

    function debounce(fn, ms) {
        let t;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    // ── Nav switching ─────────────────────────────────────────────────────── //
    function initNav() {
        const items = document.querySelectorAll('.settings-nav-item');
        items.forEach(item => {
            item.addEventListener('click', () => {
                items.forEach(i => i.classList.remove('active'));
                item.classList.add('active');
                const sec = item.dataset.section;
                document.querySelectorAll('.settings-panel').forEach(p => {
                    p.style.display = 'none';
                });
                const target = document.getElementById(sec + 'Section');
                if (target) target.style.display = 'flex';
                // Refresh live data when switching to Security tab
                if (sec === 'security') loadSessionInfo();
                // Refresh storage when switching to Data tab
                if (sec === 'data') loadStorage();
            });
        });
    }

    // ── Load all data ─────────────────────────────────────────────────────── //
    async function loadAll() {
        const loader = document.getElementById('settingsLoader');
        if (loader) loader.classList.remove('hidden');
        try {
            const [sRes, uRes, stRes] = await Promise.all([
                apiGet('/api/settings'),
                apiGet('/api/auth/me'),
                apiGet('/api/settings/storage'),
            ]);
            _settings = sRes.settings || {};
            // Handle both {user: {...}} and flat {email, username, ...} response shapes
            _user = uRes.user || uRes || {};
            // Enrich user with live analysis count from storage endpoint
            if (stRes && stRes.analysis_count !== undefined) {
                _user.analysis_count = stRes.analysis_count;
            }

            populateProfile();
            populateNotifications();
            _populateStorageUI(stRes);
            loadSessionInfo();
        } catch (e) {
            showToast('Failed to load settings — please refresh.', 'err');
        } finally {
            if (loader) loader.classList.add('hidden');
        }
    }

    // ── Profile ───────────────────────────────────────────────────────────── //
    function populateProfile() {
        const u = _user;
        if (!u || !u.email) return;

        const name     = u.username || u.name || u.email.split('@')[0];
        const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?';

        setText('profileAvatarInitials', initials);
        setText('profileDisplayName',   name);
        setText('profileDisplayEmail',  u.email);

        // Account type — use plan/tier from server if available, default to 'Free'
        const accountType = u.plan || u.account_type || u.tier || 'Free';
        setText('profileAccountType', accountType);

        // Analysis count — populated from storage endpoint
        setText('profileAnalysisCount', u.analysis_count ?? '—');

        if (u.created_at) {
            const joinDate = parseUTC(u.created_at);
            const days = joinDate ? Math.floor((Date.now() - joinDate) / 86400000) : '—';
            setText('profileMemberSince', fmtMonthYear(u.created_at));
            setText('profileJoinedDays', days);
        } else {
            setText('profileMemberSince', '—');
            setText('profileJoinedDays', '—');
        }

        if (u.last_login) {
            setText('profileLastLogin', fmtShortDate(u.last_login));
        } else {
            setText('profileLastLogin', '—');
        }

        const nameInput = document.getElementById('profileNameInput');
        if (nameInput) nameInput.value = u.username || u.name || '';

        // Security section — session info loaded separately via loadSessionInfo()
    }

    // ── Session / Account Activity ─────────────────────────────────────────── //
    async function loadSessionInfo() {
        try {
            const res = await apiGet('/api/settings/session');

            // Browser + OS as the "device" label
            const browserOS = [res.browser, res.os].filter(Boolean).join(' · ');
            setText('sessionBrowserOS', browserOS || 'Current Session');

            // Last login with full date + time — browser converts UTC → local timezone
            setText('sessionLastLogin', res.last_login
                ? 'Last login: ' + fmtDateTime(res.last_login)
                : 'Last login: —');

            // IP
            setText('sessionIP', res.ip || '—');

            // Analysis count
            setText('sessionAnalysisCount', res.total_analyses !== undefined
                ? res.total_analyses + ' analysis' + (res.total_analyses !== 1 ? 'es' : '')
                : '—');

            // Member since
            setText('sessionCreatedAt', fmtDate(res.created_at));

            // Also update profile section stats with fresh counts
            if (res.total_analyses !== undefined) {
                setText('profileAnalysisCount', res.total_analyses);
                _user.analysis_count = res.total_analyses;
            }
        } catch {
            setText('sessionBrowserOS', 'Current Session');
            setText('sessionLastLogin', 'Could not load session data');
        }
    }

    document.addEventListener('click', async (e) => {
        if (!e.target.matches('#btnSaveProfile')) return;
        const input = document.getElementById('profileNameInput');
        const name  = input ? input.value.trim() : '';
        if (!name) { setFeedback('profileSaveFb', 'Name cannot be empty.', 'err'); return; }
        try {
            const res = await apiPut('/api/settings/profile', { username: name });
            const saved = res.user || res || {};
            // Merge — preserve analysis_count which to_dict() may not return
            _user = Object.assign({}, _user, saved);
            populateProfile();
            setFeedback('profileSaveFb', 'Saved ✓');
            showToast('Profile updated.');
        } catch {
            setFeedback('profileSaveFb', 'Failed to save.', 'err');
        }
    });

    // ── Notifications ─────────────────────────────────────────────────────── //
    function populateNotifications() {
        const s = _settings;
        setToggle('weekly_report',  s.weekly_report  !== false);
        setToggle('breach_alerts',  s.breach_alerts  !== false);
        setToggle('score_alerts',   !!s.score_alerts);
        setToggle('email_notifications', s.email_notifications !== false);

        const sel = document.getElementById('digestFreqSelect');
        if (sel) {
            sel.value = s.digest_frequency || 'daily';
            updateDigestPill(sel.value);
        }

        // Show real email
        if (_user.email) setText('notifEmailDisplay', _user.email);
    }

    function updateDigestPill(val) {
        const pill = document.getElementById('digestPill');
        if (pill) pill.textContent = DIGEST_DESC[val] || '';
    }

    document.addEventListener('change', (e) => {
        if (e.target.id === 'digestFreqSelect') updateDigestPill(e.target.value);
    });

    document.addEventListener('click', async (e) => {
        if (e.target.matches('#btnSaveNotif')) {
            try {
                const payload = {
                    weekly_report:       getToggle('weekly_report'),
                    breach_alerts:       getToggle('breach_alerts'),
                    score_alerts:        getToggle('score_alerts'),
                    email_notifications: getToggle('email_notifications'),
                };
                await apiPut('/api/settings', payload);
                Object.assign(_settings, payload);
                setFeedback('notifSaveFb', 'Saved ✓');
                showToast('Notification preferences saved.');
            } catch {
                setFeedback('notifSaveFb', 'Error.', 'err');
            }
        }
        if (e.target.matches('#btnSaveDigest')) {
            try {
                const freq = document.getElementById('digestFreqSelect')?.value;
                await apiPut('/api/settings', { digest_frequency: freq });
                _settings.digest_frequency = freq;
                setFeedback('digestSaveFb', 'Saved ✓');
                showToast('Digest frequency saved.');
            } catch {
                setFeedback('digestSaveFb', 'Error.', 'err');
            }
        }
    });

    // ── Data & Export ─────────────────────────────────────────────────────── //
    function _populateStorageUI(res) {
        if (!res) return;
        setText('storageUsedMb',        res.used_mb       ?? 0);
        setText('storageAnalysisCount', res.analysis_count ?? 0);
        setText('storageLimitMb',       res.limit_mb      ?? 500);
        setText('storageBarLabel',      (res.used_pct ?? 0) + '% used');
        const fill = document.getElementById('storageBarFill');
        if (fill) fill.style.width = (Math.min(res.used_pct || 0, 100)) + '%';

        // Retention pills
        const days = _settings.retention_days || 90;
        document.querySelectorAll('#retentionPills .s-pill').forEach(p => {
            p.classList.toggle('active', parseInt(p.dataset.days) === days);
        });
    }

    async function loadStorage() {
        try {
            const res = await apiGet('/api/settings/storage');
            _user.analysis_count = res.analysis_count ?? _user.analysis_count;
            _populateStorageUI(res);
        } catch { /* silent */ }
    }

    // Retention pills
    document.addEventListener('click', (e) => {
        const pill = e.target.closest('#retentionPills .s-pill');
        if (!pill) return;
        document.querySelectorAll('#retentionPills .s-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        _settings.retention_days = parseInt(pill.dataset.days);
    });

    document.addEventListener('click', async (e) => {
        if (e.target.matches('#btnSaveRetention')) {
            try {
                await apiPut('/api/settings', { retention_days: _settings.retention_days });
                setFeedback('retentionSaveFb', 'Saved ✓');
                showToast('Retention policy saved.');
            } catch {
                setFeedback('retentionSaveFb', 'Error.', 'err');
            }
        }

        if (e.target.matches('#btnExportPrefs')) {
            window.location.href = '/api/settings/export';
        }

        if (e.target.matches('#btnImportPrefs')) {
            document.getElementById('importPrefsFile')?.click();
        }

        if (e.target.matches('#btnClearCache')) {
            if (!confirm('Clear local browser cache? This cannot be undone.')) return;
            try {
                localStorage.removeItem('sp_chart_cache');
                sessionStorage.clear();
                showToast('Local cache cleared.');
            } catch {
                showToast('Could not clear cache.', 'err');
            }
        }

        if (e.target.matches('#btnDeleteAnalyses')) {
            if (!confirm('Permanently delete ALL saved analyses? This cannot be undone.')) return;
            try {
                const res = await apiDelete('/api/settings/delete-analyses');
                showToast(`${res.deleted} analyses deleted.`);
                loadStorage();
            } catch {
                showToast('Failed to delete analyses.', 'err');
            }
        }
    });

    // Import file
    document.addEventListener('change', async (e) => {
        if (e.target.id !== 'importPrefsFile') return;
        const file = e.target.files?.[0];
        if (!file) return;
        const text = await file.text();
        try {
            const json = JSON.parse(text);
            const fd   = new FormData();
            fd.append('file', file);
            const r = await fetch('/api/settings/import', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(json),
            });
            const res = await r.json();
            if (!r.ok) throw new Error(res.error);
            _settings = res.settings || _settings;
            populateNotifications();
            loadStorage();
            showToast('Preferences imported successfully.');
        } catch {
            showToast('Invalid preferences file.', 'err');
        }
        e.target.value = '';
    });

    // ── Security ──────────────────────────────────────────────────────────── //

    // Password toggle show/hide
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.s-pw-toggle');
        if (!btn) return;
        const inp = document.getElementById(btn.dataset.target);
        if (!inp) return;
        inp.type = inp.type === 'password' ? 'text' : 'password';
    });

    // Strength meter
    document.addEventListener('input', (e) => {
        if (e.target.id !== 'newPwInput') return;
        const pw = e.target.value;
        const wrap  = document.getElementById('pwStrengthWrap');
        const fill  = document.getElementById('pwStrengthFill');
        const label = document.getElementById('pwStrengthLabel');
        if (!wrap) return;
        if (!pw) { wrap.style.display = 'none'; return; }
        wrap.style.display = 'flex';
        let score = 0;
        if (pw.length >= 8)                score++;
        if (/[A-Z]/.test(pw))              score++;
        if (/[0-9]/.test(pw))              score++;
        if (/[^A-Za-z0-9]/.test(pw))       score++;
        if (pw.length >= 12)               score++;
        const levels = [
            { pct: '20%',  color: '#ff4d6d', text: 'Very Weak' },
            { pct: '40%',  color: '#f5a623', text: 'Weak' },
            { pct: '60%',  color: '#ffd700', text: 'Fair' },
            { pct: '80%',  color: '#00e5ff', text: 'Strong' },
            { pct: '100%', color: '#00ff88', text: 'Very Strong' },
        ];
        const lv = levels[Math.max(0, score - 1)];
        fill.style.width    = lv.pct;
        fill.style.background = lv.color;
        label.textContent   = lv.text;
        label.style.color   = lv.color;
    });

    document.addEventListener('click', async (e) => {
        if (!e.target.matches('#btnChangePw')) return;
        const cur  = document.getElementById('currentPwInput')?.value || '';
        const nw   = document.getElementById('newPwInput')?.value     || '';
        const conf = document.getElementById('confirmPwInput')?.value  || '';

        if (!cur || !nw) { setFeedback('changePwFb', 'Fill in all fields.', 'err'); return; }
        if (nw !== conf) { setFeedback('changePwFb', 'Passwords do not match.', 'err'); return; }
        if (nw.length < 8) { setFeedback('changePwFb', 'Min 8 characters.', 'err'); return; }

        try {
            await apiPost('/api/settings/change-password', { current_password: cur, new_password: nw });
            setFeedback('changePwFb', 'Password updated ✓');
            showToast('Password changed successfully.');
            ['currentPwInput','newPwInput','confirmPwInput'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            const wrap = document.getElementById('pwStrengthWrap');
            if (wrap) wrap.style.display = 'none';
        } catch (err) {
            let msg = 'Error changing password.';
            try { msg = JSON.parse(err.message).error || msg; } catch { /**/ }
            setFeedback('changePwFb', msg, 'err');
        }
    });

    document.addEventListener('click', async (e) => {
        if (!e.target.matches('#btnLogoutAll')) return;
        if (!confirm('Log out all devices? You will also be logged out here.')) return;
        try {
            await apiPost('/api/auth/logout', {});
            showToast('Logged out from all devices.');
            setTimeout(() => { window.location.href = '/login'; }, 1500);
        } catch {
            showToast('Logout failed.', 'err');
        }
    });

    document.addEventListener('click', async (e) => {
        if (!e.target.matches('#btnDeleteAccount')) return;
        const first = confirm(
            'PERMANENTLY DELETE your account?\n\n' +
            'All your data, analyses, and preferences will be removed. ' +
            'This action cannot be undone.'
        );
        if (!first) return;
        const typed = prompt('Type DELETE to confirm account deletion:');
        if (typed !== 'DELETE') {
            showToast('Account deletion cancelled.', 'err');
            return;
        }
        const pw = prompt('Enter your password to confirm:');
        if (!pw) {
            showToast('Account deletion cancelled.', 'err');
            return;
        }
        try {
            await apiDelete('/api/settings/account', { current_password: pw });
            showToast('Account deleted. Redirecting…');
            setTimeout(() => { window.location.href = '/login'; }, 1800);
        } catch {
            showToast('Failed to delete account. Please contact support.', 'err');
        }
    });

    // ── Toggle helpers ────────────────────────────────────────────────────── //
    function setToggle(setting, value) {
        const el = document.querySelector(`.s-toggle[data-setting="${setting}"]`);
        if (!el) return;
        el.classList.toggle('active', !!value);
    }
    function getToggle(setting) {
        const el = document.querySelector(`.s-toggle[data-setting="${setting}"]`);
        return el ? el.classList.contains('active') : false;
    }

    // Toggle click handler
    document.addEventListener('click', (e) => {
        const toggle = e.target.closest('.s-toggle');
        if (!toggle || !toggle.dataset.setting) return;
        toggle.classList.toggle('active');
        // Optimistic update
        _settings[toggle.dataset.setting] = toggle.classList.contains('active');
    });

    // ── Date formatting helpers ───────────────────────────────────────────── //
    function parseUTC(isoStr) {
        if (!isoStr) return null;
        // Ensure the string is treated as UTC — append Z if missing
        const s = isoStr.endsWith('Z') || isoStr.includes('+') ? isoStr : isoStr + 'Z';
        const d = new Date(s);
        return isNaN(d.getTime()) ? null : d;
    }

    function fmtDateTime(isoStr) {
        const d = parseUTC(isoStr);
        if (!d) return '—';
        return d.toLocaleString(undefined, {
            day: '2-digit', month: 'short', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    }

    function fmtDate(isoStr) {
        const d = parseUTC(isoStr);
        if (!d) return '—';
        return d.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
    }

    function fmtMonthYear(isoStr) {
        const d = parseUTC(isoStr);
        if (!d) return '—';
        return 'Since ' + d.toLocaleDateString(undefined, { month: 'short', year: 'numeric' });
    }

    function fmtShortDate(isoStr) {
        const d = parseUTC(isoStr);
        if (!d) return '—';
        return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
    function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }
    function setSlider(id, val) {
        const el = document.getElementById(id);
        if (el) el.value = val;
    }
    function setStyle(id, prop, val) {
        const el = document.getElementById(id);
        if (el) el.style[prop] = val;
    }

    // ── Init on settings page open ────────────────────────────────────────── //
    function initSettings() {
        initNav();
        loadAll();
    }

    // Hook into existing page navigation — called when settings page is shown
    const originalShowPage = window.showPage;
    if (typeof originalShowPage === 'function') {
        window.showPage = function (page, ...args) {
            originalShowPage(page, ...args);
            if (page === 'settings') initSettings();
        };
    }

    // Also hook the settings button directly
    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('settingsBtn');
        if (btn) {
            btn.addEventListener('click', () => {
                setTimeout(initSettings, 50);
            });
        }
        // If settings panel is already active on load (e.g. deep-link)
        const panel = document.getElementById('page-settings');
        if (panel && panel.style.display !== 'none') initSettings();
    });

    // Expose for direct calls
    window.initSettings = initSettings;

})();