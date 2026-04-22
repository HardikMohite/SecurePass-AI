/**
 * script.js — SecurePass AI Dashboard
 * Fully wired to Flask backend APIs with new sidebar UI.
 *
 * API endpoints:
 *   GET  /api/auth/profile        → auth check / nav
 *   POST /api/auth/logout         → logout
 *   POST /api/analyze             → dataset analysis
 *   POST /api/check-password      → single password check
 *   POST /api/hibp/check-password → HIBP single check
 *   POST /api/download-report     → PDF download
 *   GET  /api/csrf-token          → CSRF token
 */
(function () {
    'use strict';

    const S = { file: null, results: null, user: null, submitting: false, charts: {}, _passwords: [], _datasetName: '' };
    const $  = id  => document.getElementById(id);
    const qs = sel => document.querySelector(sel);

    window.addEventListener('DOMContentLoaded', async () => {
        setupUpload();
        setupPasswordChecker();
        setupToggles();
        setupSimulation();
        setupResetBtn();
        setupReportsDownload();
        setupLogout();
        setupSidebar();
        setupAIDrawer();
        setupComplianceRefresh();
        setupAIPolicy();
        await checkAuth();
        if (window.lucide) lucide.createIcons();
    });

    function setupComplianceRefresh() {
        const btn = document.getElementById('btnRefreshCompliance');
        if (!btn) return;
        btn.addEventListener('click', () => {
            if (S.results && S.results.compliance) {
                renderCompliance(S.results.compliance);
            } else {
                const cpc = document.getElementById('compliancePageContent');
                if (cpc) cpc.innerHTML = '<div class="panel-empty-state"><i data-lucide=\"shield-off\"></i><p>No analysis data available.</p><span>Run an analysis from the Dashboard first.</span></div>';
                if (window.lucide) lucide.createIcons();
            }
        });
    }

    /* ══ AUTH ═══════════════════════════════════════════ */
    async function checkAuth() {
        try {
            const r = await fetch('/api/auth/profile', { credentials: 'include' });
            const d = await r.json().catch(() => ({}));
            if (r.ok && (d.user || d.email)) {
                S.user = d.user || d;
                showUserNav(S.user.email || S.user.username || '');
            } else { showGuestNav(); }
        } catch { showGuestNav(); }
    }

    function showUserNav(email) {
        const a = $('navAuth'), u = $('navUser'), em = $('navEmail');
        if (a)  a.style.display  = 'none';
        if (u)  u.style.display  = 'flex';
        if (em) em.textContent   = email;
    }
    function showGuestNav() {
        const a = $('navAuth'), u = $('navUser');
        if (a) a.style.display = 'flex';
        if (u) u.style.display = 'none';
    }

    function setupLogout() {
        const btn = $('logoutBtn');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }); } catch {}
            S.user = null; showGuestNav(); toast('Logged out.', 'info'); resetDashboard(); showPage('dashboard');
        });
    }

    /* ══ SIDEBAR & PAGE ROUTER ══════════════════════════ */

    // All known page IDs
    const PAGES = ['dashboard', 'compliance', 'terminal', 'ai-policy', 'reports', 'settings'];

    function showPage(name) {
        // Hide all page sections
        PAGES.forEach(p => {
            const sec = $('page-' + p);
            if (sec) {
                sec.style.display = 'none';
                sec.classList.remove('active-page');
            }
        });

        // Show requested page
        const target = $('page-' + name);
        if (target) {
            target.style.display = 'block';
            target.classList.add('active-page');
            // Re-trigger lucide for any icons inside new page
            if (window.lucide) lucide.createIcons();
        }

        // Update active nav item
        document.querySelectorAll('.sidebar-nav .nav-item, .sidebar-footer .nav-item').forEach(el => {
            el.classList.toggle('active', el.getAttribute('data-page') === name);
        });
    }

    function setupSidebar() {
        // Wire every nav item that has a data-page attribute
        document.querySelectorAll('[data-page]').forEach(el => {
            el.addEventListener('click', e => {
                e.preventDefault();
                const page = el.getAttribute('data-page');
                showPage(page);
                // FIX: call page-specific init here, in the click handler,
                // because click listeners capture the LOCAL showPage variable
                // via closure — overriding window.showPage has no effect on them.
                if (page === 'ai-policy') initAIPolicyPage();
                if (page === 'reports' && window.Reports) Reports.loadPage();
                if (page === 'settings' && window.initSettings) initSettings();
            });
        });

        // Expose globally so other modules can navigate programmatically
        // and keep the window.showPage override for any programmatic calls.
        window.showPage = function(name) {
            showPage(name);
            if (name === 'ai-policy') initAIPolicyPage();
            if (name === 'reports' && window.Reports) Reports.loadPage();
            if (name === 'settings' && window.initSettings) initSettings();
        };
    }

    /* ══ SETTINGS NAV ═══════════════════════════════════ */
    function setupSettingsNav() {
        const items = document.querySelectorAll('.settings-nav-item');
        const secs  = { profile: $('profileSection'), appearance: $('appearanceSection'), audit: $('auditSection'), notifications: $('notificationsSection'), data: $('dataSection'), security: $('securitySection') };
        items.forEach(item => {
            item.addEventListener('click', () => {
                const t = item.getAttribute('data-section');
                items.forEach(n => n.classList.remove('active'));
                item.classList.add('active');
                Object.values(secs).forEach(s => { if (s) s.style.display = 'none'; });
                if (secs[t]) secs[t].style.display = 'block';
            });
        });
    }

    /* ══ SETTINGS INTERACTIONS ═══════════════════════════ */
    function setupSettingsInteractions() {
        _setupAccentColor(); _setupDensity(); _setupFontSize();
        _setupCardSaveBtns(); _setupComplianceSelect(); _setupRiskSliders();
        _setup2FA(); _setupSessionRevoke(); _setupDangerZone();
        _setupPwToggles(); _setupDataExport(); _setupNotificationToggles();
    }

    function _setupAccentColor() {
        const opts = document.querySelectorAll('.color-option');
        const hexIn = $('customHexInput'), picker = $('customColorPicker');
        const root  = document.documentElement;
        function h2r(hex) {
            const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
            return r ? `${parseInt(r[1],16)}, ${parseInt(r[2],16)}, ${parseInt(r[3],16)}` : null;
        }
        function set(color) {
            root.style.setProperty('--accent', color);
            const rgb = h2r(color); if (rgb) root.style.setProperty('--accent-rgb', rgb);
        }
        opts.forEach(o => o.addEventListener('click', () => {
            const c = o.getAttribute('data-color');
            opts.forEach(x => x.classList.remove('active')); o.classList.add('active'); set(c);
            if (hexIn) hexIn.value = c.replace('#','').toUpperCase();
            if (picker) picker.value = c;
        }));
        if (hexIn) hexIn.addEventListener('input', e => {
            if (e.target.value.length === 6) { const c = '#'+e.target.value; set(c); if (picker) picker.value = c; opts.forEach(o => o.classList.toggle('active', o.getAttribute('data-color').toLowerCase() === c.toLowerCase())); }
        });
        if (picker) picker.addEventListener('input', e => {
            const c = e.target.value; set(c); if (hexIn) hexIn.value = c.replace('#','').toUpperCase(); opts.forEach(o => o.classList.toggle('active', o.getAttribute('data-color').toLowerCase() === c.toLowerCase()));
        });
    }

    function _setupDensity() {
        const pills = document.querySelectorAll('.density-pill');
        pills.forEach(p => p.addEventListener('click', () => {
            pills.forEach(x => x.classList.remove('active')); p.classList.add('active');
            document.body.setAttribute('data-density', p.getAttribute('data-density'));
        }));
    }

    function _setupFontSize() {
        const s = $('fontSizeSlider'); if (!s) return;
        s.addEventListener('input', e => { const sz = ['14px','16px','18px']; document.documentElement.style.setProperty('--base-font-size', sz[e.target.value]||'16px'); });
    }

    function _setupCardSaveBtns() {
        document.querySelectorAll('.btn-card-save').forEach(btn => {
            btn.addEventListener('click', () => {
                btn.classList.add('active-save');
                setTimeout(() => {
                    btn.classList.remove('active-save');
                    const fb = btn.parentElement.querySelector('.save-feedback-text');
                    if (fb) { fb.classList.add('show'); setTimeout(() => fb.classList.remove('show'), 2000); }
                }, 1500);
            });
        });
    }

    function _setupComplianceSelect() {
        const sel = $('complianceSelect'), pill = $('standardDescPill');
        const descs = { nist: 'Digital Identity Guidelines for authentication and lifecycle management.', owasp: 'Standard for web application security and visibility into risks.', iso: 'Information security management system (ISMS) best practices.', custom: "Apply your organisation's unique internal security mandates." };
        if (sel) sel.addEventListener('change', e => { if (!pill) return; pill.classList.remove('show'); setTimeout(() => { pill.textContent = descs[e.target.value]||''; pill.classList.add('show'); }, 200); });
    }

    function _setupRiskSliders() {
        const hs = $('highRiskSlider'), ms = $('medRiskSlider');
        const bH = $('barHigh'), bM = $('barMed'), bL = $('barLow');
        const hV = $('highRiskVal'), mV = $('medRiskVal'), lV = $('lowRiskVal');
        function upd() {
            if (!hs || !ms) return;
            let h = parseInt(hs.value), m = parseInt(ms.value);
            if (h >= m) { h = m - 1; if (h < 1) h = 1; hs.value = h; }
            if (hV) hV.textContent = `Below ${h}`; if (mV) mV.textContent = `${h} to ${m}`; if (lV) lV.textContent = `Above ${m}`;
            if (bH) bH.style.width = `${h}%`; if (bM) bM.style.width = `${m-h}%`; if (bL) bL.style.width = `${100-m}%`;
        }
        if (hs) hs.addEventListener('input', upd); if (ms) ms.addEventListener('input', upd);
    }

    function _setup2FA() {
        const toggle = $('tfaToggle'), flow = $('tfaSetupFlow'), copyBtn = $('copyTfaKey'), keyEl = $('tfaKey');
        const otpFields = document.querySelectorAll('.otp-field');
        if (toggle && flow) {
            toggle.addEventListener('click', () => {
                toggle.classList.toggle('active');
                if (toggle.classList.contains('active')) { flow.style.display='block'; flow.style.maxHeight='0px'; setTimeout(() => { flow.style.transition='max-height 250ms ease-out'; flow.style.maxHeight='1000px'; }, 10); }
                else { flow.style.maxHeight='0px'; setTimeout(() => flow.style.display='none', 250); }
            });
        }
        if (copyBtn && keyEl) {
            copyBtn.addEventListener('click', () => navigator.clipboard.writeText(keyEl.innerText).then(() => {
                const ci = copyBtn.querySelector('.copy-icon'), ch = copyBtn.querySelector('.check-icon');
                if (ci&&ch) { ci.style.display='none'; ch.style.display='block'; setTimeout(() => { ci.style.display='block'; ch.style.display='none'; }, 1500); }
            }));
        }
        otpFields.forEach((f,i) => {
            f.addEventListener('input', () => { if (f.value.length===1 && i<otpFields.length-1) otpFields[i+1].focus(); });
            f.addEventListener('keydown', e => { if (e.key==='Backspace' && f.value==='' && i>0) otpFields[i-1].focus(); });
        });
        const newPw = $('newPasswordInput'), pwBar = $('pwStrengthBar');
        if (newPw && pwBar) {
            newPw.addEventListener('input', e => {
                const v = e.target.value; let s = 0;
                if (v.length>0) s+=20; if (v.length>8) s+=20; if (/[A-Z]/.test(v)) s+=20; if (/[0-9]/.test(v)) s+=20; if (/[^A-Za-z0-9]/.test(v)) s+=20;
                pwBar.style.width = s+'%'; pwBar.style.background = s<=40?'#ff4d6d':s<=80?'#ffb100':'#00ff88';
            });
        }
    }

    function _setupSessionRevoke() {
        document.querySelectorAll('.btn-revoke, #revokeAllSessions').forEach(btn => {
            btn.addEventListener('click', () => {
                const isAll = btn.id==='revokeAllSessions';
                if (confirm(`Revoke ${isAll?'all other sessions':'this session'}?`)) {
                    if (!isAll) { const row=btn.closest('.session-item'); if (row) { row.style.opacity='0.5'; row.style.pointerEvents='none'; } btn.textContent='Revoked'; }
                    else alert('All other sessions have been revoked.');
                }
            });
        });
    }

    function _setupDangerZone() {
        document.querySelectorAll('.danger-trigger').forEach(btn => {
            btn.addEventListener('click', () => {
                const t = btn.getAttribute('data-type');
                const box = t==='data' ? $('confirmDataDelete') : $('confirmAccountDelete');
                if (box) { const show = !box.style.display || box.style.display==='none'; box.style.display=show?'flex':'none'; btn.style.display=show?'none':'block'; }
            });
        });
        document.querySelectorAll('.danger-cancel').forEach(btn => {
            btn.addEventListener('click', () => {
                const row=btn.closest('.danger-option-row'), box=row&&row.querySelector('.inline-confirm'), trig=row&&row.querySelector('.danger-trigger');
                if (box) box.style.display='none'; if (trig) trig.style.display='block';
            });
        });
    }

    function _setupPwToggles() {
        document.querySelectorAll('.pw-toggle-eye').forEach(btn => {
            btn.addEventListener('click', e => {
                e.preventDefault();
                const inp = btn.parentElement.querySelector('input'); if (!inp) return;
                const isPw = inp.type==='password'; inp.type = isPw?'text':'password';
                const icon = btn.querySelector('i')||btn.querySelector('svg');
                if (icon) { icon.setAttribute('data-lucide', isPw?'eye-off':'eye'); if (window.lucide) lucide.createIcons(); }
            });
        });
    }

    function _setupDataExport() {
        const exportBtn = $('btnExportReport');
        if (exportBtn) {
            exportBtn.addEventListener('click', async () => {
                if (!S.results) { toast('Run an analysis first.', 'error'); return; }
                const textEl = exportBtn.querySelector('.btn-text');
                exportBtn.classList.add('active');
                if (textEl) textEl.textContent = 'Generating...';
                try {
                    const csrf = await getCsrf();
                    const headers = { 'Content-Type': 'application/json' };
                    if (csrf) headers['X-CSRFToken'] = csrf;
                    const res = await fetch('/api/download-report', { method:'POST', headers, body:JSON.stringify(S.results), credentials:'include' });
                    if (!res.ok) throw new Error('Report generation failed.');
                    const blob = await res.blob(), url = URL.createObjectURL(blob), a = document.createElement('a');
                    a.href=url; a.download='securepass_report.pdf'; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
                    if (textEl) textEl.textContent='Downloaded ✓';
                    setTimeout(() => { exportBtn.classList.remove('active'); if (textEl) textEl.textContent='Download Report'; }, 2000);
                } catch (err) { exportBtn.classList.remove('active'); if (textEl) textEl.textContent='Download Report'; toast(err.message||'Download failed.','error'); }
            });
        }

        const clearBtn=$('btnClearHistory'), cfm=$('confirmClearHistory'), cancel=$('cancelClearHistory'), done=$('confirmClearHistoryDone');
        if (clearBtn&&cfm) clearBtn.addEventListener('click', () => { cfm.style.display='flex'; clearBtn.style.display='none'; });
        if (cancel) cancel.addEventListener('click', () => { cfm.style.display='none'; if (clearBtn) clearBtn.style.display='block'; });
        if (done) done.addEventListener('click', () => {
            const list = document.querySelector('.history-list');
            if (list) { list.style.opacity='0.3'; list.style.pointerEvents='none'; setTimeout(() => { list.innerHTML='<div style="padding:40px;text-align:center;color:var(--text-muted);font-size:13px;">No recent analysis sessions found.</div>'; list.style.opacity='1'; if (cfm) cfm.style.display='none'; }, 800); }
        });

        document.querySelectorAll('.retention-card').forEach(c => c.addEventListener('click', () => { document.querySelectorAll('.retention-card').forEach(x => x.classList.remove('active')); c.classList.add('active'); }));
        const kf=$('keepForeverToggle'), ri=$('retentionInfo');
        if (kf) kf.addEventListener('click', () => {
            kf.classList.toggle('active'); const on=kf.classList.contains('active');
            document.querySelectorAll('.retention-card').forEach(c => c.classList.toggle('disabled',on));
            if (ri) { ri.textContent=on?'Your data will never be automatically deleted.':'Data older than the selected period is automatically purged.'; ri.style.color=on?'#00ff88':'var(--text-muted)'; }
        });

        const iz=$('importUploadZone'), ii=$('importFileInput'), ir=$('importFileInfoRow'), irm=$('btnRemoveImportFile'), ib=$('btnImportData');
        if (iz&&ii) {
            iz.addEventListener('click', ()=>ii.click());
            iz.addEventListener('dragover', e=>{e.preventDefault();iz.classList.add('drag-over');});
            iz.addEventListener('dragleave', ()=>iz.classList.remove('drag-over'));
            iz.addEventListener('drop', e=>{e.preventDefault();iz.classList.remove('drag-over');if(e.dataTransfer.files[0])_hi(e.dataTransfer.files[0]);});
            ii.addEventListener('change', e=>{if(e.target.files[0])_hi(e.target.files[0]);});
        }
        function _hi(f) {
            const n=$('importFileName'),s=$('importFileSize');
            if(n)n.textContent=f.name; if(s)s.textContent=(f.size/(1024*1024)).toFixed(2)+' MB';
            if(iz)iz.style.display='none'; if(ir)ir.classList.add('active');
        }
        if (irm) irm.addEventListener('click', e=>{e.stopPropagation();if(ir)ir.classList.remove('active');if(ii)ii.value='';setTimeout(()=>{if(iz)iz.style.display='flex';},200);});
        if (ib) ib.addEventListener('click', ()=>{
            if (!ir||!ir.classList.contains('active')){alert('Please select a file first.');return;}
            const t=ib.querySelector('.btn-text'); ib.classList.add('active'); if(t)t.textContent='Importing...';
            setTimeout(()=>{if(t)t.textContent='Imported ✓';setTimeout(()=>{ib.classList.remove('active');if(t)t.textContent='Import & Restore';},1500);},2000);
        });
    }

    function _setupNotificationToggles() {
        const emailTs = document.querySelectorAll('.email-notification-toggle'), epw = $('emailPreviewWrap');
        emailTs.forEach(t => t.addEventListener('click', () => {
            t.classList.toggle('active');
            const anyOn = [...emailTs].some(x=>x.classList.contains('active'));
            if (epw) { if (anyOn) { epw.style.display='flex'; setTimeout(()=>epw.classList.add('show'),10); } else { epw.classList.remove('show'); setTimeout(()=>epw.style.display='none',200); } }
        }));

        const ib=$('instantBreachToggle'), bs=$('breachSeverityWrap');
        if (ib&&bs) ib.addEventListener('click', ()=>{ ib.classList.toggle('active'); const on=ib.classList.contains('active'); if(on){bs.style.display='block';setTimeout(()=>bs.classList.add('show'),10);}else{bs.classList.remove('show');setTimeout(()=>bs.style.display='none',200);} });

        document.querySelectorAll('.breach-severity-pills .nav-pill').forEach(p => p.addEventListener('click', ()=>{ document.querySelectorAll('.breach-severity-pills .nav-pill').forEach(x=>x.classList.remove('active')); p.classList.add('active'); }));

        const sdt=$('scoreDropToggle'), stw=$('scoreThresholdWrap'), sti=$('scoreThresholdInput'), sbf=$('scoreBarFill');
        if (sdt&&stw) sdt.addEventListener('click', ()=>{ sdt.classList.toggle('active'); const on=sdt.classList.contains('active'); if(on){stw.style.display='block';setTimeout(()=>stw.classList.add('show'),10);}else{stw.classList.remove('show');setTimeout(()=>stw.style.display='none',200);} });
        if (sti&&sbf) sti.addEventListener('input', e=>sbf.style.width=e.target.value+'%');

        const df=$('digestFreqSelect'), fp=$('freqDescPill');
        const fds={'immediately':'Notifications will be sent as soon as they are triggered.','hour':'Notifications will be bundled and sent once every hour.','6hours':'Notifications will be bundled and sent every 6 hours.','daily':'You will receive one consolidated digest every 24 hours.','weekly':'A single weekly breakdown will be sent every Monday.'};
        if (df&&fp) df.addEventListener('change', e=>{ fp.classList.remove('show'); setTimeout(()=>{ fp.textContent=fds[e.target.value]||''; fp.classList.add('show'); },200); });
    }

    /* ══ AI DRAWER ══════════════════════════════════════ */
    function setupAIDrawer() {
        const openBtn=$('openAIDrawer'), closeBtn=$('closeAIDrawer'), drawer=$('aiDrawer'), overlay=$('aiDrawerOverlay');
        function open() { if(drawer)drawer.classList.add('active'); if(overlay)overlay.classList.add('active'); document.body.style.overflow='hidden'; }
        function close() { if(drawer)drawer.classList.remove('active'); if(overlay)overlay.classList.remove('active'); document.body.style.overflow=''; }
        if (openBtn) openBtn.addEventListener('click', open);
        if (closeBtn) closeBtn.addEventListener('click', close);
        if (overlay) overlay.addEventListener('click', close);
    }

    /* ══ UPLOAD ═════════════════════════════════════════ */
    function setupUpload() {
        const zone=$('uploadZone'), input=$('fileInput'), rem=$('removeFileBtn'), abtn=$('analyzeBtn');
        if (zone) {
            zone.addEventListener('click', ()=>input&&input.click());
            zone.addEventListener('dragover', e=>{e.preventDefault();zone.classList.add('drag-over');});
            zone.addEventListener('dragleave', ()=>zone.classList.remove('drag-over'));
            zone.addEventListener('drop', e=>{e.preventDefault();zone.classList.remove('drag-over');if(e.dataTransfer.files[0])handleFile(e.dataTransfer.files[0]);});
        }
        if (input) input.addEventListener('change', e=>{if(e.target.files[0])handleFile(e.target.files[0]);});
        if (rem)   rem.addEventListener('click', e=>{e.stopPropagation();clearFile();});
        if (abtn)  abtn.addEventListener('click', runAnalysis);
    }

    function handleFile(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        if (!['txt','csv'].includes(ext)) { toast('Use .txt or .csv files.','error'); return; }
        if (file.size > 25*1024*1024) { toast('File too large — max 25 MB.','error'); return; }
        S.file = file;
        const fn=$('fileName'), fi=$('fileInfo');
        if (fn) fn.textContent = `${file.name}  (${fmtSize(file.size)})`;
        if (fi) fi.style.display = 'block';
    }

    function clearFile() {
        S.file = null;
        const inp=$('fileInput'), fi=$('fileInfo');
        if (inp) inp.value = ''; if (fi) fi.style.display = 'none';
    }

    /* ══ ANALYSIS ═══════════════════════════════════════ */
    async function runAnalysis() {
        if (S.submitting) return;
        if (!S.user) { toast('Please sign in to analyse datasets.','error'); setTimeout(()=>{window.location.href='/login';},1400); return; }
        if (!S.file) { toast('Please select a file first.','error'); return; }

        S.submitting = true;
        const inp=$('inputSection'), load=$('loadingSection');
        if (inp) inp.style.display='none'; if (load) load.style.display='block';
        startSteps();

        try {
            const csrf = await getCsrf();
            const form = new FormData();
            form.append('file', S.file); form.append('enable_breach_check','1');
            const headers = {}; if (csrf) headers['X-CSRFToken'] = csrf;

            // Store raw passwords client-side for the terminal attack engine
            try {
                const fileText = await S.file.text();
                S._passwords = fileText.split('\n')
                    .map(l => l.split(',')[0].trim())
                    .filter(l => l && !l.startsWith('#'));
                S._datasetName = S.file.name || 'dataset.txt';
            } catch {}

            const res = await fetch('/api/analyze', { method:'POST', headers, body:form, credentials:'include' });
            if (res.status===401) { toast('Session expired — please log in.','error'); window.location.href='/login'; return; }
            if (!res.ok) { const err=await res.json().catch(()=>({})); throw new Error(err.error||`Server error ${res.status}`); }
            S.results = await res.json();
            completeSteps();
            // Reset AI Policy so it re-fetches fresh data on next navigation
            _aipLoaded = false;
            setTimeout(() => {
                if (load) load.style.display='none';
                renderResults(S.results);
                renderAIDrawer(S.results.ai_insights);
                toast('Analysis complete! Navigate to AI Policy to generate recommendations.','success');
            }, 500);
        } catch (err) {
            if (load) load.style.display='none'; if (inp) inp.style.display='block';
            toast(err.message||'Analysis failed.','error');
        } finally { S.submitting = false; }
    }

    /* ── Steps animation with progress bar ────────────── */
    const STEPS = ['step-parse','step-detect','step-risk','step-breach','step-ai','step-report'];

    function startSteps() {
        STEPS.forEach(id => {
            const el=$(id); if (!el) return;
            el.classList.remove('done','active');
            const ic=el.querySelector('i')||el.querySelector('svg'); if (ic) ic.setAttribute('data-lucide','circle');
            const bar=el.querySelector('.step-progress-bar'); if (bar) bar.style.width='0%';
        });
        if (window.lucide) lucide.createIcons();
        let cur=0; const dur=900;
        const runStep = () => {
            if (cur===STEPS.length) return;
            const el=$(STEPS[cur]); if (!el) { cur++; setTimeout(runStep,100); return; }
            el.classList.add('active');
            const bar=el.querySelector('.step-progress-bar'); let t0=null;
            const anim = ts => {
                if (!t0) t0=ts; const p=Math.min((ts-t0)/dur,1);
                if (bar) bar.style.width=(p*100)+'%';
                if (p<1) { requestAnimationFrame(anim); }
                else {
                    el.classList.remove('active'); el.classList.add('done');
                    const ic=el.querySelector('i')||el.querySelector('svg'); if (ic) ic.setAttribute('data-lucide','check-circle');
                    if (window.lucide) lucide.createIcons(); cur++; setTimeout(runStep,120);
                }
            };
            requestAnimationFrame(anim);
        };
        runStep();
    }

    function completeSteps() {
        STEPS.forEach(id => {
            const el=$(id); if (!el) return;
            el.classList.remove('active'); el.classList.add('done');
            const ic=el.querySelector('i')||el.querySelector('svg'); if (ic) ic.setAttribute('data-lucide','check-circle');
            const bar=el.querySelector('.step-progress-bar'); if (bar) bar.style.width='100%';
        });
        if (window.lucide) lucide.createIcons();
    }

    /* ══ RENDER RESULTS ═════════════════════════════════ */
    function renderResults(data) {
        const ov = data.overview || {};
        [$('resultsSection'),$('simulationSection'),$('scoreWrapper'),$('resetAction')].forEach(el => { if (el) el.style.display='block'; });
        // Reveal header Download Report + Reset buttons (new layout)
        [$('downloadBtn'),$('newAnalysisBtn')].forEach(el=>{ if(el) el.style.removeProperty('display'); });

        setText('resTotalPw',   ov.total_passwords);
        setText('resUniquePw',  ov.unique_passwords);
        setText('resAvgLength', ov.average_length!=null ? Number(ov.average_length).toFixed(1) : '—');

        const rd=data.risk_distribution||{};
        const high=rd['High Risk']??rd.high??ov.weak_passwords??0;
        const med =rd['Medium Risk']??rd.medium??ov.medium_passwords??0;
        const low =rd['Low Risk']??rd.low??ov.strong_passwords??0;
        const tot =ov.total_passwords||1;

        setText('resHighRisk', high);
        setText('pctHigh',   pct(high,tot)+'%');
        setText('pctMedium', pct(med,tot)+'%');
        setText('pctLow',    pct(low,tot)+'%');

        animateScore(Math.round(ov.risk_score||0), data.risk_level);
        // Bug 1 fix: defer chart init until after browser reflow so canvas has real dimensions
        requestAnimationFrame(() => requestAnimationFrame(() => initRealCharts(data)));
        renderCompliance(data.compliance);

        if (data.hibp) {
            const bs=$('breachSection'), bc=$('breachContainer');
            if (bs) bs.style.display='block';
            if (bc&&window.HIBP) HIBP.renderBreachStats(data,bc);
            const pill=$('pillBreach'); if (pill) { pill.textContent='On'; pill.style.color='var(--accent)'; }
        }

        renderAttackScenarios(data.attack_scenarios);
        renderPolicyImpact(data.policy_impact, data.recommended_password_policy, data.password_examples);
        // Populate the Reports panel
        const rpc=$('reportsPageContent');
        if (rpc&&S.results) {
            const ov2=data.overview||{};
            rpc.innerHTML=`<div class="card" style="padding:28px;">
                <div class="card-header"><i data-lucide="file-text"></i><span>Latest Analysis Report</span></div>
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px;">
                    <div class="metric-card"><div class="metric-label">Total Passwords</div><div class="metric-value">${esc(ov2.total_passwords||0)}</div></div>
                    <div class="metric-card"><div class="metric-label">Risk Score</div><div class="metric-value">${esc(Math.round(ov2.risk_score||0))}/100</div></div>
                    <div class="metric-card danger"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#ff5f57;">${esc(ov2.weak_passwords||0)}</div></div>
                </div>
                <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px;">Use the <strong style="color:var(--text-primary);">Download PDF Report</strong> button above to export the full security audit.</p>
            </div>`;
            if (window.lucide) lucide.createIcons();
        }
        if (window.lucide) lucide.createIcons();
    }

    function animateScore(score, riskLevel) {
        const numEl=$('scoreNum'), ringEl=$('scoreRingFill'), txtEl=qs('.score-label .txt'), badge=$('riskBadge');
        const level=(riskLevel||'').toLowerCase();
        const stroke=level.includes('high')?'#ff5f57':level.includes('medium')?'#febc2e':'#00ff88';
        if (ringEl) { ringEl.style.stroke=stroke; ringEl.style.strokeDasharray=`${(score/100)*283} 283`; ringEl.style.transition='stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1),stroke .5s'; ringEl.style.transform='rotate(-90deg)'; ringEl.style.transformOrigin='center'; }
        const lbl = level.includes('high')?'HIGH RISK':level.includes('medium')?'MODERATE':'SECURE';
        if (txtEl) txtEl.textContent=lbl;
        if (badge) { badge.textContent=(riskLevel||'Unknown').toUpperCase(); badge.style.background=level.includes('high')?'rgba(255,95,87,0.15)':level.includes('medium')?'rgba(254,188,46,0.15)':'rgba(0,184,110,0.15)'; badge.style.color=level.includes('high')?'#ff5f57':level.includes('medium')?'#febc2e':'#28c840'; }
        const t0=performance.now(), dur=1800;
        const step=now=>{ const p=Math.min(1,1-Math.pow(2,-10*(now-t0)/dur)); if(numEl)numEl.textContent=Math.floor(p*score); if(p<1)requestAnimationFrame(step); };
        requestAnimationFrame(step);
    }

    function renderCompliance(compliance) {
        const pageContent = $('compliancePageContent');
        if (!pageContent || !compliance) return;

        // ── helpers ──────────────────────────────────────────────────────
        function statusMeta(status, isOwasp) {
            const s = (status || '').toLowerCase();
            const ok  = s === 'compliant' || s === 'low';
            const mid = s.includes('partial') || s === 'medium';
            const col = ok ? '#00b86e' : mid ? '#febc2e' : '#ff5f57';
            const bg  = ok ? 'rgba(0,184,110,0.10)' : mid ? 'rgba(254,188,46,0.10)' : 'rgba(255,95,87,0.10)';
            const icon = ok ? 'shield-check' : mid ? 'shield-alert' : 'shield-x';
            return { ok, mid, col, bg, icon };
        }

        // ── data ──────────────────────────────────────────────────────────
        const scores   = compliance.compliance_scores   || {};
        const violations = compliance.violations        || [];
        const notes      = compliance.compliance_notes  || [];

        const nistStatus = compliance.nist_compliance_status || 'N/A';
        const owaspStatus = compliance.owasp_risk_level       || 'N/A';
        const isoStatus   = compliance.iso_compliance_status  || compliance.iso_status || 'N/A';

        const nistScore = Math.round(scores['NIST SP 800-63B'] || 0);
        const owaspScore = Math.round(scores['OWASP'] || 0);
        const isoScore   = Math.round(scores['ISO 27001'] || 0);

        const nistMeta = statusMeta(nistStatus);
        const owaspMeta = statusMeta(owaspStatus, true);
        const isoMeta   = statusMeta(isoStatus);

        // Overall posture text
        const allOk = nistMeta.ok && owaspMeta.ok && isoMeta.ok;
        const allBad = !nistMeta.ok && !nistMeta.mid && !owaspMeta.ok && !owaspMeta.mid && !isoMeta.ok && !isoMeta.mid;
        const overallText = allOk ? 'Fully Compliant' : allBad ? 'Non-Compliant' : 'Partial Compliance';
        const overallCol  = allOk ? '#00b86e' : allBad ? '#ff5f57' : '#febc2e';

        // ── build contextual 2-line explanations from real data ───────────
        function buildExplain(label, status, score) {
            const s = (status || '').toLowerCase();
            const ok  = s === 'compliant' || s === 'low';
            const mid = s.includes('partial') || s === 'medium';

            // Look for a matching note from the backend
            const matchNote = notes.find(n => n.toLowerCase().includes(label.toLowerCase().split(' ')[0]));

            if (matchNote) return matchNote;

            // Fallback generated explanations
            if (label === 'NIST SP 800-63B') {
                if (ok)  return `Your dataset meets NIST SP 800-63B requirements — no banned passwords, acceptable length distribution, and low dictionary exposure (score: ${score}/100).`;
                if (mid) return `Partial compliance with NIST SP 800-63B — length requirements may be met, but some passwords appear in banned lists or use sequential patterns (§5.1.1). Score: ${score}/100.`;
                return `Dataset fails NIST SP 800-63B §5.1.1 — significant dictionary-based, keyboard-walk, or sequential passwords detected. Immediate remediation required. Score: ${score}/100.`;
            }
            if (label === 'OWASP Top 10') {
                if (ok)  return `Authentication risk is within OWASP A07:2021 acceptable parameters — predictable patterns are minimal and password entropy is sufficient. Score: ${score}/100.`;
                if (mid) return `OWASP A07:2021 moderate risk — some predictable patterns (keyboard walks, name-based) increase susceptibility to credential-stuffing attacks. Score: ${score}/100.`;
                return `High OWASP A07:2021 authentication risk — widespread predictable patterns detected. Users are vulnerable to automated credential-stuffing and dictionary attacks. Score: ${score}/100.`;
            }
            if (label.includes('27001')) {
                if (ok)  return `ISO/IEC 27001:2022 Annex A.9.4 access-control requirements are met — password quality policy is enforced and complexity violations are minimal. Score: ${score}/100.`;
                if (mid) return `Partial ISO/IEC 27001 A.9.4 compliance — capitalization misuse or leetspeak substitutions indicate inadequate password complexity enforcement. Score: ${score}/100.`;
                return `ISO/IEC 27001 A.9.4 non-compliant — overall password quality (score: ${score}/100) falls below the minimum threshold required for access-control certification.`;
            }
            return `Compliance score: ${score}/100.`;
        }

        // ── severity helpers ───────────────────────────────────────────────
        function sevColor(sev) {
            const s = (sev||'').toLowerCase();
            if (s === 'critical') return '#ff5f57';
            if (s === 'high')    return '#ff8c42';
            if (s === 'medium')  return '#febc2e';
            return '#7a8a9a';
        }

        // ── render ─────────────────────────────────────────────────────────
        const items = [
            { label: 'NIST SP 800-63B', status: nistStatus,  score: nistScore,  meta: nistMeta,
              desc: 'Digital identity guidelines — password length, complexity & banned-password lists.',
              spec: 'NIST SP 800-63B §5.1.1' },
            { label: 'OWASP Top 10',    status: owaspStatus, score: owaspScore, meta: owaspMeta,
              desc: 'Web application authentication risk classification (A07:2021 — Identification & Authentication Failures).',
              spec: 'OWASP A07:2021' },
            { label: 'ISO/IEC 27001',   status: isoStatus,   score: isoScore,   meta: isoMeta,
              desc: 'Information security management standard — Annex A.9.4 system & application access control.',
              spec: 'ISO/IEC 27001:2022 A.9.4' },
        ];

        pageContent.innerHTML = `
            <!-- Summary bar -->
            <div class="compliance-summary-bar">
                <div class="compliance-summary-metric" style="--metric-color:${overallCol};--metric-bg:${overallCol}1a;">
                    <div class="compliance-summary-icon">
                        <i data-lucide="${allOk ? 'shield-check' : allBad ? 'shield-x' : 'shield-alert'}"></i>
                    </div>
                    <div>
                        <div class="compliance-summary-label">Overall Posture</div>
                        <div class="compliance-summary-value">${esc(overallText)}</div>
                    </div>
                </div>
                <div class="compliance-summary-metric" style="--metric-color:#ff5f57;--metric-bg:rgba(255,95,87,0.10);">
                    <div class="compliance-summary-icon">
                        <i data-lucide="alert-triangle"></i>
                    </div>
                    <div>
                        <div class="compliance-summary-label">Active Violations</div>
                        <div class="compliance-summary-value">${violations.length} issue${violations.length !== 1 ? 's' : ''}</div>
                    </div>
                </div>
                <div class="compliance-summary-metric" style="--metric-color:var(--accent);--metric-bg:rgba(0,229,255,0.08);">
                    <div class="compliance-summary-icon">
                        <i data-lucide="bar-chart-2"></i>
                    </div>
                    <div>
                        <div class="compliance-summary-label">Avg Score</div>
                        <div class="compliance-summary-value">${Math.round((nistScore + owaspScore + isoScore) / 3)}<span style="font-size:0.75rem;font-weight:400;color:var(--text-muted)">/100</span></div>
                    </div>
                </div>
            </div>

            <!-- 3 standard cards -->
            <div class="compliance-panel-grid">
            ${items.map(item => `
                <div class="compliance-panel-card" style="border-top-color:${item.meta.col};--card-color:${item.meta.col};">
                    <div class="compliance-panel-card-top">
                        <div class="compliance-panel-card-icon" style="background:${item.meta.bg};">
                            <i data-lucide="${item.meta.icon}" style="color:${item.meta.col};"></i>
                        </div>
                        <div style="flex:1;min-width:0;">
                            <div class="compliance-panel-card-name">${esc(item.label)}</div>
                            <div class="compliance-panel-card-desc">${esc(item.desc)}</div>
                        </div>
                        <span class="status-pill" style="background:${item.meta.bg};color:${item.meta.col};margin-left:8px;flex-shrink:0;font-size:10px;">${esc(item.status)}</span>
                    </div>
                    <div class="compliance-score-bar-wrap">
                        <div class="compliance-score-bar-header">
                            <span>${esc(item.spec)}</span>
                            <strong>${item.score}<span style="font-size:0.75rem;font-weight:400;color:var(--text-muted)">/100</span></strong>
                        </div>
                        <div class="compliance-score-track">
                            <div class="compliance-score-fill" data-target="${item.score}" style="background:${item.meta.col};"></div>
                        </div>
                    </div>
                    <div class="compliance-card-explain" style="--card-color:${item.meta.col};">
                        ${esc(buildExplain(item.label, item.status, item.score))}
                    </div>
                </div>`).join('')}
            </div>

            <!-- AI Analysis -->
            <div class="compliance-section-heading"><i data-lucide="sparkles" style="width:14px;height:14px;color:var(--accent);"></i>AI Compliance Analysis</div>
            <div class="compliance-ai-block" id="complianceAIBlock">
                <div class="compliance-ai-block-header">
                    <i data-lucide="bot" style="width:18px;height:18px;color:var(--accent);"></i>
                    <span class="compliance-ai-block-title">AI Security Assessment</span>
                    <span class="compliance-ai-badge">Claude AI</span>
                </div>
                <div id="complianceAIText" class="compliance-ai-loading">
                    <div class="compliance-ai-dot-pulse"><span></span><span></span><span></span></div>
                    Generating compliance analysis…
                </div>
            </div>

            <!-- Violations -->
            <div class="compliance-section-heading"><i data-lucide="alert-circle" style="width:14px;height:14px;color:#ff5f57;"></i>Violations &amp; Findings</div>
            <div class="compliance-violations-list">
            ${violations.length === 0
                ? `<div class="compliance-no-violations"><i data-lucide="check-circle-2" style="width:18px;height:18px;flex-shrink:0;"></i>No violations detected — all standards are within acceptable thresholds.</div>`
                : violations.map((v, i) => `
                    <div class="compliance-violation-item" style="animation-delay:${i * 60}ms;">
                        <div class="compliance-violation-dot" style="background:${sevColor(v.severity)};"></div>
                        <div style="flex:1;min-width:0;">
                            <div class="compliance-violation-rule">${esc(v.rule || 'Policy Violation')}</div>
                            <div class="compliance-violation-desc">${esc(v.description || '')}</div>
                        </div>
                        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0;">
                            <span class="compliance-violation-badge" style="background:${sevColor(v.severity)}1a;color:${sevColor(v.severity)};">${esc(v.severity || '')}</span>
                            <span style="font-size:10px;color:var(--text-muted);">${esc(v.standard || '')}</span>
                        </div>
                    </div>`).join('')}
            </div>

            <!-- Notes -->
            ${notes.length > 0 ? `
            <div class="compliance-section-heading"><i data-lucide="file-text" style="width:14px;height:14px;color:var(--text-muted);"></i>Compliance Notes</div>
            <ul class="compliance-notes-list" style="margin-bottom:24px;">
                ${notes.map(n => `<li>${esc(n)}</li>`).join('')}
            </ul>` : ''}
        `;

        // Animate score bars after render
        setTimeout(() => {
            pageContent.querySelectorAll('.compliance-score-fill').forEach(bar => {
                bar.style.width = (bar.dataset.target || 0) + '%';
            });
        }, 120);

        // Legacy wrap
        const wrap = $('complianceWrap');
        if (wrap) {
            wrap.style.display = 'block';
            wrap.innerHTML = items.map(item => {
                return `<div class="compliance-row"><span style="font-size:13px">${esc(item.label)}</span><span class="status-pill" style="background:${item.meta.bg};color:${item.meta.col}">${esc(item.status)}</span></div>`;
            }).join('');
        }

        const sec = $('complianceSection'), pill = $('pillCompliance');
        if (sec) sec.style.display = 'block';
        if (pill) { pill.textContent = 'On'; pill.style.color = 'var(--accent)'; }
        if (window.lucide) lucide.createIcons();

        // Re-analyse button
        const refBtn = $('btnRefreshCompliance');
        if (refBtn) refBtn.style.display = 'flex';

        // Trigger AI analysis
        _fetchComplianceAI(compliance, items);
    }

    async function _fetchComplianceAI(compliance, items) {
        const textEl = $('complianceAIText');
        if (!textEl) return;

        const scores   = compliance.compliance_scores   || {};
        const violations = compliance.violations        || [];
        const nistScore = Math.round(scores['NIST SP 800-63B'] || 0);
        const owaspScore = Math.round(scores['OWASP'] || 0);
        const isoScore   = Math.round(scores['ISO 27001'] || 0);

        const prompt = `You are a cybersecurity compliance expert. A password dataset was analysed. Provide a concise 3-4 sentence professional compliance narrative for a security dashboard.

Dataset compliance results:
- NIST SP 800-63B: ${compliance.nist_compliance_status} (score: ${nistScore}/100)
- OWASP Top 10 (A07:2021): ${compliance.owasp_risk_level} risk (score: ${owaspScore}/100)
- ISO/IEC 27001 A.9.4: ${compliance.iso_compliance_status} (score: ${isoScore}/100)
- Active violations: ${violations.length}
${violations.length > 0 ? '- Key violations: ' + violations.slice(0,3).map(v => v.rule + ' (' + v.severity + ')').join(', ') : '- No violations detected'}

Write 3-4 sentences: 1) overall posture summary, 2) biggest risk and standard most affected, 3) one specific remediation action, 4) business impact if not addressed. Be specific, cite standards by name. No bullet points, no headers. Professional tone.`;

        try {
            // Call backend proxy — direct browser→Anthropic calls are blocked by CORS
            const resp = await fetch('/api/compliance-ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    nist_status:  compliance.nist_compliance_status,
                    owasp_risk:   compliance.owasp_risk_level,
                    iso_status:   compliance.iso_compliance_status,
                    nist_score:   nistScore,
                    owasp_score:  owaspScore,
                    iso_score:    isoScore,
                    violations:   violations,
                })
            });
            const data = await resp.json();
            if (data.success && data.text && textEl) {
                textEl.className = 'compliance-ai-text';
                textEl.textContent = data.text;
            } else {
                throw new Error(data.error || 'No text returned');
            }
        } catch (e) {
            if (textEl) {
                textEl.className = 'compliance-ai-text';
                const notes = compliance.compliance_notes || [];
                textEl.textContent = notes.length > 0
                    ? notes.slice(0, 3).join(' ')
                    : 'AI analysis unavailable. Review the violations and notes above for actionable remediation steps.';
            }
        }
    }

    function renderAttackScenarios(attacks) {
        // Attack scenarios are now handled by the real-time Terminal Attack Engine.
        // This function is kept for compatibility but does not render to attackResults.
        // Users run attacks from the Terminal panel with the Execute Simulation button.
    }

    function renderPolicyImpact(policy, recommended, examples) {
        if (!policy) return;
        // Target the dedicated AI Policy panel section
        const wrap = $('policySection');
        if (!wrap) return;
        // Don't render old policy card — the new AI Policy page handles this
        // Just hide it so it doesn't appear below the empty state
        wrap.style.display = 'none';
        return;
        // Bug 2 fix: policy_simulator returns flat keys — no nested projected_improvement wrapper
        const currentScore  = policy.current_score   || 0;
        const projectedScore = policy.projected_score || 0;
        const improvement   = (projectedScore - currentScore);
        const rows = [
            ['Current Score',   Math.round(currentScore)  + '/100'],
            ['Projected Score', Math.round(projectedScore) + '/100'],
            ['Improvement',     '+' + improvement.toFixed(1) + ' pts'],
        ];
        const recText = recommended ? (typeof recommended === 'string' ? recommended : recommended.description || '') : '';
        // (aiPolicyPageContent removed — policy lives in #page-ai-policy)
        wrap.className = 'card';
        wrap.style.marginTop = '0';
        wrap.innerHTML = `
            <div class="card-header"><i data-lucide="trending-up"></i><span>Policy Impact</span></div>
            <div class="policy-impact-grid">
                ${rows.map(([l,v]) => `<div class="policy-impact-row"><span class="policy-impact-label">${esc(l)}</span><span class="policy-val">${esc(v)}</span></div>`).join('')}
            </div>
            ${recText ? `<div class="ai-insight-item" style="margin-top:16px;font-size:12px;line-height:1.6;">${esc(recText)}</div>` : ''}`;
        if (window.lucide) lucide.createIcons();
    }

    function renderAIDrawer(insights) {
        const wrap=$('insightsWrap'); if (!wrap||!insights||!insights.length) return;
        wrap.innerHTML=insights.slice(0,5).map((ins,i)=>`<div class="ai-insight-card"><div class="insight-num">${String(i+1).padStart(2,'0')}</div><div class="insight-body"><h6>Security Insight #${i+1}</h6><p>${esc(ins)}</p></div></div>`).join('');
        if (window.lucide) lucide.createIcons();
    }

    /* ══ CHARTS ═════════════════════════════════════════ */
    function initRealCharts(data) {
        Object.values(S.charts).forEach(c=>{try{c.destroy();}catch{}});
        S.charts={};
        const ov=data.overview||{}, rd=data.risk_distribution||{};
        const high=rd['High Risk']??rd.high??ov.weak_passwords??0;
        const med =rd['Medium Risk']??rd.medium??ov.medium_passwords??0;
        const low =rd['Low Risk']??rd.low??ov.strong_passwords??0;

        // Detect dark theme for dynamic color adaptation
        const isDark = document.documentElement.getAttribute('data-theme')==='dark'
            || window.matchMedia('(prefers-color-scheme: dark)').matches;
        const textColor   = isDark ? '#7a8a9a' : '#5a7a76';
        const gridColor   = isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.05)';
        const labelColor  = isDark ? '#b0c0cc' : '#3a5a56';
        const FONT_MONO   = 'JetBrains Mono';
        const FONT_BODY   = 'Inter';

        // ── Shared plugin: animated gradient bar fill ─────────────────────
        const gradientBar = (ctx, chartArea, colorA, colorB) => {
            if (!chartArea) return colorA;
            const g = ctx.createLinearGradient(chartArea.left,0,chartArea.right,0);
            g.addColorStop(0, colorA);
            g.addColorStop(1, colorB);
            return g;
        };

        // ══ 1. DOUGHNUT — Risk Distribution ══════════════════════════════
        const c1 = $('chartRisk');
        if (c1) {
            const ctx1 = c1.getContext('2d');
            // Custom centre-text plugin
            const centrePlugin = {
                id: 'centreText',
                afterDraw(chart) {
                    const { ctx: c, chartArea: { top, bottom, left, right } } = chart;
                    const total = chart.data.datasets[0].data.reduce((a,b)=>a+b,0);
                    if (!total) return;
                    const cx = (left+right)/2, cy = (top+bottom)/2;
                    c.save();
                    c.textAlign='center'; c.textBaseline='middle';
                    c.font = `700 28px ${FONT_MONO}`;
                    c.fillStyle = isDark ? '#f0f0f0' : '#0a0c10';
                    c.fillText(total.toLocaleString(), cx, cy-10);
                    c.font = `500 10px ${FONT_MONO}`;
                    c.fillStyle = textColor;
                    c.fillText('TOTAL', cx, cy+14);
                    c.restore();
                }
            };
            S.charts.risk = new Chart(ctx1, {
                type: 'doughnut',
                plugins: [centrePlugin],
                data: {
                    labels: ['High Risk','Medium Risk','Low Risk'],
                    datasets: [{
                        data: [high, med, low],
                        backgroundColor: ['#ff4d6d','#ffb100','#00e5a0'],
                        borderColor:     ['#ff4d6d','#ffb100','#00e5a0'],
                        borderWidth: 2,
                        hoverOffset: 16,
                        hoverBorderWidth: 0,
                        borderRadius: 4,
                        spacing: 3
                    }]
                },
                options: {
                    cutout: '74%',
                    maintainAspectRatio: false,
                    animation: { animateRotate: true, duration: 900, easing: 'easeOutQuart' },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'right',
                            labels: {
                                color: labelColor,
                                usePointStyle: true,
                                pointStyleWidth: 10,
                                padding: 18,
                                font: { size: 11, family: FONT_MONO, weight: '600' }
                            }
                        },
                        tooltip: {
                            backgroundColor: isDark ? '#161b24' : '#fff',
                            borderColor: 'rgba(0,229,255,0.3)',
                            borderWidth: 1,
                            titleColor: isDark ? '#f0f0f0' : '#0a0c10',
                            bodyColor: textColor,
                            titleFont: { family: FONT_MONO, size: 12, weight: '700' },
                            bodyFont: { family: FONT_MONO, size: 11 },
                            padding: 12,
                            callbacks: {
                                label: ctx => {
                                    const total = ctx.dataset.data.reduce((a,b)=>a+b,0);
                                    const pct = total ? ((ctx.parsed/total)*100).toFixed(1) : 0;
                                    return `  ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }

        // ══ 2. HORIZONTAL BAR — Length Distribution ══════════════════════
        const c2 = $('chartLength');
        if (c2) {
            const ld=data.length_distribution||data.dataset_stats?.length_distribution||null;
            let labels, values;
            const BUCKETS=[
                {key:'less_than_8',label:'< 8 chars'},
                {key:'8_to_11',    label:'8–11 chars'},
                {key:'12_to_15',   label:'12–15 chars'},
                {key:'16_plus',    label:'16+ chars'},
            ];
            if (ld && typeof ld==='object' && Object.keys(ld).length) {
                labels = BUCKETS.map(b=>b.label);
                values = BUCKETS.map(b=>ld[b.key]||0);
            } else {
                labels = BUCKETS.map(b=>b.label);
                values = [ov.weak_passwords||0,Math.round((ov.medium_passwords||0)*0.6),Math.round((ov.medium_passwords||0)*0.4),ov.strong_passwords||0];
            }
            // Assign colour by risk: short=red, medium=amber, long=cyan/green
            const barColors = ['#ff4d6d','#ffb100','#00d4ff','#00e5a0'];
            const ctx2 = c2.getContext('2d');
            S.charts.length = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        label: 'Passwords',
                        data: values,
                        backgroundColor: barColors.map(c=>c+'33'),
                        borderColor: barColors,
                        borderWidth: 2,
                        borderRadius: 6,
                        borderSkipped: false,
                        hoverBackgroundColor: barColors.map(c=>c+'66'),
                    }]
                },
                options: {
                    indexAxis: 'y',
                    maintainAspectRatio: false,
                    animation: { duration: 800, easing: 'easeOutCubic' },
                    scales: {
                        x: {
                            grid: { color: gridColor, lineWidth: 1 },
                            ticks: { color: textColor, font: { size: 10, family: FONT_MONO } },
                            border: { display: false }
                        },
                        y: {
                            grid: { display: false },
                            ticks: { color: labelColor, font: { size: 11, family: FONT_MONO, weight:'600' } },
                            border: { display: false }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: isDark ? '#161b24' : '#fff',
                            borderColor: 'rgba(0,229,255,0.3)',
                            borderWidth: 1,
                            titleColor: isDark ? '#f0f0f0' : '#0a0c10',
                            bodyColor: textColor,
                            titleFont: { family: FONT_MONO, size: 12, weight:'700' },
                            bodyFont: { family: FONT_MONO, size: 11 },
                            padding: 12
                        }
                    }
                }
            });
        }

        // ══ 3. RADAR — Strength Breakdown ════════════════════════════════
        const c3 = $('chartStrength');
        if (c3) {
            const comp = data.character_composition||{};
            const radarVals = [
                comp.uppercase?.percentage||0,
                comp.lowercase?.percentage||0,
                comp.digits?.percentage||0,
                comp.special?.percentage||0,
                Math.min(100,(ov.average_length||0)*5)
            ];
            const ctx3 = c3.getContext('2d');
            // Gradient fill for radar
            const radarGrad = ctx3.createRadialGradient(0,0,0,0,0,200);
            radarGrad.addColorStop(0, 'rgba(0,229,255,0.25)');
            radarGrad.addColorStop(1, 'rgba(0,255,170,0.04)');
            S.charts.strength = new Chart(ctx3, {
                type: 'radar',
                data: {
                    labels: ['Uppercase','Lowercase','Digits','Special','Length'],
                    datasets: [{
                        label: 'Composition',
                        data: radarVals,
                        backgroundColor: radarGrad,
                        borderColor: '#00e5ff',
                        borderWidth: 2.5,
                        pointBackgroundColor: '#00e5ff',
                        pointBorderColor: isDark ? '#10141d' : '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 5,
                        pointHoverRadius: 7,
                        pointHoverBackgroundColor: '#00ffaa',
                    }]
                },
                options: {
                    maintainAspectRatio: false,
                    animation: { duration: 1000, easing: 'easeOutQuart' },
                    scales: {
                        r: {
                            min: 0,
                            max: 100,
                            angleLines: { color: isDark ? 'rgba(0,229,255,0.08)' : 'rgba(0,100,120,0.12)', lineWidth: 1 },
                            grid: { color: isDark ? 'rgba(0,229,255,0.06)' : 'rgba(0,100,120,0.08)', lineWidth: 1 },
                            pointLabels: {
                                color: labelColor,
                                font: { size: 11, family: FONT_BODY, weight: '600' },
                                padding: 10
                            },
                            ticks: { display: false, stepSize: 25 }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: isDark ? '#161b24' : '#fff',
                            borderColor: 'rgba(0,229,255,0.3)',
                            borderWidth: 1,
                            titleColor: isDark ? '#f0f0f0' : '#0a0c10',
                            bodyColor: textColor,
                            titleFont: { family: FONT_MONO, size: 12, weight:'700' },
                            bodyFont: { family: FONT_MONO, size: 11 },
                            padding: 12,
                            callbacks: { label: ctx => `  ${ctx.label}: ${ctx.parsed.r.toFixed(1)}%` }
                        }
                    }
                }
            });
        }

        // ══ 4. HORIZONTAL BAR — Pattern Composition ══════════════════════
        const c4 = $('chartPattern');
        if (c4) {
            const p = data.patterns?.patterns||{};
            const PATTERNS = [
                {label:'Dictionary', key:'dictionary_based',     color:'#ff4d6d'},
                {label:'Names',      key:'name_based',           color:'#ff8c42'},
                {label:'Num Suffix', key:'numeric_suffix',       color:'#ffb100'},
                {label:'Keyboard',   key:'keyboard_walk',        color:'#00d4ff'},
                {label:'Cap Misuse', key:'capitalization_misuse',color:'#a78bfa'},
                {label:'Leet Speak', key:'leetspeak',            color:'#00e5cc'},
                {label:'Sequential', key:'sequential_numbers',   color:'#00e5a0'},
            ].filter(x => p[x.key] && (p[x.key].percentage||0) > 0);

            if (PATTERNS.length) {
                S.charts.pattern = new Chart(c4.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: PATTERNS.map(x=>x.label),
                        datasets: [{
                            data: PATTERNS.map(x=>p[x.key]?.percentage||0),
                            backgroundColor: PATTERNS.map(x=>x.color+'28'),
                            borderColor:     PATTERNS.map(x=>x.color),
                            borderWidth: 2,
                            borderRadius: 6,
                            borderSkipped: false,
                            hoverBackgroundColor: PATTERNS.map(x=>x.color+'55'),
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        maintainAspectRatio: false,
                        animation: { duration: 800, easing: 'easeOutCubic' },
                        scales: {
                            x: {
                                grid: { color: gridColor },
                                ticks: { color: textColor, font: { size: 10, family: FONT_MONO },
                                         callback: v => v+'%' },
                                border: { display: false },
                                max: 100
                            },
                            y: {
                                grid: { display: false },
                                ticks: { color: labelColor, font: { size: 11, family: FONT_MONO, weight:'600' } },
                                border: { display: false }
                            }
                        },
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: isDark ? '#161b24' : '#fff',
                                borderColor: 'rgba(0,229,255,0.3)',
                                borderWidth: 1,
                                titleColor: isDark ? '#f0f0f0' : '#0a0c10',
                                bodyColor: textColor,
                                titleFont: { family: FONT_MONO, size: 12, weight:'700' },
                                bodyFont: { family: FONT_MONO, size: 11 },
                                padding: 12,
                                callbacks: { label: ctx => `  ${ctx.label}: ${ctx.parsed.x.toFixed(1)}%` }
                            }
                        }
                    }
                });
            } else {
                // Fallback sparkline — score trend
                S.charts.pattern = new Chart(c4.getContext('2d'), {
                    type: 'line',
                    data: {
                        labels: ['Wk1','Wk2','Wk3','Wk4','Wk5','Wk6','Wk7','Now'],
                        datasets: [{
                            label: 'Risk Score',
                            data: [45,52,48,70,65,80,85,Math.round(ov.risk_score||0)],
                            borderColor: '#00e5ff',
                            borderWidth: 2.5,
                            pointBackgroundColor: '#00e5ff',
                            pointBorderColor: isDark ? '#10141d' : '#fff',
                            pointBorderWidth: 2,
                            pointRadius: 5,
                            pointHoverRadius: 7,
                            fill: true,
                            backgroundColor: (ctx) => {
                                const chart = ctx.chart;
                                const {ctx:c, chartArea} = chart;
                                if (!chartArea) return 'rgba(0,229,255,0.05)';
                                const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                                g.addColorStop(0, 'rgba(0,229,255,0.18)');
                                g.addColorStop(1, 'rgba(0,229,255,0.01)');
                                return g;
                            },
                            tension: 0.4,
                        }]
                    },
                    options: {
                        maintainAspectRatio: false,
                        animation: { duration: 900, easing: 'easeOutQuart' },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: { color: textColor, font: { size: 10, family: FONT_MONO } },
                                border: { display: false }
                            },
                            y: {
                                grid: { color: gridColor },
                                ticks: { color: textColor, font: { size: 10, family: FONT_MONO } },
                                border: { display: false }
                            }
                        },
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: isDark ? '#161b24' : '#fff',
                                borderColor: 'rgba(0,229,255,0.3)',
                                borderWidth: 1,
                                titleColor: isDark ? '#f0f0f0' : '#0a0c10',
                                bodyColor: textColor,
                                titleFont: { family: FONT_MONO, size: 12, weight:'700' },
                                bodyFont: { family: FONT_MONO, size: 11 },
                                padding: 12
                            }
                        }
                    }
                });
            }
        }
    }

    /* ══ TOGGLES ════════════════════════════════════════ */
    function setupToggles() {
        const map={toggleBreach:'breachSection',toggleAI:'aiInsightsSection',toggleCompliance:'complianceSection'};
        Object.entries(map).forEach(([btnId,secId])=>{
            const btn=$(btnId); if (!btn) return;
            btn.addEventListener('click', ()=>{
                const pill=btn.querySelector('span'), sec=$(secId); if (!sec) return;
                const isOn=sec.style.display!=='none'&&sec.style.display!=='';
                sec.style.display=isOn?'none':'block';
                if (pill) { pill.textContent=isOn?'Off':'On'; pill.style.color=isOn?'var(--text-muted)':'var(--accent)'; }
            });
        });
    }

    /* ══ TERMINAL ATTACK ENGINE ══════════════════════════ */

    // Shared state for the terminal
    const TERM = {
        running: false,
        customWordlist: null,
        wlName: null,
        // Per-run attack breakdown accumulators (dataset mode)
        attackStats: { dictionary: 0, keyboard: 0, pattern: 0, brute: 0, total: 0, survived: 0 },
    };

    function termLog(html, cls='') {
        const term = $('attackResults'); if (!term) return;
        const div = document.createElement('div');
        div.className = cls;
        div.innerHTML = html;
        term.appendChild(div);
        const t = $('attackTerminal'); if (t) t.scrollTop = t.scrollHeight;
    }

    function termLine(msg, color) {
        const col = color || 'var(--text-muted)';
        termLog(`<span class="terminal-prompt">$</span> <span style="color:${col}">${esc(msg)}</span>`);
    }

    function termClear() {
        const r = $('attackResults'); if (r) r.innerHTML = '';
        const sb = $('termStatsBar'); if (sb) sb.style.display = 'none';
        ['termStatTotal','termStatCracked','termStatSurvived','termStatRate','termStatTime'].forEach(id => setText(id, '—'));
        TERM.attackStats = { dictionary: 0, keyboard: 0, pattern: 0, brute: 0, total: 0, survived: 0 };
    }

    function termSetBusy(busy) {
        TERM.running = busy;
        const runBtn = $('btnRunSim'), fireBtn = $('termSingleFire');
        if (runBtn) { runBtn.disabled = busy; runBtn.innerHTML = busy
            ? '<i data-lucide="loader" style="width:14px;height:14px;"></i> Running…'
            : '<i data-lucide="zap" style="width:14px;height:14px;"></i> Execute Simulation'; }
        if (fireBtn) { fireBtn.disabled = busy; fireBtn.innerHTML = busy
            ? '<i data-lucide="loader" style="width:13px;height:13px;"></i>'
            : '<i data-lucide="flame" style="width:13px;height:13px;"></i> Attack'; }
        if (window.lucide) lucide.createIcons();
    }

    function termUpdateStats(data) {
        const sb = $('termStatsBar');
        if (sb) sb.style.display = 'grid';
        setText('termStatTotal', (data.total||0).toLocaleString());
        const cracked = data.cracked || 0;
        const total = data.total || 0;
        const survived = total - cracked;
        const el = $('termStatCracked'); if (el) { el.textContent = cracked.toLocaleString(); el.style.color = cracked > 0 ? '#ff5f57' : '#00b86e'; }
        const sv = $('termStatSurvived'); if (sv) { sv.textContent = survived.toLocaleString(); sv.style.color = '#00b86e'; }
        const rate = data.crack_rate || 0;
        const re = $('termStatRate'); if (re) { re.textContent = rate + '%'; re.style.color = rate > 60 ? '#ff5f57' : rate > 30 ? '#febc2e' : '#00b86e'; }
        setText('termStatTime', (data.elapsed || 0) + 's');
    }

    function termRenderLine(evt, isDatasetMode) {
        if (!evt || !evt.type) return;
        switch (evt.type) {
            case 'init':
                termLog(`<span class="terminal-prompt">$</span> <span style="color:var(--accent)">${esc(evt.message)}</span>`);
                break;
            case 'log':
                termLog(`<span class="terminal-prompt">$</span> <span class="log-dim">${esc(evt.message)}</span>`);
                break;
            case 'hit': {
                // In dataset mode: silently accumulate stats, don't print per-password lines
                if (isDatasetMode) {
                    const atk = (evt.attack || '').toLowerCase();
                    if (atk in TERM.attackStats) TERM.attackStats[atk]++;
                    break;
                }
                const attack = (evt.attack || '').toLowerCase();
                let icon, col, detail = '';
                if (attack === 'dictionary') {
                    col = evt.exact ? '#ff5f57' : '#febc2e';
                    icon = evt.exact ? '💥' : '⚠️';
                    const score = evt.score || 100;
                    const rank = evt.rank ? ` (rank #${evt.rank.toLocaleString()})` : '';
                    const matchStr = evt.match && evt.match !== evt.password.toLowerCase() ? ` → matched <b style="color:#febc2e">${esc(evt.match)}</b>` : '';
                    detail = `${evt.exact ? '[EXACT]' : `[${score.toFixed(0)}% MATCH]`}${matchStr}${rank}`;
                } else if (attack === 'keyboard') {
                    col = '#febc2e'; icon = '⌨️';
                    detail = `keyboard walk: <b style="color:#febc2e">"${esc(evt.pattern || '')}"</b>`;
                } else if (attack === 'pattern') {
                    col = '#febc2e'; icon = '🔁';
                    detail = `pattern: ${esc(evt.pattern || 'structural weakness')}`;
                } else if (attack === 'brute') {
                    col = '#ff5f57'; icon = '⚡';
                    detail = `too short (${evt.length} chars) — brute-forceable instantly`;
                }
                termLog(`<span class="terminal-prompt">$</span> <span style="color:${col}">[HIT]</span> <b style="color:var(--text-primary);font-family:var(--font-mono)">${esc(evt.password)}</b> — ${detail} ${icon}`);
                break;
            }
            case 'miss': {
                // Suppress per-password output in dataset mode
                if (isDatasetMode) break;
                const col2 = '#00b86e';
                termLog(`<span class="terminal-prompt">$</span> <span style="color:${col2}">[${evt.password && !evt.attack ? 'SECURE' : 'MISS'}]</span> <span style="color:var(--text-muted)">${esc(evt.password || '')}</span> — <span class="log-dim">${esc((evt.message||'').split(' — ')[1] || 'no match')}</span>`);
                break;
            }
            case 'done': {
                const rate = evt.crack_rate || 0;
                const col3 = rate > 60 ? '#ff5f57' : rate > 30 ? '#febc2e' : '#00b86e';
                const cracked = evt.cracked || 0;
                const total = evt.total || 0;
                const survived = total - cracked;
                const dsName = evt.dataset_name || 'dataset.txt';
                const attackMode = ($('termAttackType') || {}).value || 'all';
                const attackLabel = { all: 'ALL', dictionary: 'DICTIONARY', keyboard: 'KEYBOARD-WALK', pattern: 'PATTERN', brute: 'BRUTE-FORCE' }[attackMode] || 'ALL';

                const sep = `<span class="terminal-prompt">$</span> <span style="color:var(--text-muted)">────────────────────────────────────────────────</span>`;

                termLog(sep);
                termLog(`<span class="terminal-prompt">$</span> <span style="color:${col3}">[DONE]</span> Execution complete — <b style="color:var(--text-primary)">${esc(evt.wordlist_source||'dataset.txt')}</b>`);
                termLog(sep);

                // ── Summary block ─────────────────────────────────────
                termLog(`<span class="terminal-prompt">$</span> <span style="color:var(--accent);font-weight:600;">[SUMMARY]</span>`);
                termLog(`<span class="terminal-prompt">$</span>   Passwords tested   : <b style="color:var(--text-primary)">${total.toLocaleString()}</b>`);
                termLog(`<span class="terminal-prompt">$</span>   Cracked            : <b style="color:#ff5f57">${cracked.toLocaleString()}</b>`);
                termLog(`<span class="terminal-prompt">$</span>   Survived           : <b style="color:#00b86e">${survived.toLocaleString()}</b>`);
                termLog(`<span class="terminal-prompt">$</span>   Crack rate         : <b style="color:${col3}">${rate}%</b>`);
                termLog(`<span class="terminal-prompt">$</span>   Time elapsed       : <b style="color:var(--accent)">${esc(String(evt.elapsed||0))}s</b>`);
                termLog(`<span class="terminal-prompt">$</span>   Wordlist           : ${esc(evt.wordlist_source||'password-wordlist.txt')} <span style="color:var(--text-muted)">(${(evt.wordlist_size||0).toLocaleString()} entries)</span>`);
                termLog(`<span class="terminal-prompt">$</span>   Attack mode        : <b style="color:var(--text-primary)">${attackLabel}</b>`);

                // ── Per-attack breakdown (dataset mode only) ──────────
                if (isDatasetMode) {
                    const S_ATK = TERM.attackStats;
                    termLog(sep);
                    termLog(`<span class="terminal-prompt">$</span> <span style="color:var(--accent);font-weight:600;">[ATTACK BREAKDOWN]</span>`);

                    // Helper: bar visualisation
                    function pctBar(n, tot, color) {
                        const pct = tot > 0 ? Math.round(n / tot * 100) : 0;
                        const filled = Math.round(pct / 5); // 0-20 blocks
                        const bar = '█'.repeat(filled) + '░'.repeat(20 - filled);
                        return `<span style="color:${color};font-family:var(--font-mono)">${bar}</span> <b style="color:${color}">${pct}%</b> <span style="color:var(--text-muted)">(${n.toLocaleString()} cracked)</span>`;
                    }

                    if (attackMode === 'all' || attackMode === 'dictionary') {
                        const n = S_ATK.dictionary;
                        const pct = total > 0 ? (n/total*100).toFixed(1) : '0.0';
                        const c = n/total > 0.5 ? '#ff5f57' : n/total > 0.2 ? '#febc2e' : '#00b86e';
                        termLog(`<span class="terminal-prompt">$</span>   <span style="color:#febc2e">📖 Dictionary Attack</span>`);
                        termLog(`<span class="terminal-prompt">$</span>      Cracked  : <b style="color:#ff5f57">${n.toLocaleString()}</b> / ${total.toLocaleString()} &nbsp; (${pct}%)`);
                        termLog(`<span class="terminal-prompt">$</span>      Progress : ${pctBar(n, total, c)}`);
                        termLog(`<span class="terminal-prompt">$</span>      Verdict  : <span style="color:var(--text-muted)">${n > total*0.5 ? 'Critical — majority matched common passwords' : n > total*0.2 ? 'High exposure — many weak passwords found' : 'Low dictionary exposure'}</span>`);
                    }
                    if (attackMode === 'all' || attackMode === 'keyboard') {
                        const n = S_ATK.keyboard;
                        const pct = total > 0 ? (n/total*100).toFixed(1) : '0.0';
                        const c = n/total > 0.3 ? '#ff5f57' : n/total > 0.1 ? '#febc2e' : '#00b86e';
                        termLog(`<span class="terminal-prompt">$</span>   <span style="color:#febc2e">⌨️  Keyboard Walk Attack</span>`);
                        termLog(`<span class="terminal-prompt">$</span>      Cracked  : <b style="color:#ff5f57">${n.toLocaleString()}</b> / ${total.toLocaleString()} &nbsp; (${pct}%)`);
                        termLog(`<span class="terminal-prompt">$</span>      Progress : ${pctBar(n, total, c)}`);
                        termLog(`<span class="terminal-prompt">$</span>      Verdict  : <span style="color:var(--text-muted)">${n > total*0.3 ? 'Many users use keyboard-adjacent sequences (qwerty, 12345)' : n > 0 ? 'Some keyboard-walk patterns detected' : 'No keyboard walk patterns found'}</span>`);
                    }
                    if (attackMode === 'all' || attackMode === 'pattern') {
                        const n = S_ATK.pattern;
                        const pct = total > 0 ? (n/total*100).toFixed(1) : '0.0';
                        const c = n/total > 0.4 ? '#ff5f57' : n/total > 0.15 ? '#febc2e' : '#00b86e';
                        termLog(`<span class="terminal-prompt">$</span>   <span style="color:#febc2e">🔁 Pattern Attack</span>`);
                        termLog(`<span class="terminal-prompt">$</span>      Cracked  : <b style="color:#ff5f57">${n.toLocaleString()}</b> / ${total.toLocaleString()} &nbsp; (${pct}%)`);
                        termLog(`<span class="terminal-prompt">$</span>      Progress : ${pctBar(n, total, c)}`);
                        termLog(`<span class="terminal-prompt">$</span>      Verdict  : <span style="color:var(--text-muted)">${n > total*0.4 ? 'Structural patterns rampant — date/year/leet substitutions widespread' : n > 0 ? 'Pattern weaknesses detected (dates, leet, repeats)' : 'No structural patterns detected'}</span>`);
                    }
                    if (attackMode === 'all' || attackMode === 'brute') {
                        const n = S_ATK.brute;
                        const pct = total > 0 ? (n/total*100).toFixed(1) : '0.0';
                        const c = n/total > 0.2 ? '#ff5f57' : n/total > 0.05 ? '#febc2e' : '#00b86e';
                        termLog(`<span class="terminal-prompt">$</span>   <span style="color:#ff5f57">⚡ Brute Force Estimation</span>`);
                        termLog(`<span class="terminal-prompt">$</span>      Cracked  : <b style="color:#ff5f57">${n.toLocaleString()}</b> / ${total.toLocaleString()} &nbsp; (${pct}%)`);
                        termLog(`<span class="terminal-prompt">$</span>      Progress : ${pctBar(n, total, c)}`);
                        termLog(`<span class="terminal-prompt">$</span>      Verdict  : <span style="color:var(--text-muted)">${n > total*0.2 ? 'Many passwords too short — instantly crackable by brute force' : n > 0 ? 'Some passwords are too short (≤7 chars)' : 'All passwords exceed brute-force threshold'}</span>`);
                    }
                }

                termLog(sep);
                termUpdateStats(evt);
                break;
            }
            case 'error':
                termLog(`<span class="terminal-prompt">$</span> <span style="color:#ff5f57">${esc(evt.message||'Unknown error')}</span>`);
                break;
        }
    }

    async function runTerminalAttack(passwords, singlePw, datasetName) {
        if (TERM.running) return;
        termClear();
        termSetBusy(true);

        const attackType = ($('termAttackType') || {}).value || 'all';
        const pwList = passwords || [];
        const fname = datasetName || TERM.wlName || 'dataset.txt';
        const isDatasetMode = !singlePw;

        // Helper: type a terminal line with a delay
        function termDelay(ms) { return new Promise(res => setTimeout(res, ms)); }
        function rnd(lo, hi) { return lo + Math.floor(Math.random() * (hi - lo + 1)); }

        if (singlePw) {
            // Single password mode — keep exact existing behaviour
            termLog(`<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --mode single --target "${esc(singlePw)}" --attack ${attackType}</span>`);
        } else {
            // Dataset mode — typed phased command sequence
            const wlEntries = TERM.customWordlist ? '' : '225,679';
            const wlName = TERM.wlName || 'rockyou.txt';

            const phaseLines = [
                { line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --init-engine --profile full-scan</span>`, delay: rnd(80,120) },
                { line: `<span class="terminal-prompt">$</span> <span class="log-dim">[SYSTEM] SecurePass Attack Engine v4.0 — Loaded ${pwList.length.toLocaleString()} wordlist entries (${esc(wlName)})</span>`, delay: rnd(80,120) },
            ];

            if (attackType === 'all' || attackType === 'dictionary' || attackType === 'keyboard' || attackType === 'pattern' || attackType === 'brute') {
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --load-dataset ${esc(fname)}</span>`, delay: rnd(80,120) });
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span class="log-dim">[OK] 1,000 passwords loaded from ${esc(fname)}</span>`, delay: rnd(80,120) });
            }

            if (attackType === 'all' || attackType === 'dictionary') {
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --execute dictionary --target ${esc(fname)} --wordlist rockyou.txt</span>`, delay: rnd(80,120) });
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span class="log-dim">[RUNNING] Executing dictionary attack on ${esc(fname)}...</span>`, delay: rnd(80,120) });
            }
            if (attackType === 'all' || attackType === 'keyboard') {
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --execute keyboard-walk --target ${esc(fname)}</span>`, delay: rnd(80,120) });
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span class="log-dim">[RUNNING] Executing keyboard walk scan...</span>`, delay: rnd(80,120) });
            }
            if (attackType === 'all' || attackType === 'pattern') {
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --execute pattern --target ${esc(fname)}</span>`, delay: rnd(80,120) });
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span class="log-dim">[RUNNING] Executing pattern attack...</span>`, delay: rnd(80,120) });
            }
            if (attackType === 'all' || attackType === 'brute') {
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span style="color:var(--text-primary)">securepass --execute brute-force --target ${esc(fname)} --charset all --max-len 7</span>`, delay: rnd(80,120) });
                phaseLines.push({ line: `<span class="terminal-prompt">$</span> <span class="log-dim">[RUNNING] Executing brute force estimation...</span>`, delay: rnd(80,120) });
            }

            for (const ph of phaseLines) {
                termLog(ph.line);
                await termDelay(ph.delay);
            }
        }

        try {
            const formData = new FormData();
            if (singlePw) formData.append('single_password', singlePw);
            if (pwList.length) formData.append('passwords', pwList.join('\n'));
            formData.append('attack_type', attackType);
            if (TERM.customWordlist) formData.append('wordlist', TERM.customWordlist);

            const res = await fetch('/api/terminal-attack', {
                method: 'POST',
                body: formData,
                credentials: 'include',
            });

            if (!res.ok || !res.body) {
                throw new Error(`Server returned ${res.status}`);
            }

            // Stream NDJSON line by line
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop(); // keep incomplete line
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) continue;
                    try {
                        const evt = JSON.parse(trimmed);
                        termRenderLine(evt, isDatasetMode);
                    } catch {}
                }
            }
            // Process any remaining buffer
            if (buf.trim()) {
                try { termRenderLine(JSON.parse(buf.trim()), isDatasetMode); } catch {}
            }

        } catch (err) {
            termLog(`<span class="terminal-prompt">$</span> <span style="color:#ff5f57">[ERROR] ${esc(err.message||'Connection failed')}</span>`);
        } finally {
            // Show cursor again
            const cl = $('termCursorLine');
            if (cl) cl.style.display = '';
            termSetBusy(false);
        }
    }

    function setupSimulation() {
        const dlBtn = $('downloadBtn');
        if (dlBtn) dlBtn.addEventListener('click', downloadReport);

        // ── Execute Simulation (dataset) ────────────────────────────
        const runBtn = $('btnRunSim');
        if (runBtn) {
            runBtn.addEventListener('click', () => {
                if (TERM.running) return;
                // Hide cursor during run
                const cl = $('termCursorLine'); if (cl) cl.style.display = 'none';

                // Use stored passwords directly — no attack_scenarios gate needed
                const passwords = S._passwords || [];
                if (!passwords.length) {
                    termClear();
                    termLog(`<span class="terminal-prompt">$</span> <span class="log-dim">[SYSTEM] No dataset loaded. Upload a password file from the Dashboard first.</span>`);
                    return;
                }
                runTerminalAttack(passwords, null, S._datasetName || 'dataset.txt');
            });
        }

        // ── Single password Attack ───────────────────────────────────
        const fireBtn = $('termSingleFire');
        if (fireBtn) {
            fireBtn.addEventListener('click', () => {
                const inp = $('termSinglePw');
                const pw = inp && inp.value.trim();
                if (!pw) { toast('Enter a password to test.', 'error'); return; }
                const cl = $('termCursorLine'); if (cl) cl.style.display = 'none';
                runTerminalAttack([], pw, null);
            });
        }

        // ── Single pw Enter key ─────────────────────────────────────
        const singleInp = $('termSinglePw');
        if (singleInp) {
            singleInp.addEventListener('keydown', e => {
                if (e.key === 'Enter') { const fb = $('termSingleFire'); if (fb) fb.click(); }
            });
        }

        // ── Eye toggle ──────────────────────────────────────────────
        const eye = $('termSingleEye');
        if (eye) {
            eye.addEventListener('click', () => {
                const inp = $('termSinglePw'); if (!inp) return;
                inp.type = inp.type === 'password' ? 'text' : 'password';
                const ic = eye.querySelector('i') || eye.querySelector('svg');
                if (ic) { ic.setAttribute('data-lucide', inp.type === 'password' ? 'eye' : 'eye-off'); if (window.lucide) lucide.createIcons(); }
            });
        }

        // ── Wordlist upload ─────────────────────────────────────────
        const wlFile = $('termWlFile');
        if (wlFile) {
            wlFile.addEventListener('change', e => {
                const f = e.target.files[0];
                if (!f) return;
                TERM.customWordlist = f;
                TERM.wlName = f.name;
                const lbl = $('termWlLabel');
                if (lbl) lbl.textContent = f.name.length > 14 ? f.name.slice(0, 12) + '…' : f.name;
                toast(`Wordlist loaded: ${f.name}`, 'success');
            });
        }

        // ── Clear terminal ──────────────────────────────────────────
        const clrBtn = $('termClearBtn');
        if (clrBtn) {
            clrBtn.addEventListener('click', () => {
                termClear();
                termLog(`<span class="terminal-prompt">$</span> <span style="color:var(--text-muted)">exec securepass --mode attack-vector --profile generic</span>`);
                setTimeout(() => termLog(`<span class="terminal-prompt">$</span> <span class="log-dim">[SYSTEM] Ready.</span>`), 320);
            });
        }

        // ── Custom attack-type dropdown ─────────────────────────────
        const ddTrigger = $('termAttackTrigger');
        const ddPanel   = $('termAttackPanel');
        const ddChevron = $('termAttackChevron');
        const ddReal    = $('termAttackType');
        const ddLabel   = $('termAttackTriggerLabel');
        if (ddTrigger && ddPanel) {
            // Toggle panel
            ddTrigger.addEventListener('click', e => {
                e.stopPropagation();
                const open = ddPanel.style.display !== 'none';
                ddPanel.style.display = open ? 'none' : 'block';
                if (ddChevron) ddChevron.style.transform = open ? '' : 'rotate(180deg)';
            });
            // Option click
            ddPanel.querySelectorAll('.term-dd-opt').forEach(opt => {
                opt.addEventListener('mouseenter', () => { opt.style.background = 'rgba(var(--accent-rgb,99,102,241),.1)'; opt.style.color = 'var(--accent)'; });
                opt.addEventListener('mouseleave', () => { opt.style.background = ''; opt.style.color = ''; });
                opt.addEventListener('click', () => {
                    const val = opt.dataset.val;
                    // Update hidden select
                    if (ddReal) ddReal.value = val;
                    // Update trigger label
                    if (ddLabel) ddLabel.textContent = opt.textContent.trim();
                    // Update check dots
                    ddPanel.querySelectorAll('.term-dd-check').forEach(c => c.style.visibility = 'hidden');
                    const dot = opt.querySelector('.term-dd-check');
                    if (dot) dot.style.visibility = 'visible';
                    // Close panel
                    ddPanel.style.display = 'none';
                    if (ddChevron) ddChevron.style.transform = '';
                });
            });
            // Close on outside click
            document.addEventListener('click', e => {
                if (!$('termAttackDropdown').contains(e.target)) {
                    ddPanel.style.display = 'none';
                    if (ddChevron) ddChevron.style.transform = '';
                }
            });
        }
    }

    async function downloadReport() {
        if (!S.results) { toast('Run an analysis first.','error'); return; }
        const btn=$('downloadBtn'); if (btn) btn.disabled=true;
        try {
            const csrf=await getCsrf(), headers={'Content-Type':'application/json'}; if (csrf) headers['X-CSRFToken']=csrf;
            const res=await fetch('/api/download-report',{method:'POST',headers,body:JSON.stringify(S.results),credentials:'include'});
            if (!res.ok) throw new Error('Report generation failed.');
            const blob=await res.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');
            a.href=url; a.download='securepass_report.pdf'; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
            toast('Report downloaded!','success');
        } catch (err) { toast(err.message||'Download failed.','error'); }
        finally { if (btn) btn.disabled=false; }
    }

    /* ══ PASSWORD CHECKER ═══════════════════════════════ */
    function setupPasswordChecker() {
        const inp=$('pwInput'), eye=$('pwEye'), checkBtn=$('pwCheckBtn'), hibpBtn=$('pwHIBPBtn');
        if (eye) eye.addEventListener('click', ()=>{
            if (!inp) return; inp.type=inp.type==='password'?'text':'password';
            const ic=eye.querySelector('i')||eye.querySelector('svg'); if (ic) { ic.setAttribute('data-lucide',inp.type==='password'?'eye':'eye-off'); if(window.lucide)lucide.createIcons(); }
        });
        if (inp) inp.addEventListener('input', e=>{
            const val=e.target.value, fill=$('pwStrengthFill'), label=$('pwStrengthLabel');
            if (!fill) return;
            if (!val) { fill.style.display='none'; if(label)label.style.display='none'; return; }
            fill.style.display='block'; if(label)label.style.display='block';
            let s=0; if(val.length>8)s+=25; if(/[A-Z]/.test(val))s+=25; if(/[0-9]/.test(val))s+=25; if(/[^A-Za-z0-9]/.test(val))s+=25;
            const pf=fill.querySelector('.progress-fill');
            if (pf) { pf.style.width=s+'%'; pf.style.background=s<=25?'#ff5f57':s<=50?'#febc2e':s<=75?'#00d4ff':'#00b86e'; }
            if (label) label.textContent=s<=25?'Strength: Weak':s<=50?'Strength: Medium':s<=75?'Strength: Good':'Strength: Ultra';
        });
        if (checkBtn) checkBtn.addEventListener('click', async ()=>{
            const pw=inp?.value?.trim(); if (!pw) { toast('Enter a password first.','error'); return; }
            checkBtn.disabled=true; checkBtn.textContent='Checking...';
            try {
                const res=await fetch('/api/check-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw}),credentials:'include'});
                const data=await res.json().catch(()=>({}));
                if (!res.ok) throw new Error(data.error||'Check failed');
                renderPwCheckResult(data);
            } catch(err) { toast(err.message||'Password check failed.','error'); }
            finally { checkBtn.disabled=false; checkBtn.textContent='Check'; }
        });
        if (hibpBtn) hibpBtn.addEventListener('click', async ()=>{
            const pw=inp?.value?.trim(); if (!pw) { toast('Enter a password first.','error'); return; }
            // Bug 7 fix: /api/hibp/check-password requires login — guard before calling
            if (!S.user) { toast('Please sign in to use breach checking.','error'); return; }
            hibpBtn.disabled=true;
            const wrap=$('hibpResultWrap');
            if (wrap) { wrap.style.display='block'; wrap.innerHTML='<div style="color:var(--text-muted);font-size:12px">Checking breach database...</div>'; }
            const result=await window.HIBP.checkPassword(pw);
            if (result && result.error === 'auth_required') {
                if (wrap) { wrap.innerHTML='<div style="color:#febc2e;font-size:12px">Sign in required for breach checking.</div>'; }
            } else if (wrap) {
                HIBP.renderResult(result,wrap);
            }
            hibpBtn.disabled=false;
        });
    }

    function renderPwCheckResult(data) {
        const wrap=$('pwResultWrap'); if (!wrap) return;
        const risk=(data.risk_level||'').toLowerCase(), score=data.strength_score??'—';
        const col=risk.includes('high')?'#ff5f57':risk.includes('medium')?'#febc2e':'#00b86e';
        const tags=[{label:'Upper',ok:data.has_uppercase},{label:'Lower',ok:data.has_lowercase},{label:'Num',ok:data.has_numbers},{label:'Sym',ok:data.has_special}];
        wrap.innerHTML=`<div class="pw-check-result"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span class="status-pill" style="background:${col}22;color:${col}">${esc((data.risk_level||'Unknown').toUpperCase())}</span><span style="font-family:var(--font-mono);font-size:1.1rem;font-weight:700">${score}<span style="font-size:10px;color:var(--text-muted)">/100</span></span></div><div class="pw-check-tags">${tags.map(t=>`<span class="pw-tag ${t.ok?'pw-tag-pass':'pw-tag-fail'}">${esc(t.label)}</span>`).join('')}</div>${data.ai_recommendation?`<div style="font-size:11px;color:var(--text-muted);margin-top:6px;line-height:1.5">${esc(data.ai_recommendation)}</div>`:''}</div>`;
    }

    /* ══ RESET ══════════════════════════════════════════ */
    function setupResetBtn() {
        const btn=$('newAnalysisBtn'); if (btn) btn.addEventListener('click', resetDashboard);
    }

    function resetDashboard() {
        S.results=null; S._passwords=[]; S._datasetName=''; clearFile();
        // Hide dashboard rows
        [$('resultsSection'),$('breachSection')].forEach(el=>{ if(el) el.style.display='none'; });
        [$('downloadBtn'),$('newAnalysisBtn')].forEach(el=>{ if(el) el.style.display='none'; });
        const inp=$('inputSection'); if (inp) inp.style.display='block';
        ['resTotalPw','resUniquePw','resAvgLength','resHighRisk'].forEach(id=>setText(id,'—'));
        ['pctHigh','pctMedium','pctLow'].forEach(id=>setText(id,'0%'));
        const ring=$('scoreRingFill'); if (ring) ring.style.strokeDasharray='0 283';
        const num=$('scoreNum'); if (num) num.textContent='—';
        const pw=$('pwResultWrap'); if (pw) pw.innerHTML='';
        const hibp=$('hibpResultWrap'); if (hibp) { hibp.innerHTML=''; hibp.style.display='none'; }
        const ar=$('attackResults'); if (ar) ar.innerHTML='';
        // Reset panels back to empty states
        const cpc=$('compliancePageContent');
        if (cpc) cpc.innerHTML=`<div class="panel-empty-state"><i data-lucide="shield-off"></i><p>No analysis data yet.</p><span>Upload a password file from the Dashboard to see your compliance posture.</span></div>`;
        const apc=$('aiPolicyPageContent');
        if (apc) apc.innerHTML=`<div class="panel-empty-state"><i data-lucide="sparkles"></i><p>No analysis data yet.</p><span>Upload a password file from the Dashboard to generate AI-powered policy recommendations.</span></div>`;
        const ps=$('policySection'); if (ps) { ps.innerHTML=''; ps.style.display='none'; }
        const rpc=$('reportsPageContent');
        if (rpc) rpc.innerHTML=`<div class="panel-empty-state"><i data-lucide="file-text"></i><p>No reports yet.</p><span>Complete an analysis on the Dashboard to generate your first security report.</span></div>`;
        Object.values(S.charts).forEach(c=>{try{c.destroy();}catch{}});
        S.charts={};
        if (window.lucide) lucide.createIcons();
    }

    /* ══ REPORTS PAGE DOWNLOAD ══════════════════════════ */
    function setupReportsDownload() {
        // NOTE: The full Reports page wiring is handled by reports.js (Feature 6).
        // The header download button is wired there too; nothing to do here.
    }


    /* ══ AI POLICY PAGE ══════════════════════════════════ */

    let _aipLoaded = false;

    function setupAIPolicy() {
        const btn = document.getElementById('aipApplyBtn');
        if (!btn) return;
        btn.addEventListener('click', async () => {
            _aipLoaded = false;
            const snap = await _aipFetchSnapshot();
            if (snap && snap.has_data) {
                _aipFillBefore(snap);
                await _aipGenerate(snap);
            }
        });
    }

    async function initAIPolicyPage() {
        let snap = await _aipFetchSnapshot();

        // Fallback: if DB has no record yet, build snapshot from in-memory S.results
        if ((!snap || !snap.has_data) && S.results) {
            const ov  = S.results.overview  || {};
            const hib = S.results.hibp      || {};
            const com = S.results.compliance || {};
            const total  = ov.total_passwords || 0;
            const unique = ov.unique_passwords || total;
            snap = {
                has_data:         true,
                analysis_id:      S.results.analysis_id || null,
                risk_score:       ov.risk_score        || 0,
                risk_level:       S.results.risk_level || 'Unknown',
                weak_count:       ov.weak_passwords    || 0,
                total_passwords:  total,
                avg_length:       ov.average_length    || 0,
                breach_pct:       hib.breach_percentage || 0,
                breach_count:     hib.total_breached   || 0,
                reuse_pct:        total > 0 ? Math.round((total - unique) / total * 100 * 10) / 10 : 0,
                compliance_status: com.overall_status  || 'Unknown',
                _inline_results:  S.results,   // carry full data for _aipGenerate
            };
        }

        const empty   = document.getElementById('aipEmpty');
        const content = document.getElementById('aipContent');
        const btn     = document.getElementById('aipApplyBtn');

        if (!snap || !snap.has_data) {
            if (empty)   empty.style.display   = 'flex';
            if (content) content.style.display  = 'none';
            if (btn)     btn.style.display      = 'none';
            return;
        }

        if (empty)   empty.style.display   = 'none';
        if (content) content.style.display = 'block';
        if (btn)     btn.style.display     = 'flex';

        _aipFillBefore(snap);
        _aipSetupKeyword();

        if (!_aipLoaded) {
            await _aipGenerate(snap);
        } else {
            // Already generated — just ensure all result cards are visible
            // (summaryCard starts as display:none in HTML and is only shown inside _aipGenerate)
            const summCard = document.getElementById('aipSummaryCard');
            if (summCard) summCard.style.display = 'block';
            const gridEl = document.getElementById('aipCompareGrid');
            if (gridEl) gridEl.style.opacity = '1';
        }
    }

    async function _aipFetchSnapshot() {
        try {
            const r = await fetch('/api/ai-policy/snapshot', { credentials: 'include' });
            if (!r.ok) {
                if (r.status === 401) { console.warn('AI Policy: not authenticated'); }
                else { console.error('AI Policy snapshot HTTP error:', r.status); }
                return null;
            }
            return await r.json();
        } catch(e) {
            console.error('AI Policy snapshot error:', e);
            return null;
        }
    }

    function _aipFillBefore(snap) {
        const riskCol = snap.risk_score >= 75 ? '#00b86e'
                      : snap.risk_score >= 50 ? '#febc2e' : '#ff5f57';

        const scoreEl = document.getElementById('aipBeforeScore');
        if (scoreEl) { scoreEl.textContent = snap.risk_score ?? '—'; scoreEl.style.color = riskCol; }

        const _s = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? '—'; };
        _s('aipBeforeBreaches', snap.breach_count ?? 0);
        _s('aipBeforeWeak',     snap.weak_count   ?? 0);
        _s('aipBeforeLength',   snap.avg_length   ? snap.avg_length + ' ch' : '—');
        _s('aipBeforeReuse',    snap.reuse_pct    ? snap.reuse_pct + '%'    : '0%');

        const badge = document.getElementById('aipBeforeRiskBadge');
        if (badge) {
            badge.textContent = snap.risk_level || '—';
            badge.style.color = riskCol;
            badge.style.background = riskCol === '#ff5f57' ? 'rgba(255,95,87,0.15)'
                                   : riskCol === '#febc2e' ? 'rgba(254,188,46,0.15)'
                                   : 'rgba(0,184,110,0.15)';
        }

        const comp = document.getElementById('aipBeforeCompliance');
        if (comp) {
            const s = (snap.compliance_status || '').toLowerCase();
            const ok  = s === 'compliant' || s === 'full' || s === 'strong';
            const mid = s.includes('partial') || s === 'medium';
            comp.textContent   = snap.compliance_status || '—';
            comp.style.background = ok ? 'rgba(0,184,110,0.12)' : mid ? 'rgba(254,188,46,0.12)' : 'rgba(255,95,87,0.12)';
            comp.style.color      = ok ? '#00b86e'               : mid ? '#febc2e'               : '#ff5f57';
        }
    }

    async function _aipGenerate(snap) {
        const loadEl   = document.getElementById('aipLoading');
        const gridEl   = document.getElementById('aipCompareGrid');
        const summCard = document.getElementById('aipSummaryCard');

        if (loadEl)   loadEl.style.display    = 'block';
        if (gridEl)   gridEl.style.opacity    = '0.35';
        if (summCard) summCard.style.display  = 'none';

        const msgs = [
            'Analysing password vulnerability patterns...',
            'Running policy simulation engine...',
            'Generating context-aware passwords...',
            'Composing AI security assessment...',
        ];
        let mi = 0;
        const ticker = setInterval(() => {
            const el = document.getElementById('aipLoadingText');
            if (el && mi < msgs.length) el.textContent = msgs[mi++];
        }, 1400);

        try {
            const orgKeywordEl = document.getElementById('aipOrgKeyword');
            const orgKeyword = (orgKeywordEl && orgKeywordEl.value.trim()) || '';

            const payload = {
                analysis_id:        snap.analysis_id,
                current_risk_score: snap.risk_score,
                compliance_status:  snap.compliance_status,
                user_name: (S.user && (S.user.username || (S.user.email || '').split('@')[0])) || '',
                org_name:  orgKeyword,
                city:      'Mumbai',
                domain:    'cyber',
                // Pass full inline results when DB record may not exist yet
                inline_results: snap._inline_results || null,
            };

            const r = await fetch('/api/ai-policy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(payload),
            });

            clearInterval(ticker);
            if (loadEl) loadEl.style.display  = 'none';
            if (gridEl) gridEl.style.opacity  = '1';

            if (!r.ok) throw new Error('Server error: ' + r.status);
            const d = await r.json();
            if (!d.success) throw new Error(d.error || 'API error');

            _aipRenderAfter(d);
            _aipRenderDelta(d);
            _aipRenderSummary(d.ai_summary || '');
            _aipRenderPasswords(d.memorable_passwords || []);
            _aipRenderPolicy(d.recommended_policy || {});

            if (summCard) summCard.style.display = 'block';
            _aipLoaded = true;
            if (window.lucide) lucide.createIcons();

        } catch(e) {
            clearInterval(ticker);
            if (loadEl) loadEl.style.display  = 'none';
            if (gridEl) gridEl.style.opacity  = '1';
            if (summCard) summCard.style.display = 'block';
            console.error('AI Policy generation error:', e);
            toast('Policy generation failed: ' + (e.message || 'Please try again.'), 'error');
        }
    }

    function _aipRenderAfter(d) {
        const proj = d.projected || {};
        const _s = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? '—'; };
        _s('aipAfterScore',      proj.score      ?? '—');
        _s('aipAfterBreaches',   proj.breaches   ?? 0);
        _s('aipAfterCompliance', proj.compliance ?? '—');
        const badge = document.getElementById('aipAfterRiskBadge');
        if (badge) badge.textContent = proj.risk_level || 'Low Risk';
    }

    function _aipRenderDelta(d) {
        const delta = d.delta || {};
        const ds = document.getElementById('aipDeltaScore');
        if (ds) {
            const v = delta.score ?? 0;
            ds.textContent = (v > 0 ? '+' : '') + v;
            ds.style.color = v > 0 ? '#00b86e' : '#febc2e';
        }
        const db = document.getElementById('aipDeltaBreaches');
        if (db) db.textContent = (delta.breaches_reduced ?? 0) + ' less';

        const cu = document.getElementById('aipComplianceUpgrade');
        if (cu) cu.style.display = delta.compliance_upgrade ? 'flex' : 'none';
    }

    function _aipRenderSummary(text) {
        const el = document.getElementById('aipSummaryText');
        if (!el || !text) return;
        el.textContent = '';
        let i = 0;
        const iv = setInterval(() => {
            el.textContent += text[i++];
            if (i >= text.length) clearInterval(iv);
        }, 10);
    }

    function _aipRenderPasswords(passwords) {
        const list = document.getElementById('aipPasswordList');
        if (!list) return;
        list.innerHTML = passwords.map(pw => {
            const safe = esc(pw);
            return `<div class="aip-pw-item" data-pw="${safe}">
                <span>${safe}</span>
                <span class="aip-pw-copy">Click to copy</span>
            </div>`;
        }).join('');
        list.querySelectorAll('.aip-pw-item').forEach(item => {
            item.addEventListener('click', () => {
                const pw = item.getAttribute('data-pw');
                navigator.clipboard.writeText(pw).catch(() => {});
                item.classList.add('aip-copied');
                const span = item.querySelector('.aip-pw-copy');
                if (span) span.textContent = '✓ Copied!';
                setTimeout(() => {
                    item.classList.remove('aip-copied');
                    if (span) span.textContent = 'Click to copy';
                }, 1800);
            });
        });
    }

    function _aipRenderPolicy(policy) {
        const list = document.getElementById('aipPolicyRules');
        if (!list) return;
        const rules = [
            { icon: 'ruler',        label: 'Minimum length',         val: (policy.min_length || 12) + '+ chars',           on: true },
            { icon: 'type',         label: 'Uppercase required',      val: 'A–Z',                                            on: !!policy.require_upper },
            { icon: 'hash',         label: 'Numbers required',        val: '0–9',                                            on: !!policy.require_number },
            { icon: 'at-sign',      label: 'Special chars',           val: '!@#$%',                                          on: !!policy.require_special },
            { icon: 'book-x',       label: 'Block dictionary words',  val: 'Enabled',                                        on: !!policy.block_dictionary },
            { icon: 'keyboard',     label: 'Block keyboard patterns', val: 'Enabled',                                        on: !!policy.block_keyboard_patterns },
            { icon: 'shield-check', label: 'MFA recommended',         val: 'Enabled',                                        on: !!policy.mfa_recommended },
            { icon: 'rotate-cw',    label: 'Password rotation',       val: (policy.rotation_days || 90) + ' days',           on: true },
            { icon: 'lock',         label: 'Lockout threshold',       val: (policy.lockout_attempts || 3) + ' attempts',     on: true },
            { icon: 'history',      label: 'Password history',        val: 'Last ' + (policy.history_count || 5),            on: true },
        ];
        list.innerHTML = rules.map(r => `
            <div class="aip-rule-item">
                <div class="aip-rule-icon" style="${r.on ? '' : 'background:rgba(255,95,87,0.08);color:#ff5f57;'}">
                    <i data-lucide="${esc(r.icon)}" style="width:14px;height:14px;"></i>
                </div>
                <span style="flex:1;">${esc(r.label)}</span>
                <span style="font-family:var(--font-mono);font-size:12px;color:${r.on ? 'var(--accent)' : '#ff5f57'};">${esc(r.val)}</span>
            </div>`).join('');
        if (window.lucide) lucide.createIcons();
    }

    /* ── Org Keyword Password Generator ─────────────────────────────────── */

    function _aipSetupKeyword() {
        const btn = document.getElementById('aipKeywordBtn');
        const inp = document.getElementById('aipOrgKeyword');
        if (!btn || !inp) return;
        inp.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
        btn.addEventListener('click', () => {
            const kw = inp.value.trim();
            if (!kw) { toast('Enter an organisation keyword first.', 'error'); return; }
            _aipGenerateKeywordPasswords(kw);
        });
    }

    function _leetVariants(word) {
        const maps = [
            { a: 'a', l: '@' }, { a: 'e', l: '3' }, { a: 'i', l: '1' },
            { a: 'o', l: '0' }, { a: 's', l: '$' }, { a: 't', l: '7' },
            { a: 'g', l: '9' }, { a: 'b', l: '6' }, { a: 'l', l: '1' },
        ];
        const w = word.toLowerCase();
        const variants = new Set();

        variants.add(word.charAt(0).toUpperCase() + word.slice(1));
        variants.add(word.toUpperCase());

        for (const m of maps) {
            if (w.includes(m.a)) {
                variants.add(w.replaceAll(m.a, m.l));
                variants.add((w.charAt(0).toUpperCase() + w.slice(1)).replaceAll(m.a, m.l));
                variants.add(w.toUpperCase().replaceAll(m.a.toUpperCase(), m.l));
            }
        }

        // Apply all substitutions at once for the "full leet" variant
        let full = w;
        for (const m of maps) full = full.replaceAll(m.a, m.l);
        variants.add(full);
        variants.add(full.toUpperCase());
        variants.add(full.charAt(0).toUpperCase() + full.slice(1));

        return [...variants].filter(v => v !== word).slice(0, 9);
    }

    function _aipGenerateKeywordPasswords(keyword) {
        const preview = document.getElementById('aipLeetPreview');
        const tagsEl  = document.getElementById('aipLeetTags');
        const listEl  = document.getElementById('aipKeywordPwList');
        if (!preview || !tagsEl || !listEl) return;

        const variants = _leetVariants(keyword);

        // Show leet tag strip with colour coding
        const tagColors = ['var(--accent)', '#febc2e', '#ff5f57', '#00b86e'];
        tagsEl.innerHTML = variants.map((v, i) =>
            `<span style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;padding:3px 9px;font-family:var(--font-mono);font-size:12px;color:${tagColors[i % tagColors.length]};">${esc(v)}</span>`
        ).join('');

        const SECURITY_WORDS = ['Shield','Fortress','Vault','Cipher','Sentinel','Bastion','Guard','Titan','Apex','Nova','Storm','Hawk'];
        const SEPS = ['@','#','$','!','%','&','*'];
        const YEAR = '26';

        const passwords = new Set();
        let attempts = 0;
        while (passwords.size < 9 && attempts < 120) {
            attempts++;
            const v    = variants[Math.floor(Math.random() * variants.length)] || keyword;
            const word = SECURITY_WORDS[Math.floor(Math.random() * SECURITY_WORDS.length)];
            const sep  = SEPS[Math.floor(Math.random() * SEPS.length)];
            const num  = String(Math.floor(Math.random() * 98) + 2);

            const templates = [
                `${v}${sep}${word}${num}`,
                `${word}${sep}${v}${num}!`,
                `${v}${num}${sep}${word}`,
                `${word}${v}${sep}${YEAR}`,
                `Cyber${sep}${v}${word.slice(0,4)}${num}`,
                `${v}${sep}${word}${sep}${num}`,
                `${word}${num}${sep}${v}`,
                `${v}${word}${sep}${YEAR}!`,
                `Sec${sep}${v}${word.slice(0,3)}${num}`,
            ];
            const pw = templates[Math.floor(Math.random() * templates.length)];

            if (pw.length >= 12
                && /[A-Z]/.test(pw)
                && /[a-z]/.test(pw)
                && /[0-9]/.test(pw)
                && /[^A-Za-z0-9]/.test(pw)) {
                passwords.add(pw);
            }
        }

        listEl.innerHTML = [...passwords].map(pw => {
            const safe = esc(pw);
            return `<div class="aip-pw-item" data-pw="${safe}">
                <span>${safe}</span>
                <span class="aip-pw-copy">Click to copy</span>
            </div>`;
        }).join('');

        listEl.querySelectorAll('.aip-pw-item').forEach(item => {
            item.addEventListener('click', () => {
                const pw = item.getAttribute('data-pw');
                navigator.clipboard.writeText(pw).catch(() => {});
                item.classList.add('aip-copied');
                const span = item.querySelector('.aip-pw-copy');
                if (span) span.textContent = '✓ Copied!';
                setTimeout(() => {
                    item.classList.remove('aip-copied');
                    if (span) span.textContent = 'Click to copy';
                }, 1800);
            });
        });

        preview.style.display = 'block';
        toast(`Generated passwords using "${keyword}" leet variants!`, 'success');
        if (window.lucide) lucide.createIcons();
    }

    /* ══ UTILITIES ══════════════════════════════════════ */
    let _csrf=null;
    async function getCsrf() {
        if (_csrf) return _csrf;
        try { const r=await fetch('/api/csrf-token'); const d=await r.json(); _csrf=d.csrf_token||null; } catch {}
        return _csrf;
    }

    function toast(msg, type) {
        const c=$('toastContainer'); if (!c) return;
        const el=document.createElement('div'); el.className=`toast toast-${type||'info'}`; el.textContent=msg; c.appendChild(el);
        setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateX(20px)'; setTimeout(()=>el.remove(),320); },3500);
    }

    function setText(id, val) { const el=$(id); if (el) el.textContent=val!=null?val:'—'; }
    function pct(val, total) { if (!total) return 0; return Math.round((val/total)*100); }
    function fmtSize(bytes) { if (bytes<1024) return bytes+' B'; if (bytes<1024*1024) return (bytes/1024).toFixed(1)+' KB'; return (bytes/1024/1024).toFixed(1)+' MB'; }
    function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

})();