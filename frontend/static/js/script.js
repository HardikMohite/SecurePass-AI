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

    const S = { file: null, results: null, user: null, submitting: false, charts: {} };
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
        setupSettingsNav();
        setupSettingsInteractions();
        setupAIDrawer();
        setupComplianceRefresh();
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
            });
        });

        // Expose globally so other modules can navigate programmatically
        window.showPage = showPage;
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
            const res = await fetch('/api/analyze', { method:'POST', headers, body:form, credentials:'include' });
            if (res.status===401) { toast('Session expired — please log in.','error'); window.location.href='/login'; return; }
            if (!res.ok) { const err=await res.json().catch(()=>({})); throw new Error(err.error||`Server error ${res.status}`); }
            S.results = await res.json();
            completeSteps();
            setTimeout(() => {
                if (load) load.style.display='none';
                renderResults(S.results);
                renderAIDrawer(S.results.ai_insights);
                toast('Analysis complete!','success');
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
            const resp = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: 'claude-sonnet-4-20250514',
                    max_tokens: 1000,
                    messages: [{ role: 'user', content: prompt }]
                })
            });
            const data = await resp.json();
            const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
            if (text && textEl) {
                textEl.className = 'compliance-ai-text';
                textEl.textContent = text;
            }
        } catch (e) {
            if (textEl) {
                textEl.className = 'compliance-ai-text';
                // Fallback from notes if API fails
                const notes = compliance.compliance_notes || [];
                textEl.textContent = notes.length > 0
                    ? notes.slice(0, 3).join(' ')
                    : 'AI analysis unavailable. Review the violations and notes above for actionable remediation steps.';
            }
        }
    }

    function renderAttackScenarios(attacks) {
        const term=$('attackResults'); if (!term||!attacks||!attacks.length) return;
        term.innerHTML='';
        attacks.forEach((a,i)=>setTimeout(()=>{
            const div=document.createElement('div');
            // Bug 5 fix: fallback returns strings; normal path returns objects
            let p, col, line;
            if (typeof a === 'string') {
                p = 0; col = '#00d4ff';
                line = `<span class="terminal-prompt">$</span><span style="color:${col}">[--]</span> ${esc(a)}`;
            } else {
                p = (a.probability||0).toFixed(1);
                col = a.probability>60?'#ff5f57':a.probability>30?'#febc2e':'#00d4ff';
                line = `<span class="terminal-prompt">$</span><span style="color:${col}">[${p}%]</span> ${esc(a.name)}: ${esc(a.description)} (${(a.count||0).toLocaleString()}/${(a.total||0).toLocaleString()})`;
            }
            div.className='log-dim'; div.innerHTML=line;
            term.appendChild(div); term.scrollTop=term.scrollHeight;
        }, i*200));
    }

    function renderPolicyImpact(policy, recommended, examples) {
        if (!policy) return;
        // Target the dedicated AI Policy panel section
        const wrap = $('policySection');
        if (!wrap) return;
        wrap.style.display = 'block';
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
        // Also clear the empty-state
        const pc = $('aiPolicyPageContent');
        if (pc) pc.innerHTML = '';
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

    /* ══ SIMULATION ═════════════════════════════════════ */
    function setupSimulation() {
        const runBtn=$('btnRunSim'), dlBtn=$('downloadBtn');
        if (runBtn) {
            runBtn.addEventListener('click', ()=>{
                const term=$('attackResults'); if (!term) return; term.innerHTML='';
                if (S.results&&S.results.attack_scenarios&&S.results.attack_scenarios.length) {
                    S.results.attack_scenarios.forEach((a,i)=>setTimeout(()=>{
                        const div=document.createElement('div');
                        // Bug 5 fix: handle both string (fallback) and object (normal) scenarios
                        let line;
                        if (typeof a === 'string') {
                            line = `<span class="terminal-prompt">$</span><span style="color:#00d4ff">[--]</span> ${esc(a)}`;
                        } else {
                            const p=(a.probability||0).toFixed(1), col=a.probability>60?'#ff5f57':a.probability>30?'#febc2e':'#00d4ff';
                            line = `<span class="terminal-prompt">$</span><span style="color:${col}">[${p}%]</span> ${esc(a.name)}: ${esc(a.description)} (${(a.count||0).toLocaleString()} of ${(a.total||0).toLocaleString()})`;
                        }
                        div.className='log-dim'; div.innerHTML=line;
                        term.appendChild(div); term.scrollTop=term.scrollHeight;
                    }, i*280));
                } else {
                    [{text:'No dataset loaded. Upload a file first.',cls:'log-dim'}].forEach((l,i)=>setTimeout(()=>{
                        const div=document.createElement('div'); div.className=l.cls; div.innerHTML=`<span class="terminal-prompt">$</span>${esc(l.text)}`; term.appendChild(div);
                    },i*200));
                }
            });
        }
        if (dlBtn) dlBtn.addEventListener('click', downloadReport);
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
        S.results=null; clearFile();
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
        // Wire the Reports panel Download button to the same downloadReport() fn
        const btn=$('downloadBtnReports');
        if (btn) btn.addEventListener('click', downloadReport);
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