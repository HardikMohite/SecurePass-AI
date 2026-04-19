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
        setupLogout();
        setupSidebar();
        setupSettingsNav();
        setupSettingsInteractions();
        setupAIDrawer();
        await checkAuth();
        if (window.lucide) lucide.createIcons();
    });

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
            S.user = null; showGuestNav(); toast('Logged out.', 'info'); resetDashboard();
        });
    }

    /* ══ SIDEBAR ════════════════════════════════════════ */
    function setupSidebar() {
        const dashBtn = $('dashboardBtn'), settBtn = $('settingsBtn');
        const dashSec = $('dashboardSection'), settSec = $('settingsSection');
        const navItems = document.querySelectorAll('.sidebar-nav .nav-item');

        if (dashBtn) dashBtn.addEventListener('click', () => {
            if (settSec) settSec.style.display = 'none';
            if (dashSec) dashSec.style.display = 'block';
            navItems.forEach(i => i.classList.remove('active'));
            dashBtn.classList.add('active');
        });

        if (settBtn) settBtn.addEventListener('click', () => {
            if (dashSec) dashSec.style.display = 'none';
            if (settSec) settSec.style.display = 'block';
            navItems.forEach(i => i.classList.remove('active'));
            settBtn.classList.add('active');
        });
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
        initRealCharts(data);
        renderCompliance(data.compliance);

        if (data.breach_statistics||data.breach_stats) {
            const bs=$('breachSection'), bc=$('breachContainer');
            if (bs) bs.style.display='block';
            if (bc&&window.HIBP) HIBP.renderBreachStats(data.breach_statistics||data.breach_stats,bc);
            const pill=$('pillBreach'); if (pill) { pill.textContent='On'; pill.style.color='var(--accent)'; }
        }

        renderAttackScenarios(data.attack_scenarios);
        renderPolicyImpact(data.policy_impact, data.recommended_password_policy, data.password_examples);
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
        const wrap=$('complianceWrap'); if (!wrap||!compliance) return;
        const items=[{label:'NIST 800-63B',status:compliance.nist_compliance_status||'N/A'},{label:'OWASP Top 10',status:compliance.owasp_risk_level||'N/A'},{label:'ISO/IEC 27001',status:compliance.iso_compliance_status||compliance.iso_status||'N/A'}];
        wrap.innerHTML=items.map(item=>{
            const s=(item.status||'').toLowerCase(), ok=s==='compliant'||s==='low', mid=s.includes('partial')||s==='medium';
            const bg=ok?'rgba(0,184,110,0.12)':mid?'rgba(254,188,46,0.12)':'rgba(255,95,87,0.12)', col=ok?'#00b86e':mid?'#febc2e':'#ff5f57';
            return `<div class="compliance-row"><span style="font-size:13px">${esc(item.label)}</span><span class="status-pill" style="background:${bg};color:${col}">${esc(item.status)}</span></div>`;
        }).join('');
        const sec=$('complianceSection'), pill=$('pillCompliance');
        if (sec) sec.style.display='block'; if (pill) { pill.textContent='On'; pill.style.color='var(--accent)'; }
    }

    function renderAttackScenarios(attacks) {
        const term=$('attackResults'); if (!term||!attacks||!attacks.length) return;
        term.innerHTML='';
        attacks.forEach((a,i)=>setTimeout(()=>{
            const div=document.createElement('div'), p=(a.probability||0).toFixed(1), col=a.probability>60?'#ff5f57':a.probability>30?'#febc2e':'#00d4ff';
            div.className='log-dim'; div.innerHTML=`<span class="terminal-prompt">$</span><span style="color:${col}">[${p}%]</span> ${esc(a.name)}: ${esc(a.description)} (${(a.count||0).toLocaleString()}/${(a.total||0).toLocaleString()})`;
            term.appendChild(div); term.scrollTop=term.scrollHeight;
        }, i*200));
    }

    function renderPolicyImpact(policy, recommended, examples) {
        if (!policy) return;
        let wrap=$('policySection');
        if (!wrap) { wrap=document.createElement('div'); wrap.id='policySection'; wrap.className='card'; wrap.style.marginTop='1.25rem'; const col=qs('.right-col'); if (col) col.appendChild(wrap); }
        const imp=policy.projected_improvement||{};
        const rows=[['Current Score',(policy.current_score||0)+'/100'],['Projected Score',(imp.projected_score||0)+'/100'],['Improvement','+'+(imp.improvement||0).toFixed(1)+' pts']];
        wrap.innerHTML=`<div class="card-header"><i data-lucide="trending-up"></i><span>Policy Impact</span></div>${rows.map(([l,v])=>`<div class="policy-row"><span style="font-size:12px">${esc(l)}</span><span class="policy-val">${esc(v)}</span></div>`).join('')}${recommended?`<div class="ai-insight-item" style="margin-top:12px;font-size:11px">${esc(typeof recommended==='string'?recommended:recommended.description||'')}</div>`:''}`;
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

        // 1. Doughnut — legend right
        const c1=$('chartRisk');
        if (c1) S.charts.risk=new Chart(c1.getContext('2d'),{type:'doughnut',data:{labels:['High Risk','Medium Risk','Low Risk'],datasets:[{data:[high,med,low],backgroundColor:['#ff5f57','#febc2e','#00b86e'],borderWidth:0,hoverOffset:12}]},options:{cutout:'72%',maintainAspectRatio:false,plugins:{legend:{display:true,position:'right',labels:{color:'#666',usePointStyle:true,font:{size:11,family:'JetBrains Mono'}}}}}});

        // 2. Horizontal bar — length distribution
        const c2=$('chartLength');
        if (c2) {
            const ld=data.patterns?.length_distribution;
            let labels,values;
            if (ld&&typeof ld==='object'&&Object.keys(ld).length) { labels=Object.keys(ld); values=Object.values(ld); }
            else { labels=['<8 chars','8-11 chars','12-15 chars','16+ chars']; values=[ov.weak_passwords||0,Math.round((ov.medium_passwords||0)*0.6),Math.round((ov.medium_passwords||0)*0.4),ov.strong_passwords||0]; }
            S.charts.length=new Chart(c2.getContext('2d'),{type:'bar',data:{labels,datasets:[{label:'Length',data:values,backgroundColor:'rgba(0,212,255,0.4)',borderColor:'#00d4ff',borderWidth:1,borderRadius:4}]},options:{indexAxis:'y',maintainAspectRatio:false,scales:{x:{grid:{display:false},ticks:{color:'#666',font:{size:10}}},y:{grid:{display:false},ticks:{color:'#888',font:{size:11}}}},plugins:{legend:{display:false}}}});
        }

        // 3. Radar — composition
        const c3=$('chartStrength');
        if (c3) {
            const comp=data.patterns?.character_composition||{};
            S.charts.strength=new Chart(c3.getContext('2d'),{type:'radar',data:{labels:['Entropy','Diversity','Complexity','Novelty','Resilience'],datasets:[{label:'Baseline',data:[comp.uppercase?.percentage||0,comp.lowercase?.percentage||0,comp.digits?.percentage||0,comp.special?.percentage||0,Math.min(100,(ov.average_length||0)*5)],backgroundColor:'rgba(0,212,255,0.1)',borderColor:'#00d4ff',borderWidth:2,pointBackgroundColor:'#00d4ff'}]},options:{maintainAspectRatio:false,scales:{r:{angleLines:{color:'rgba(255,255,255,0.05)'},grid:{color:'rgba(255,255,255,0.05)'},pointLabels:{color:'#888',font:{size:11,family:'Inter'}},ticks:{display:false}}},plugins:{legend:{display:false}}}});
        }

        // 4. Pattern horizontal bars
        const c4=$('chartPattern');
        if (c4) {
            const p=data.patterns?.patterns||{};
            const pm=[{label:'Dictionary',key:'dictionary_based',color:'#ff5f57'},{label:'Name',key:'name_based',color:'#ff8c42'},{label:'Num Suffix',key:'numeric_suffix',color:'#febc2e'},{label:'Keyboard',key:'keyboard_walk',color:'#00d4ff'},{label:'Cap Misuse',key:'capitalization_misuse',color:'#9b59ff'},{label:'Leet',key:'leetspeak',color:'#00e5cc'},{label:'Sequential',key:'sequential_numbers',color:'#00b86e'}].filter(x=>p[x.key]&&(p[x.key].percentage||0)>0);
            if (pm.length) {
                S.charts.pattern=new Chart(c4.getContext('2d'),{type:'bar',data:{labels:pm.map(x=>x.label),datasets:[{data:pm.map(x=>p[x.key]?.percentage||0),backgroundColor:pm.map(x=>x.color+'cc'),borderWidth:0,borderRadius:3}]},options:{indexAxis:'y',maintainAspectRatio:false,scales:{x:{grid:{display:false},ticks:{color:'#666',font:{size:11}}},y:{grid:{display:false},ticks:{color:'#888',font:{size:11}}}},plugins:{legend:{display:false}}}});
            } else {
                S.charts.pattern=new Chart(c4.getContext('2d'),{type:'bar',data:{labels:['Wk1','Wk2','Wk3','Wk4','Wk5','Wk6','Wk7','Wk8'],datasets:[{label:'Score',data:[45,52,48,70,65,80,85,Math.round(ov.risk_score||0)],backgroundColor:'rgba(0,212,255,0.2)',borderColor:'#00d4ff',borderWidth:1}]},options:{maintainAspectRatio:false,scales:{x:{grid:{display:false},ticks:{color:'#666',font:{size:11}}},y:{grid:{color:'rgba(255,255,255,0.03)'},ticks:{color:'#666',font:{size:11}}}},plugins:{legend:{display:false}}}});
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
                        const div=document.createElement('div'), p=(a.probability||0).toFixed(1), col=a.probability>60?'#ff5f57':a.probability>30?'#febc2e':'#00d4ff';
                        div.className='log-dim'; div.innerHTML=`<span class="terminal-prompt">$</span><span style="color:${col}">[${p}%]</span> ${esc(a.name)}: ${esc(a.description)} (${(a.count||0).toLocaleString()} of ${(a.total||0).toLocaleString()})`;
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
            hibpBtn.disabled=true;
            const wrap=$('hibpResultWrap');
            if (wrap) { wrap.style.display='block'; wrap.innerHTML='<div style="color:var(--text-muted);font-size:12px">Checking breach database...</div>'; }
            const result=await window.HIBP.checkPassword(pw);
            if (wrap) HIBP.renderResult(result,wrap);
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
        ['resultsSection','simulationSection','scoreWrapper','resetAction'].forEach(id=>{const el=$(id);if(el)el.style.display='none';});
        const inp=$('inputSection'); if (inp) inp.style.display='block';
        ['resTotalPw','resUniquePw','resAvgLength','resHighRisk'].forEach(id=>setText(id,'0'));
        ['pctHigh','pctMedium','pctLow'].forEach(id=>setText(id,'0%'));
        const ring=$('scoreRingFill'); if (ring) ring.style.strokeDasharray='0 283';
        const num=$('scoreNum'); if (num) num.textContent='0';
        const pw=$('pwResultWrap'); if (pw) pw.innerHTML='';
        const hibp=$('hibpResultWrap'); if (hibp) { hibp.innerHTML=''; hibp.style.display='none'; }
        const ar=$('attackResults'); if (ar) ar.innerHTML='';
        const ps=$('policySection'); if (ps) ps.remove();
        Object.values(S.charts).forEach(c=>{try{c.destroy();}catch{}});
        S.charts={};
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