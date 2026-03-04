/**
 * script.js — SecurePass AI main dashboard
 * Requires: theme.js, hibp.js loaded before this file
 */
(function () {
  'use strict';

  /* ── State ─────────────────────────────────────────────── */
  const state = {
    selectedFile:    null,
    analysisResults: null,
    currentUser:     null,
    enableBreach:    true,
    enableAI:        true,
    enableCompliance:true,
    submitting:      false,
    pwCheckTimeout:  null,
  };

  /* ── DOM refs ──────────────────────────────────────────── */
  let $;

  /* ── Init ──────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    $ = id => document.getElementById(id);

    setupNav();
    setupUploadZone();
    setupToggles();
    setupPasswordChecker();
    setupResultsActions();
    checkAuthStatus();
  });

  /* ================================================================
     NAV
  ================================================================ */
  function setupNav() {
    const logoutBtn = $('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
  }

  async function checkAuthStatus() {
    try {
      const res  = await fetch('/api/auth/profile', { credentials: 'include' });
      const data = await res.json().catch(() => ({}));
      if (data.user || data.email) {
        state.currentUser = data.user || data;
        showUserNav(state.currentUser.email || state.currentUser);
      } else {
        showGuestNav();
      }
    } catch {
      showGuestNav();
    }
  }

  function showUserNav(email) {
    const auth    = $('navAuth');
    const userBox = $('navUser');
    const emailEl = $('navEmail');
    if (auth)    auth.style.display    = 'none';
    if (userBox) userBox.style.display = 'flex';
    if (emailEl) emailEl.textContent   = email;
  }

  function showGuestNav() {
    const auth    = $('navAuth');
    const userBox = $('navUser');
    if (auth)    auth.style.display    = 'flex';
    if (userBox) userBox.style.display = 'none';
  }

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    } catch {}
    state.currentUser = null;
    showGuestNav();
    toast('Logged out.', 'info');
    resetDashboard();
  }

  /* ================================================================
     UPLOAD ZONE
  ================================================================ */
  function setupUploadZone() {
    const zone      = $('uploadZone');
    const fileInput = $('fileInput');
    const selectBtn = $('selectFileBtn');
    const removeBtn = $('removeFileBtn');
    const analyzeBtn= $('analyzeBtn');

    if (selectBtn) selectBtn.addEventListener('click', () => fileInput && fileInput.click());
    if (zone)      zone.addEventListener('click',      () => fileInput && fileInput.click());

    if (fileInput) {
      fileInput.addEventListener('change', function (e) {
        if (e.target.files.length) handleFileSelect(e.target.files[0]);
      });
    }

    if (zone) {
      zone.addEventListener('dragover',  function (e) { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', function ()  { zone.classList.remove('drag-over'); });
      zone.addEventListener('drop',      function (e) {
        e.preventDefault(); zone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]);
      });
    }

    if (removeBtn) removeBtn.addEventListener('click', function (e) { e.stopPropagation(); clearFile(); });
    if (analyzeBtn) analyzeBtn.addEventListener('click', runAnalysis);
  }

  function handleFileSelect(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['txt','csv'].includes(ext)) {
      toast('Invalid file type. Use .txt or .csv', 'error'); return;
    }
    if (file.size > 16 * 1024 * 1024) {
      toast('File too large — max 16 MB.', 'error'); return;
    }
    state.selectedFile = file;

    const nameEl = $('fileName');
    const infoEl = $('fileInfo');
    const btn    = $('analyzeBtn');
    if (nameEl) nameEl.textContent = `${file.name}  (${fmtSize(file.size)})`;
    if (infoEl) infoEl.classList.add('visible');
    if (btn)    btn.disabled = false;
  }

  function clearFile() {
    state.selectedFile = null;
    const fi  = $('fileInput');
    const inf = $('fileInfo');
    const btn = $('analyzeBtn');
    if (fi)  fi.value   = '';
    if (inf) inf.classList.remove('visible');
    if (btn) btn.disabled = true;
  }

  /* ================================================================
     OPTIONS TOGGLES (Breach / AI / Compliance)
  ================================================================ */
  function setupToggles() {
    bindToggle('toggleBreach',     'pillBreach',     'enableBreach');
    bindToggle('toggleAI',         'pillAI',         'enableAI');
    bindToggle('toggleCompliance', 'pillCompliance', 'enableCompliance');
  }

  function bindToggle(wrapId, pillId, stateKey) {
    const wrap = $(wrapId);
    const pill = $(pillId);
    if (!wrap) return;
    // Set initial on-state
    if (state[stateKey]) { pill && pill.classList.add('on'); wrap.classList.add('active'); }
    wrap.addEventListener('click', function () {
      state[stateKey] = !state[stateKey];
      pill && pill.classList.toggle('on', state[stateKey]);
      wrap.classList.toggle('active', state[stateKey]);
    });
  }

  /* ================================================================
     ANALYSIS
  ================================================================ */
  async function runAnalysis() {
    if (state.submitting || !state.selectedFile) return;

    // Require login
    if (!state.currentUser) {
      toast('Please sign in to analyse datasets.', 'error');
      setTimeout(() => { window.location.href = '/login'; }, 1400);
      return;
    }

    state.submitting = true;
    showSection('loading');
    startLoaderSteps();

    try {
      const csrf = await getCsrfToken();
      const form = new FormData();
      form.append('file', state.selectedFile);
      form.append('enable_breach_check', state.enableBreach ? '1' : '0');
      form.append('enable_ai',           state.enableAI     ? '1' : '0');
      form.append('enable_compliance',   state.enableCompliance ? '1' : '0');

      const headers = {};
      if (csrf) headers['X-CSRFToken'] = csrf;

      const res = await fetch('/api/analyze', { method: 'POST', headers, body: form, credentials: 'include' });

      if (res.status === 401) {
        toast('Session expired. Please log in again.', 'error');
        showSection('input'); state.submitting = false; return;
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Server error ${res.status}`);
      }

      state.analysisResults = await res.json();
      renderResults(state.analysisResults);
      showSection('results');
      toast('Analysis complete!', 'success');

    } catch (err) {
      console.error('Analysis error:', err);
      toast(err.message || 'Analysis failed.', 'error');
      showSection('input');
    } finally {
      state.submitting = false;
    }
  }

  /* ── Loader steps ──────────────────────────────────────── */
  const STEPS = ['step-parse','step-detect','step-risk','step-breach','step-ai','step-report'];
  function startLoaderSteps() {
    STEPS.forEach(id => {
      const el = $(id);
      if (el) {
        el.classList.remove('active','done');
        const ic = el.querySelector('.step-icon i');
        if (ic) { ic.className = 'fa-regular fa-square'; }
      }
    });
    STEPS.forEach((id, i) => {
      setTimeout(() => {
        STEPS.slice(0, i).forEach(prev => {
          const p = $(prev);
          if (p) {
            p.classList.remove('active'); p.classList.add('done');
            const ic = p.querySelector('.step-icon i');
            if (ic) { ic.className = 'fa-solid fa-square-check'; ic.style.color = 'var(--green)'; }
          }
        });
        const el = $(id);
        if (el) {
          el.classList.add('active');
          const ic = el.querySelector('.step-icon i');
          if (ic) { ic.className = 'fa-solid fa-spinner fa-spin'; ic.style.color = 'var(--accent)'; }
        }
      }, i * 700);
    });
  }

  /* ================================================================
     RENDER RESULTS
  ================================================================ */
  function renderResults(data) {
    const ov = data.overview || {};
    const ci = (id, val) => { const e = $(id); if (e) e.textContent = val ?? '—'; };

    ci('resTotalPw',   ov.total_passwords);
    ci('resUniquePw',  ov.unique_passwords);
    ci('resAvgLength', ov.average_length ? Number(ov.average_length).toFixed(1) : '—');
    ci('resHighRisk',  data.risk_distribution?.['High Risk'] ?? data.risk_distribution?.high ?? ov.weak_passwords ?? '—');

    // Score ring
    const score = ov.risk_score ?? 0;
    ci('scoreNum', score);
    animateRing('scoreRingFill', score, 100);

    // Risk badge
    const badge = $('riskBadge');
    if (badge) {
      const level = (data.risk_level || '').toLowerCase();
      badge.className  = 'risk-badge risk-' + (level || 'medium');
      badge.textContent = (data.risk_level || 'Unknown').toUpperCase();
    }

    // Risk distribution bars
    const rd = data.risk_distribution || {};
    const total = ov.total_passwords || 1;
    animateBar('barHigh',   rd['High Risk']   || rd.high   || 0, total, 'pctHigh');
    animateBar('barMedium', rd['Medium Risk'] || rd.medium || 0, total, 'pctMedium');
    animateBar('barLow',    rd['Low Risk']    || rd.low    || 0, total, 'pctLow');

    // Patterns
    renderPatterns(data.patterns);

    // HIBP
    if (state.enableBreach && (data.breach_statistics || data.breach_stats) && window.HIBP) {
      const bsec = $('breachSection');
      const bstats = data.breach_statistics || data.breach_stats;
      if (bsec) { bsec.style.display = 'block'; HIBP.renderBreachStats(bstats, $('breachContainer')); }
    } else {
      const bsec = $('breachSection'); if (bsec) bsec.style.display = 'none';
    }

    // Compliance
    renderCompliance(data.compliance);

    // AI Insights
    renderInsights(data.ai_insights);

    // Charts
    renderCharts(data.charts);

    // Download button
    const dl = $('downloadBtn');
    if (dl) dl.style.display = 'inline-flex';
  }

  function animateRing(id, value, max) {
    const el = $(id);
    if (!el) return;
    const circ = 2 * Math.PI * 52; // r=52
    const pct  = Math.min(Math.max(value / max, 0), 1);
    el.setAttribute('stroke-dasharray', circ);
    el.setAttribute('stroke-dashoffset', circ);
    const color = value >= 70 ? 'var(--red)' : value >= 40 ? 'var(--amber)' : 'var(--green)';
    el.setAttribute('stroke', color);
    requestAnimationFrame(() => {
      el.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)';
      el.setAttribute('stroke-dashoffset', circ * (1 - pct));
    });
  }

  function animateBar(fillId, count, total, pctId) {
    const fill = $(fillId);
    const pctEl= $(pctId);
    if (!fill) return;
    const pct = total ? (count / total * 100) : 0;
    if (pctEl) pctEl.textContent = pct.toFixed(1) + '%';
    requestAnimationFrame(() => {
      fill.style.width = pct.toFixed(1) + '%';
    });
  }

  function renderPatterns(patterns) {
    const wrap = $('patternsWrap');
    if (!wrap) return;
    const map = (patterns && patterns.patterns) ? patterns.patterns : patterns;
    if (!map) { wrap.innerHTML = '<p class="text-muted" style="font-size:0.8rem">No pattern data available.</p>'; return; }
    const icons = {
      dictionary_based:   '<i class="fa-solid fa-book"></i>',
      keyboard_patterns:  '<i class="fa-solid fa-keyboard"></i>',
      sequential_numbers: '<i class="fa-solid fa-list-ol"></i>',
      name_based:         '<i class="fa-solid fa-user"></i>',
      date_patterns:      '<i class="fa-solid fa-calendar"></i>',
      repeated_chars:     '<i class="fa-solid fa-rotate"></i>',
      common_words:       '<i class="fa-solid fa-comment"></i>',
    };
    const defaultIcon = '<i class="fa-solid fa-magnifying-glass"></i>';
    const entries = Object.entries(map).filter(([,v]) => (v?.count || 0) > 0);
    if (!entries.length) { wrap.innerHTML = '<p class="text-muted" style="font-size:0.8rem">No patterns detected.</p>'; return; }
    wrap.innerHTML = entries.map(([k, v]) => `
      <div class="metric-card" style="flex-direction:row;align-items:center;gap:12px;padding:12px 14px">
        <div class="metric-icon" style="margin-bottom:0;flex-shrink:0">${icons[k] || defaultIcon}</div>
        <div>
          <div class="metric-label">${k.replace(/_/g,' ')}</div>
          <div style="font-size:0.85rem;font-weight:700">${v.count} <span class="text-muted" style="font-size:0.72rem">(${v.percentage ?? 0}%)</span></div>
        </div>
      </div>`).join('');
  }

  function renderCompliance(compliance) {
    const wrap = $('complianceWrap');
    if (!wrap || !compliance) return;
    const items = [
      { name: 'NIST SP 800-63', key: 'nist_compliance_status' },
      { name: 'OWASP',          key: 'owasp_risk_level' },
      { name: 'ISO 27001',      key: 'iso_compliance_status' },
    ];
    wrap.innerHTML = items.map(item => {
      const raw    = (compliance[item.key] || 'Unknown');
      const cls    = raw.toLowerCase().includes('compli') ? 'compliant'
                   : raw.toLowerCase().includes('partial')? 'partial' : 'noncompliant';
      return `<div class="compliance-item">
        <span class="compliance-name">${item.name}</span>
        <span class="compliance-status status-${cls}">${raw}</span>
      </div>`;
    }).join('');
  }

  function renderInsights(insights) {
    const wrap = $('insightsWrap');
    if (!wrap) return;
    if (!insights || !insights.length) {
      wrap.innerHTML = '<p class="text-muted" style="font-size:0.8rem">No AI insights available.</p>'; return;
    }
    wrap.innerHTML = insights.map((txt, i) => `
      <div class="insight-item" style="animation-delay:${i * 0.08}s">
        <div class="insight-num">${i + 1}</div>
        <div class="insight-text">${esc(txt)}</div>
      </div>`).join('');
  }

  function renderCharts(charts) {
    if (!charts) return;
    const map = {
      chartRisk:    charts.risk_pie,
      chartLength:  charts.length_distribution,
      chartStrength:charts.strength_distribution,
      chartPattern: charts.pattern_distribution,
    };
    Object.entries(map).forEach(([id, path]) => {
      if (!path) return;
      const el = $(id);
      if (!el) return;
      let src = path.replace(/^frontend\/static\//, '');
      if (!src.startsWith('/static/')) src = '/static/' + src;
      el.src = src;
      el.onerror = () => { el.parentElement.style.display = 'none'; };
    });
    const cg = $('chartsGrid');
    if (cg) cg.style.display = 'grid';
  }

  /* ================================================================
     PASSWORD CHECKER
  ================================================================ */
  function setupPasswordChecker() {
    const inp        = $('pwInput');
    const eye        = $('pwEye');
    const checkBtn   = $('pwCheckBtn');
    const hibpBtn    = $('pwHIBPBtn');
    const strengthFill = $('pwStrengthFill');

    if (eye) eye.addEventListener('click', function () {
      if (!inp) return;
      inp.type = inp.type === 'password' ? 'text' : 'password';
      const icon = eye.querySelector('i');
      if (icon) icon.className = inp.type === 'password' ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash';
    });

    if (inp) inp.addEventListener('input', function () {
      clearTimeout(state.pwCheckTimeout);
      updateLocalStrength(inp.value);
    });

    if (checkBtn) checkBtn.addEventListener('click', async function () {
      const pw = inp?.value?.trim();
      if (!pw) { toast('Enter a password first.', 'error'); return; }
      await runPasswordCheck(pw);
    });

    if (hibpBtn && window.HIBP) {
      hibpBtn.addEventListener('click', async function () {
        const pw = inp?.value?.trim();
        if (!pw) { toast('Enter a password first.', 'error'); return; }
        hibpBtn.disabled = true;
        const c = $('hibpResultWrap');
        if (c) { c.style.display = 'block'; c.innerHTML = '<div class="hibp-checking"><div class="hibp-spinner"></div> Checking breach database…</div>'; }
        const result = await HIBP.checkPassword(pw);
        if (c) { HIBP.renderResult(result, c); }
        hibpBtn.disabled = false;
      });
    }
  }

  function updateLocalStrength(pw) {
    const fill  = $('pwStrengthFill');
    const label = $('pwStrengthLabel');
    if (!fill) return;
    const checks = [
      pw.length >= 8, /[A-Z]/.test(pw), /[a-z]/.test(pw),
      /[0-9]/.test(pw), /[^A-Za-z0-9]/.test(pw),
      pw.length >= 12, pw.length >= 16,
    ];
    const score  = checks.filter(Boolean).length;
    const pct    = Math.round(score / 7 * 100);
    const colors = ['var(--border)','var(--red)','var(--red)','var(--amber)','var(--amber)','var(--green)','var(--green)','var(--green)'];
    fill.style.width      = pct + '%';
    fill.style.background = colors[score];
    if (label) {
      const lbls = ['','Very Weak','Weak','Fair','Good','Strong','Very Strong','Excellent'];
      label.textContent = pw ? lbls[score] : '';
    }
  }

  async function runPasswordCheck(pw) {
    const btn = $('pwCheckBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    try {
      const res  = await fetch('/api/check-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pw }),
        credentials: 'include',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Check failed');
      renderPasswordCheckResult(data);
    } catch (err) {
      toast(err.message || 'Password check failed.', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Analyse'; }
    }
  }

  function renderPasswordCheckResult(data) {
    const wrap = $('pwResultWrap');
    if (!wrap) return;
    const risk   = (data.risk_level || 'unknown').toLowerCase();
    const color  = risk === 'high' ? 'var(--red)' : risk === 'medium' ? 'var(--amber)' : 'var(--green)';
    const checks = [
      ['Uppercase',  data.has_uppercase],
      ['Lowercase',  data.has_lowercase],
      ['Number',     data.has_numbers],
      ['Symbol',     data.has_special],
    ];
    wrap.style.display = 'block';
    wrap.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <div class="risk-badge risk-${risk}" style="border-color:${color};color:${color}">
          ${(data.risk_level || 'Unknown').toUpperCase()}
        </div>
        <span style="font-family:var(--font-display);font-size:1.5rem;font-weight:800">${data.strength_score ?? '—'}<span style="font-size:0.8rem;font-weight:400;color:var(--text-muted)">/100</span></span>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        ${checks.map(([lbl,ok]) => `<span class="tag" style="border-color:${ok ? 'var(--green)' : 'var(--border)'};color:${ok ? 'var(--green)' : 'var(--text-dim)'}">
          <i class="fa-solid ${ok ? 'fa-check' : 'fa-xmark'}"></i> ${lbl}</span>`).join('')}
      </div>
      ${data.ai_recommendation ? `<div class="pw-detail"><i class="fa-solid fa-lightbulb" style="color:var(--amber)"></i> ${esc(data.ai_recommendation)}</div>` : ''}`;
  }

  /* ================================================================
     RESULTS ACTIONS (New analysis, Download)
  ================================================================ */
  function setupResultsActions() {
    const newBtn = $('newAnalysisBtn');
    const dlBtn  = $('downloadBtn');
    if (newBtn) newBtn.addEventListener('click', resetDashboard);
    if (dlBtn)  dlBtn.addEventListener('click',  downloadReport);
  }

  async function downloadReport() {
    if (!state.analysisResults) { toast('No results to download.', 'error'); return; }
    const btn = $('downloadBtn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating…'; }
    try {
      const res = await fetch('/api/download-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state.analysisResults),
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Report generation failed');
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'securepass_report.pdf';
      document.body.appendChild(a); a.click();
      document.body.removeChild(a); URL.revokeObjectURL(url);
      toast('Report downloaded!', 'success');
    } catch (err) {
      toast(err.message || 'Download failed.', 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-download"></i> Download Report'; }
    }
  }

  function resetDashboard() {
    state.analysisResults = null;
    clearFile();
    showSection('input');
    const dl = $('downloadBtn');
    if (dl) dl.style.display = 'none';
    const pwWrap = $('pwResultWrap');
    if (pwWrap) pwWrap.style.display = 'none';
    const hibpWrap = $('hibpResultWrap');
    if (hibpWrap) { hibpWrap.style.display = 'none'; hibpWrap.innerHTML = ''; }
  }

  /* ================================================================
     SECTION SWITCHING
  ================================================================ */
  function showSection(name) {
    ['input','loading','results'].forEach(n => {
      const el = $(n + 'Section');
      if (el) el.style.display = n === name ? 'block' : 'none';
    });
  }

  /* ================================================================
     CSRF
  ================================================================ */
  let _csrf = null;
  async function getCsrfToken() {
    if (_csrf) return _csrf;
    try {
      const r = await fetch('/api/csrf-token');
      const d = await r.json();
      _csrf = d.csrf_token || null;
    } catch {}
    return _csrf;
  }

  /* ================================================================
     TOAST
  ================================================================ */
  function toast(msg, type) {
    type = type || 'info';
    const container = $('toastContainer');
    if (!container) { console.log('[TOAST]', msg); return; }
    const el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(20px)'; el.style.transition = '0.3s ease'; setTimeout(() => el.remove(), 320); }, 3500);
  }

  /* ================================================================
     UTILITIES
  ================================================================ */
  function fmtSize(bytes) {
    if (bytes < 1024)          return bytes + ' B';
    if (bytes < 1024 * 1024)   return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

})();