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
    renderCharts(data);

    // Attack Simulation
    // Attack Simulation — store data, wire up button
    initAttackSim(data.attack_scenarios, data.overview);

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

  function initAttackSim(scenarios, overview) {
    const btn = document.getElementById('btnRunSim');
    if (!btn) return;

    // Store on window so button handler can read them
    window._simScenarios = scenarios || [];
    window._simOverview  = overview  || {};

    // Reset terminal to idle state
    const term = document.getElementById('attackTerminal');
    if (term) {
      term.innerHTML = '<div class="t-line t-muted"><span>// Ready. Dataset loaded: <span class="t-success">' +
        (overview && overview.total_passwords ? overview.total_passwords.toLocaleString() : '?') +
        ' passwords</span>. Click EXECUTE SIMULATION to begin. <span class="t-cursor"></span></span></div>';
    }
    const results = document.getElementById('attackResults');
    if (results) { results.style.display = 'none'; results.innerHTML = ''; }

    btn.disabled = false;
    btn.onclick  = () => runSimAnimation(window._simScenarios, window._simOverview);
  }

  function runSimAnimation(scenarios, overview) {
    const btn  = document.getElementById('btnRunSim');
    const term = document.getElementById('attackTerminal');
    if (!btn || !term) return;

    btn.disabled = true;
    btn.textContent = '⏳ RUNNING...';

    const total   = overview && overview.total_passwords ? overview.total_passwords : 0;
    const unique  = overview && overview.unique_passwords ? overview.unique_passwords : 0;
    const avgLen  = overview && overview.average_length  ? overview.average_length  : 0;
    const uniquePct = total > 0 ? ((unique / total) * 100).toFixed(1) : 0;

    function riskLabel(pct) {
      if (pct >= 40) return ['CRITICAL', 'badge-critical'];
      if (pct >= 25) return ['HIGH',     'badge-high'];
      if (pct >= 10) return ['MEDIUM',   'badge-medium'];
      return               ['LOW',       'badge-low'];
    }
    function barColor(pct) {
      if (pct >= 40) return '#f85149';
      if (pct >= 25) return '#f0883e';
      if (pct >= 10) return '#d29922';
      return '#3fb950';
    }

    // Build list of lines to print
    const lines = [
      { text: '> Initialising SecurePass Attack Engine v1.0...', cls: 't-prompt', badge: ['OK', 'badge-ok'], delay: 350 },
      { text: `> Dataset loaded: ${total.toLocaleString()} passwords detected`, cls: 't-info', badge: ['OK', 'badge-ok'], delay: 380 },
      { text: `> Unique passwords: ${unique.toLocaleString()} (${uniquePct}% unique)`, cls: 't-info', badge: ['OK', 'badge-ok'], delay: 360 },
      { text: `> Average password length: ${avgLen} characters`, cls: 't-info', badge: ['OK', 'badge-ok'], delay: 340 },
      { text: '> ─────────────────────────────────────────────', cls: 't-muted', delay: 250 },
    ];

    scenarios.forEach((s, i) => {
      const pct   = parseFloat(s.probability) || 0;
      const cnt   = s.count  != null ? s.count  : '?';
      const [rl, bc] = riskLabel(pct);
      lines.push({ text: `> [${i+1}/${scenarios.length}] Running ${s.name}...`, cls: 't-prompt', badge: ['RUNNING', 'badge-running'], delay: 420 });
      lines.push({ text: `> Scanning ${total.toLocaleString()} passwords — ${s.description}`, cls: 't-muted', delay: 500 });
      lines.push({ text: `> Matched: ${cnt} passwords vulnerable`, cls: pct >= 25 ? 't-danger' : 't-warn', delay: 480 });
      lines.push({ text: `> Vulnerability: ${pct}%`, cls: pct >= 40 ? 't-danger' : pct >= 10 ? 't-warn' : 't-success', badge: [rl, bc], delay: 350 });
      lines.push({ text: '> ─────────────────────────────────────────────', cls: 't-muted', delay: 200 });
    });

    // Verdict
    const top = scenarios.length
      ? scenarios.reduce((a, b) => (parseFloat(a.probability) > parseFloat(b.probability) ? a : b))
      : null;
    if (top) {
      const topPct = parseFloat(top.probability);
      const [rl, bc] = riskLabel(topPct);
      lines.push({ text: '> SIMULATION COMPLETE', cls: 't-success', badge: ['OK', 'badge-ok'], delay: 300 });
      lines.push({ text: `> Highest exposure: ${top.name} (${topPct}%)`, cls: 't-warn', delay: 300 });
      lines.push({ text: `> Est. vulnerable: ${top.count != null ? top.count.toLocaleString() : '?'} of ${total.toLocaleString()} passwords`, cls: 't-danger', delay: 300 });
      lines.push({ text: `> VERDICT: ${rl} RISK — remediation recommended`, cls: topPct >= 40 ? 't-danger' : topPct >= 10 ? 't-warn' : 't-success', badge: [rl, bc], delay: 400 });
    }

    // Clear terminal, print lines one by one
    term.innerHTML = '';
    let cumDelay = 0;
    lines.forEach(({ text, cls, badge, delay }) => {
      cumDelay += delay;
      setTimeout(() => {
        const div = document.createElement('div');
        div.className = 't-line';
        const span = document.createElement('span');
        span.className = cls || 't-prompt';
        span.textContent = text;
        div.appendChild(span);
        if (badge) {
          const b = document.createElement('span');
          b.className = 't-badge ' + badge[1];
          b.textContent = badge[0];
          div.appendChild(b);
        }
        term.appendChild(div);
        term.scrollTop = term.scrollHeight;
      }, cumDelay);
    });

    // After all lines, show results bars
    setTimeout(() => {
      btn.disabled    = false;
      btn.textContent = '↺  RUN AGAIN';
      showSimResults(scenarios);
    }, cumDelay + 600);
  }

  function showSimResults(scenarios) {
    const el = document.getElementById('attackResults');
    if (!el) return;

    function riskLabel(pct) {
      if (pct >= 40) return ['CRITICAL', '#f85149'];
      if (pct >= 25) return ['HIGH',     '#f0883e'];
      if (pct >= 10) return ['MEDIUM',   '#d29922'];
      return               ['LOW',       '#3fb950'];
    }

    let html = '<div style="margin-bottom:10px;font-size:0.75rem;color:#484f58;font-family:\'Courier New\',monospace;letter-spacing:0.05em;">// RESULTS</div>';
    scenarios.forEach(s => {
      const pct = parseFloat(s.probability) || 0;
      const [rl, col] = riskLabel(pct);
      html += `
        <div class="sim-bar-row">
          <div class="sim-bar-label">${s.name}</div>
          <div class="sim-bar-track">
            <div class="sim-bar-fill" data-pct="${pct}" style="background:${col}"></div>
          </div>
          <div class="sim-bar-pct" style="color:${col}">${pct}%</div>
          <div style="width:72px;font-size:0.9rem;font-weight:700;color:${col};font-family:'Courier New',monospace">${rl}</div>
        </div>`;
    });

    // Verdict
    if (scenarios.length) {
      const top    = scenarios.reduce((a, b) => (parseFloat(a.probability) > parseFloat(b.probability) ? a : b));
      const topPct = parseFloat(top.probability);
      const [rl, col] = riskLabel(topPct);
      const vClass = topPct >= 40 ? 'verdict-critical' : topPct >= 25 ? 'verdict-high' : topPct >= 10 ? 'verdict-medium' : 'verdict-low';
      html += `<div class="sim-verdict ${vClass}">
        &#9654; VERDICT: ${rl} RISK &mdash; Highest exposure: ${top.name} at ${topPct}%
        &nbsp;(${top.count != null ? top.count.toLocaleString() : '?'} passwords affected)
      </div>`;
    }

    el.innerHTML  = html;
    el.style.display = 'block';

    // Animate bars after brief paint delay
    setTimeout(() => {
      el.querySelectorAll('.sim-bar-fill').forEach(bar => {
        bar.style.width = bar.dataset.pct + '%';
      });
    }, 80);
  }

  function renderAttackSim(scenarios) {
    // Legacy no-op — initAttackSim is used instead
  }

  function renderCharts(data) {
    const grid = $('chartsGrid');
    if (grid) grid.style.display = 'grid';

    // ── Shared Chart.js defaults (dark theme) ──────────────────────────
    const FONT       = "'Inter', 'Segoe UI', sans-serif";
    const C_TEXT     = '#c9d1d9';
    const C_MUTED    = '#484f58';
    const C_GRID     = 'rgba(255,255,255,0.06)';
    const C_RED      = '#f85149';
    const C_AMBER    = '#d29922';
    const C_GREEN    = '#3fb950';
    const C_CYAN     = '#00d4ff';
    const C_BLUE     = '#58a6ff';
    const C_PURPLE   = '#bc8cff';
    const C_ORANGE   = '#f0883e';
    const C_TEAL     = '#39d353';

    Chart.defaults.color          = C_TEXT;
    Chart.defaults.font.family    = FONT;
    Chart.defaults.font.size      = 13;

    const tooltipDefaults = {
      backgroundColor: '#161b22',
      borderColor:     '#30363d',
      borderWidth:     1,
      titleColor:      '#e6edf3',
      bodyColor:       C_TEXT,
      padding:         12,
      cornerRadius:    8,
      displayColors:   true,
      boxPadding:      4,
    };

    function destroyIfExists(key) {
      if (window['_ch_' + key] instanceof Chart) {
        window['_ch_' + key].destroy();
      }
    }

    // ── 1. Risk Distribution — Doughnut ───────────────────────────────
    destroyIfExists('risk');
    const rd   = data.risk_distribution || {};
    const high = rd.high || rd['High Risk']   || 0;
    const med  = rd.medium || rd['Medium Risk'] || 0;
    const low  = rd.low  || rd['Low Risk']    || 0;
    const ctxRisk = document.getElementById('chartRisk');
    if (ctxRisk && (high + med + low) > 0) {
      window._ch_risk = new Chart(ctxRisk, {
        type: 'doughnut',
        data: {
          labels: ['High Risk', 'Medium Risk', 'Low Risk'],
          datasets: [{
            data: [high, med, low],
            backgroundColor: [
              'rgba(248,81,73,0.85)',
              'rgba(210,153,34,0.85)',
              'rgba(63,185,80,0.85)',
            ],
            borderColor: [C_RED, C_AMBER, C_GREEN],
            borderWidth: 2,
            hoverOffset: 10,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          cutout: '68%',
          animation: { animateRotate: true, duration: 900 },
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 16, boxWidth: 12, borderRadius: 4, useBorderRadius: true },
            },
            tooltip: {
              ...tooltipDefaults,
              callbacks: {
                label: ctx => {
                  const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                  const pct   = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                  return `  ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
                },
              },
            },
          },
        },
      });
    }

    // ── 2. Length Distribution — Bar ──────────────────────────────────
    destroyIfExists('length');
    const stats   = data.dataset_stats || {};
    const lenDist = data.patterns && data.patterns.length_distribution
      ? data.patterns.length_distribution
      : null;

    const ctxLen = document.getElementById('chartLength');
    if (ctxLen) {
      // Build buckets from raw length_distribution or fall back to overview
      let bucketLabels, bucketData;
      if (lenDist && typeof lenDist === 'object') {
        bucketLabels = Object.keys(lenDist);
        bucketData   = Object.values(lenDist);
      } else {
        const ov = data.overview || {};
        bucketLabels = ['< 8', '8–11', '12–15', '16+'];
        const total  = ov.total_passwords || 1;
        const weak   = ov.weak_passwords  || 0;
        const med2   = ov.medium_passwords || 0;
        const strong = ov.strong_passwords || 0;
        bucketData   = [weak, Math.round(med2 * 0.6), Math.round(med2 * 0.4), strong];
      }
      const barColors = bucketData.map((_, i) => {
        const palette = [C_RED, C_AMBER, C_CYAN, C_GREEN];
        return palette[i % palette.length] + 'cc';
      });
      const barBorder = bucketData.map((_, i) => {
        const palette = [C_RED, C_AMBER, C_CYAN, C_GREEN];
        return palette[i % palette.length];
      });
      window._ch_length = new Chart(ctxLen, {
        type: 'bar',
        data: {
          labels: bucketLabels,
          datasets: [{
            label: 'Passwords',
            data:  bucketData,
            backgroundColor: barColors,
            borderColor:     barBorder,
            borderWidth: 2,
            borderRadius: 6,
            borderSkipped: false,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          animation: { duration: 800, easing: 'easeOutQuart' },
          plugins: {
            legend: { display: false },
            tooltip: {
              ...tooltipDefaults,
              callbacks: { label: ctx => `  ${ctx.parsed.y.toLocaleString()} passwords` },
            },
          },
          scales: {
            x: {
              grid: { color: C_GRID },
              ticks: { color: C_TEXT },
            },
            y: {
              grid: { color: C_GRID },
              ticks: { color: C_TEXT, precision: 0 },
              beginAtZero: true,
            },
          },
        },
      });
    }

    // ── 3. Character Coverage — Radar ─────────────────────────────────
    destroyIfExists('strength');
    const ctxStr = document.getElementById('chartStrength');
    if (ctxStr) {
      const comp = (data.patterns && data.patterns.character_composition) ? data.patterns.character_composition : {};
      const radarData = [
        comp.uppercase ? (comp.uppercase.percentage || 0) : 0,
        comp.lowercase ? (comp.lowercase.percentage || 0) : 0,
        comp.digits    ? (comp.digits.percentage    || 0) : 0,
        comp.special   ? (comp.special.percentage   || 0) : 0,
        data.overview  ? Math.min(100, (data.overview.average_length || 0) * 5) : 0,
      ];
      window._ch_strength = new Chart(ctxStr, {
        type: 'radar',
        data: {
          labels: ['Uppercase', 'Lowercase', 'Digits', 'Special Chars', 'Length Score'],
          datasets: [{
            label: 'Coverage %',
            data:  radarData,
            backgroundColor: 'rgba(0,212,255,0.12)',
            borderColor:     C_CYAN,
            borderWidth:     2,
            pointBackgroundColor: C_CYAN,
            pointBorderColor:    '#0d1117',
            pointHoverBackgroundColor: '#fff',
            pointRadius: 5,
            pointHoverRadius: 7,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          animation: { duration: 900 },
          plugins: {
            legend: { display: false },
            tooltip: {
              ...tooltipDefaults,
              callbacks: { label: ctx => `  ${ctx.label}: ${ctx.parsed.r.toFixed(1)}%` },
            },
          },
          scales: {
            r: {
              min: 0, max: 100,
              grid:      { color: C_GRID },
              angleLines: { color: C_GRID },
              pointLabels: { color: C_TEXT, font: { size: 12 } },
              ticks: {
                display: true, stepSize: 25,
                color: C_MUTED,
                backdropColor: 'transparent',
              },
            },
          },
        },
      });
    }

    // ── 4. Pattern Breakdown — Horizontal Bar ─────────────────────────
    destroyIfExists('pattern');
    const ctxPat = document.getElementById('chartPattern');
    if (ctxPat) {
      const p = (data.patterns && data.patterns.patterns) ? data.patterns.patterns : (data.patterns || {});
      const patternMap = [
        { label: 'Dictionary Words',     key: 'dictionary_based',      color: C_RED    },
        { label: 'Name Based',           key: 'name_based',            color: C_ORANGE },
        { label: 'Numeric Suffix',       key: 'numeric_suffix',        color: C_AMBER  },
        { label: 'Keyboard Walk',        key: 'keyboard_walk',         color: C_CYAN   },
        { label: 'Capitalisation Misuse',key: 'capitalization_misuse', color: C_BLUE   },
        { label: 'Leet Speak',           key: 'leetspeak',             color: C_PURPLE },
        { label: 'Sequential Numbers',   key: 'sequential_numbers',    color: C_TEAL   },
      ];
      const filtered = patternMap.filter(pm => {
        const v = p[pm.key];
        return v && (v.percentage > 0 || v.count > 0);
      });
      const patLabels = filtered.map(pm => pm.label);
      const patData   = filtered.map(pm => {
        const v = p[pm.key];
        return v ? (v.percentage || 0) : 0;
      });
      const patColors = filtered.map(pm => pm.color + 'cc');
      const patBorder = filtered.map(pm => pm.color);

      window._ch_pattern = new Chart(ctxPat, {
        type: 'bar',
        data: {
          labels: patLabels.length ? patLabels : ['No patterns detected'],
          datasets: [{
            label: '% of passwords',
            data:  patData.length  ? patData  : [0],
            backgroundColor: patColors.length ? patColors : ['rgba(72,79,88,0.5)'],
            borderColor:     patBorder.length ? patBorder : [C_MUTED],
            borderWidth: 2,
            borderRadius: 6,
            borderSkipped: false,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          indexAxis: 'y',
          animation: { duration: 800, easing: 'easeOutQuart' },
          plugins: {
            legend: { display: false },
            tooltip: {
              ...tooltipDefaults,
              callbacks: { label: ctx => `  ${ctx.parsed.x.toFixed(1)}% of passwords` },
            },
          },
          scales: {
            x: {
              min: 0, max: 100,
              grid:  { color: C_GRID },
              ticks: { color: C_TEXT, callback: v => v + '%' },
            },
            y: {
              grid:  { display: false },
              ticks: { color: C_TEXT, font: { size: 12 } },
            },
          },
        },
      });
    }
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