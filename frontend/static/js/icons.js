/**
 * icons.js — Lucide SVG icon helpers
 * All icons rendered as inline SVG strings.
 * Usage: Icons.shield(20)  →  '<svg ...>...</svg>'
 */
window.Icons = (function () {
  'use strict';

  function svg(size, paths, extra) {
    extra = extra || '';
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"' + extra + '>' + paths + '</svg>';
  }

  return {
    /* ── Branding / nav ─────────────────────────────── */
    shieldHalf: function (s) {
      s = s || 20;
      // Custom half-filled shield: right half filled, left half outline
      return '<svg xmlns="http://www.w3.org/2000/svg" width="' + s + '" height="' + s + '" viewBox="0 0 24 24">' +
        '<defs><clipPath id="lhalf"><rect x="0" y="0" width="12" height="24"/></clipPath><clipPath id="rhalf"><rect x="12" y="0" width="12" height="24"/></clipPath></defs>' +
        '<path d="M12 22s-8-4.5-8-11.8V5l8-3 8 3v5.2C20 17.5 12 22 12 22z" fill="currentColor" clip-path="url(#rhalf)" opacity="0.85"/>' +
        '<path d="M12 22s-8-4.5-8-11.8V5l8-3 8 3v5.2C20 17.5 12 22 12 22z" fill="none" stroke="currentColor" stroke-width="1.8" clip-path="url(#lhalf)"/>' +
        '<path d="M12 22s-8-4.5-8-11.8V5l8-3 8 3v5.2C20 17.5 12 22 12 22z" fill="none" stroke="currentColor" stroke-width="1.8"/>' +
        '</svg>';
    },
    shield: function (s) {
      s = s || 20;
      return svg(s, '<path d="M12 22s-8-4.5-8-11.8V5l8-3 8 3v5.2C20 17.5 12 22 12 22z"/>');
    },
    sun: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>');
    },
    moon: function (s) {
      s = s || 16;
      return svg(s, '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>');
    },
    /* ── Nav / actions ──────────────────────────────── */
    logOut: function (s) {
      s = s || 16;
      return svg(s, '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>');
    },
    user: function (s) {
      s = s || 16;
      return svg(s, '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>');
    },
    /* ── Upload / file ──────────────────────────────── */
    upload: function (s) {
      s = s || 22;
      return svg(s, '<polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>');
    },
    file: function (s) {
      s = s || 16;
      return svg(s, '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>');
    },
    fileText: function (s) {
      s = s || 16;
      return svg(s, '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>');
    },
    folderOpen: function (s) {
      s = s || 16;
      return svg(s, '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>');
    },
    x: function (s) {
      s = s || 14;
      return svg(s, '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>');
    },
    /* ── Analysis ───────────────────────────────────── */
    zap: function (s) {
      s = s || 16;
      return svg(s, '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>');
    },
    scan: function (s) {
      s = s || 16;
      return svg(s, '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="7" y1="12" x2="17" y2="12"/>');
    },
    search: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>');
    },
    activity: function (s) {
      s = s || 16;
      return svg(s, '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>');
    },
    barChart: function (s) {
      s = s || 16;
      return svg(s, '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>');
    },
    pieChart: function (s) {
      s = s || 16;
      return svg(s, '<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>');
    },
    /* ── Risk / security ────────────────────────────── */
    alertTriangle: function (s) {
      s = s || 16;
      return svg(s, '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>');
    },
    alertCircle: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>');
    },
    checkCircle: function (s) {
      s = s || 16;
      return svg(s, '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>');
    },
    check: function (s) {
      s = s || 14;
      return svg(s, '<polyline points="20 6 9 17 4 12"/>');
    },
    xCircle: function (s) {
      s = s || 14;
      return svg(s, '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>');
    },
    lock: function (s) {
      s = s || 16;
      return svg(s, '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>');
    },
    key: function (s) {
      s = s || 16;
      return svg(s, '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>');
    },
    eye: function (s) {
      s = s || 16;
      return svg(s, '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>');
    },
    eyeOff: function (s) {
      s = s || 16;
      return svg(s, '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>');
    },
    /* ── Info / compliance ──────────────────────────── */
    info: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>');
    },
    clipboardCheck: function (s) {
      s = s || 16;
      return svg(s, '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="m9 14 2 2 4-4"/>');
    },
    robot: function (s) {
      s = s || 16;
      return svg(s, '<rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/><path d="M8 11v-1"/><path d="M16 11v-1"/>');
    },
    /* ── Download / report ──────────────────────────── */
    download: function (s) {
      s = s || 16;
      return svg(s, '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>');
    },
    fileDown: function (s) {
      s = s || 16;
      return svg(s, '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="12 18 12 12"/><polyline points="9 15 12 18 15 15"/>');
    },
    refreshCw: function (s) {
      s = s || 16;
      return svg(s, '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>');
    },
    plusCircle: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>');
    },
    /* ── Stats ──────────────────────────────────────── */
    database: function (s) {
      s = s || 16;
      return svg(s, '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>');
    },
    hash: function (s) {
      s = s || 16;
      return svg(s, '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>');
    },
    ruler: function (s) {
      s = s || 16;
      return svg(s, '<path d="M21.3 8.7 8.7 21.3c-1 1-2.5 1-3.4 0l-2.6-2.6c-1-1-1-2.5 0-3.4L15.3 2.7c1-1 2.5-1 3.4 0l2.6 2.6c1 1 1 2.5 0 3.4z"/><line x1="7.5" y1="10.5" x2="10" y2="13"/><line x1="11" y1="7" x2="13.5" y2="9.5"/>');
    },
    target: function (s) {
      s = s || 16;
      return svg(s, '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>');
    },
    trendingUp: function (s) {
      s = s || 16;
      return svg(s, '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>');
    },
    /* ── Auth ───────────────────────────────────────── */
    mail: function (s) {
      s = s || 16;
      return svg(s, '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>');
    },
    userPlus: function (s) {
      s = s || 16;
      return svg(s, '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/>');
    },
    arrowRight: function (s) {
      s = s || 14;
      return svg(s, '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>');
    },
    logIn: function (s) {
      s = s || 16;
      return svg(s, '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>');
    },
    /* ── Misc ───────────────────────────────────────── */
    lightbulb: function (s) {
      s = s || 16;
      return svg(s, '<line x1="9" y1="18" x2="15" y2="18"/><line x1="10" y1="22" x2="14" y2="22"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>');
    },
    cpu: function (s) {
      s = s || 16;
      return svg(s, '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>');
    },
    terminal: function (s) {
      s = s || 16;
      return svg(s, '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>');
    },
    wifi: function (s) {
      s = s || 16;
      return svg(s, '<path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>');
    },
    gitBranch: function (s) {
      s = s || 16;
      return svg(s, '<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>');
    },
    list: function (s) {
      s = s || 16;
      return svg(s, '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>');
    },
    layers: function (s) {
      s = s || 16;
      return svg(s, '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>');
    },
  };
})();
