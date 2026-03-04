/**
 * theme.js — Dark / Light theme toggle
 * Include on every page BEFORE other scripts.
 * Reads/writes localStorage key 'sp-theme'.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'sp-theme';
  const DEFAULT     = 'dark';

  /* Apply theme immediately (before paint) */
  const saved = localStorage.getItem(STORAGE_KEY) || DEFAULT;
  document.documentElement.setAttribute('data-theme', saved);

  /* Update all toggle elements on the page */
  function syncToggles(theme) {
    /* Nav toggle thumb (main dashboard) */
    const thumb = document.getElementById('toggleThumb');
    if (thumb) thumb.textContent = theme === 'dark' ? '☀️' : '🌙';

    /* Fixed button (auth pages) */
    const btn = document.getElementById('themeToggle');
    if (btn && btn.tagName === 'BUTTON' && !btn.classList.contains('theme-toggle')) {
      btn.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
    syncToggles(theme);
  }

  function toggle() {
    const current = document.documentElement.getAttribute('data-theme') || DEFAULT;
    applyTheme(current === 'dark' ? 'light' : 'dark');
  }

  /* Expose globally */
  window.ThemeManager = { toggle, apply: applyTheme, current: () => document.documentElement.getAttribute('data-theme') };

  /* Wire up elements once DOM is ready */
  document.addEventListener('DOMContentLoaded', function () {
    syncToggles(document.documentElement.getAttribute('data-theme'));

    /* Nav pill toggle (dashboard) */
    const navToggle = document.getElementById('themeToggle');
    if (navToggle) navToggle.addEventListener('click', toggle);

    /* Auth page button (same id, different element) */
    const authBtn = document.getElementById('themeToggle');
    if (authBtn && authBtn !== navToggle) authBtn.addEventListener('click', toggle);
  });
})();