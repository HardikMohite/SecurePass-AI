/**
 * login.js — Login page logic
 * Requires: auth.js, theme.js
 */
(function () {
  'use strict';

  let submitting = false;

  /* ── Init ──────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    // Focus email on load
    const email = document.getElementById('email');
    if (email) email.focus();

    // Real-time email validation
    if (email) {
      email.addEventListener('blur', function () {
        if (!email.value) return;
        const v = Auth.validateEmail(email.value.trim());
        email.classList.toggle('invalid', !v.valid);
        email.classList.toggle('valid',   v.valid);
      });
      email.addEventListener('input', function () {
        email.classList.remove('invalid', 'valid');
        Auth.hideError();
      });
    }

    // Password clears error on input
    const pw = document.getElementById('password');
    if (pw) pw.addEventListener('input', Auth.hideError);

    // Submit button
    const btn = document.getElementById('loginSubmit');
    if (btn) btn.addEventListener('click', handleLogin);

    // Enter key submits
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !submitting) handleLogin();
    });

    // Password toggle
    const eyeBtn = document.getElementById('pwEye');
    if (eyeBtn) {
      eyeBtn.addEventListener('click', function () {
        Auth.togglePasswordVisibility('password', eyeBtn);
      });
    }
  });

  /* ── Handle login ──────────────────────────────────────── */
  async function handleLogin() {
    if (submitting) return;
    Auth.hideError();

    const email    = (document.getElementById('email')?.value || '').trim();
    const password = document.getElementById('password')?.value || '';

    // Client-side validation
    const emailV = Auth.validateEmail(email);
    if (!emailV.valid) { Auth.showError(emailV.error); return; }
    if (!password)     { Auth.showError('Password is required'); return; }

    submitting = true;
    Auth.setLoading('loginSubmit', 'loginBtnText', true, 'Sign In');

    try {
      const result = await Auth.apiRequest('/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (result.ok) {
        if (result.data.user) Auth.storeUser(result.data.user);
        Auth.showSuccess('✅ Signed in! Redirecting…');
        setTimeout(function () { window.location.href = '/'; }, 800);
      } else {
        handleLoginError(result.data, result.status);
      }
    } catch (err) {
      Auth.showError(err.message || 'Login failed. Please try again.');
    } finally {
      submitting = false;
      Auth.setLoading('loginSubmit', 'loginBtnText', false, 'Sign In');
    }
  }

  function handleLoginError(data, status) {
    const msg = data.error || 'Login failed.';
    switch (status) {
      case 401:
        Auth.showError('Invalid email or password.');
        const pw = document.getElementById('password');
        if (pw) { pw.value = ''; pw.focus(); }
        break;
      case 403:
        Auth.showError('Your account has been disabled.');
        break;
      case 429:
        Auth.showError('Too many attempts. Please wait before trying again.');
        break;
      default:
        Auth.showError(msg);
    }
  }

})();