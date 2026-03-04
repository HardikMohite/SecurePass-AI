/**
 * register.js — Registration page logic
 * Requires: auth.js, theme.js
 */
(function () {
  'use strict';

  let submitting = false;

  /* ── Init ──────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    const emailInp   = document.getElementById('email');
    const pwInp      = document.getElementById('password');
    const confirmInp = document.getElementById('confirm');
    const submitBtn  = document.getElementById('regSubmit');
    const eyePw      = document.getElementById('pwEye');
    const eyeConf    = document.getElementById('confEye');

    if (emailInp) emailInp.focus();

    /* Email validation */
    if (emailInp) {
      emailInp.addEventListener('blur', function () {
        if (!emailInp.value) return;
        const v = Auth.validateEmail(emailInp.value.trim());
        emailInp.classList.toggle('valid',   v.valid);
        emailInp.classList.toggle('invalid', !v.valid);
      });
      emailInp.addEventListener('input', function () {
        emailInp.classList.remove('valid', 'invalid');
        Auth.hideError();
      });
    }

    /* Password strength */
    const debouncedPw = Auth.debounce(updateStrength, 120);
    if (pwInp) {
      pwInp.addEventListener('input', function () {
        debouncedPw(pwInp.value);
        Auth.hideError();
        if (confirmInp && confirmInp.value) validateConfirmField();
      });
    }

    /* Confirm match */
    if (confirmInp) {
      confirmInp.addEventListener('input', validateConfirmField);
    }

    /* Password toggles */
    if (eyePw)   eyePw.addEventListener('click',   function () { Auth.togglePasswordVisibility('password', eyePw); });
    if (eyeConf) eyeConf.addEventListener('click',  function () { Auth.togglePasswordVisibility('confirm',  eyeConf); });

    /* Submit */
    if (submitBtn) submitBtn.addEventListener('click', handleRegister);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !submitting) handleRegister();
    });
  });

  /* ── Strength meter ────────────────────────────────────── */
  function updateStrength(pw) {
    const colors  = ['var(--border)', 'var(--red)', 'var(--red)', 'var(--amber)', 'var(--green)', 'var(--green)', 'var(--green)'];
    const labels  = ['', 'Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
    const v       = Auth.validatePassword(pw);
    const reqs    = v.requirements || {};

    const checks = [
      reqs.length, reqs.uppercase, reqs.lowercase, reqs.number, reqs.special,
      pw.length >= 12, pw.length >= 16,
    ];
    const score = checks.filter(Boolean).length;

    // Segments
    for (let i = 0; i < 4; i++) {
      const seg = document.getElementById('seg' + i);
      if (seg) seg.style.background = i < score ? colors[score] : 'var(--border)';
    }

    // Label
    const lbl = document.getElementById('strengthLabel');
    if (lbl) {
      lbl.textContent = pw ? labels[score] : '';
      lbl.style.color = colors[score];
    }

    // Requirement indicators
    const reqMap = {
      'req-len': reqs.length,
      'req-up':  reqs.uppercase,
      'req-low': reqs.lowercase,
      'req-num': reqs.number,
      'req-spc': reqs.special,
      'req-12':  pw.length >= 12,
    };
    Object.entries(reqMap).forEach(function ([id, met]) {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.toggle('met', !!met);
      const icon = el.querySelector('.req-icon');
      if (icon) icon.textContent = met ? '✓' : '○';
    });
  }

  /* ── Confirm match ─────────────────────────────────────── */
  function validateConfirmField() {
    const pw      = document.getElementById('password')?.value || '';
    const confirm = document.getElementById('confirm');
    if (!confirm || !confirm.value) return;
    const match = pw === confirm.value;
    confirm.classList.toggle('valid',   match);
    confirm.classList.toggle('invalid', !match);
  }

  /* ── Handle register ───────────────────────────────────── */
  async function handleRegister() {
    if (submitting) return;
    Auth.hideError();

    const email    = (document.getElementById('email')?.value || '').trim();
    const password = document.getElementById('password')?.value || '';
    const confirm  = document.getElementById('confirm')?.value  || '';

    // Validate
    const emailV = Auth.validateEmail(email);
    if (!emailV.valid) { Auth.showError(emailV.error); return; }

    const pwV = Auth.validatePassword(password);
    if (!pwV.valid) { Auth.showError(pwV.error); return; }

    const matchV = Auth.validatePasswordMatch(password, confirm);
    if (!matchV.valid) { Auth.showError(matchV.error); return; }

    submitting = true;
    Auth.setLoading('regSubmit', 'regBtnText', true, 'Create Account');

    try {
      const result = await Auth.apiRequest('/register', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (result.ok) {
        if (result.data.user) Auth.storeUser(result.data.user);
        Auth.showSuccess('✅ Account created! Redirecting…');
        setTimeout(function () { window.location.href = '/'; }, 1000);
      } else {
        handleRegisterError(result.data, result.status);
      }
    } catch (err) {
      Auth.showError(err.message || 'Registration failed. Please try again.');
    } finally {
      submitting = false;
      Auth.setLoading('regSubmit', 'regBtnText', false, 'Create Account');
    }
  }

  function handleRegisterError(data, status) {
    const msg = data.error || 'Registration failed.';
    switch (status) {
      case 409: Auth.showError('This email is already registered. Try signing in.'); break;
      case 429: Auth.showError('Too many attempts. Please wait before trying again.'); break;
      case 400:
        if (msg.toLowerCase().includes('email'))    Auth.showError(msg);
        else if (msg.toLowerCase().includes('pass')) Auth.showError(msg);
        else Auth.showError(msg);
        break;
      default: Auth.showError(msg);
    }
  }

})();