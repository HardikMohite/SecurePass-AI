/**
 * register.js — SecurePass AI Register Page
 * Wired to /api/auth/register
 *
 * FIXES:
 * - Guard against window.Auth not being defined
 * - Clear error banner when the user edits any field
 * - Live confirm-password mismatch indicator
 * - Re-enable button and reset label on all error paths
 */
document.addEventListener('DOMContentLoaded', () => {
    const form      = document.getElementById('registerForm');
    const btnText   = document.getElementById('regBtnText');
    const errMsg    = document.getElementById('errMsg');
    const errText   = document.getElementById('errText');
    const pwInput   = document.getElementById('password');
    const confInput = document.getElementById('confirm');
    const pwEye     = document.getElementById('pwEye');
    const confEye   = document.getElementById('confEye');

    // ── Sanity check: Auth must be loaded ──────────────────────────────
    if (typeof window.Auth === 'undefined') {
        console.error('[register.js] window.Auth is not defined. Make sure auth.js is loaded BEFORE register.js.');
    }

    // ── Eye toggles ────────────────────────────────────────────────────
    [{ btn: pwEye, inp: pwInput }, { btn: confEye, inp: confInput }].forEach(({ btn, inp }) => {
        if (btn && inp) {
            btn.addEventListener('click', () => {
                const isPw = inp.type === 'password';
                inp.type = isPw ? 'text' : 'password';
                const icon = btn.querySelector('i') || btn.querySelector('svg');
                if (icon) {
                    icon.setAttribute('data-lucide', isPw ? 'eye-off' : 'eye');
                    if (window.lucide) lucide.createIcons();
                }
            });
        }
    });

    // ── Clear error when user edits any field ──────────────────────────
    ['email', 'password', 'confirm', 'username'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => {
            if (errMsg) errMsg.classList.remove('visible');
        });
    });

    // ── Live confirm-password mismatch indicator ───────────────────────
    if (confInput && pwInput) {
        confInput.addEventListener('input', () => {
            if (confInput.value && confInput.value !== pwInput.value) {
                confInput.style.borderColor = '#ff5f57';
            } else {
                confInput.style.borderColor = '';
            }
        });
    }

    // ── Password strength indicator ────────────────────────────────────
    if (pwInput) {
        pwInput.addEventListener('input', e => {
            const val   = e.target.value;
            const label = document.getElementById('strengthLabel');
            const segs  = [0, 1, 2, 3].map(i => document.getElementById('seg' + i));
            const reqs  = [
                { id: 'req-len', met: val.length >= 8 },
                { id: 'req-12',  met: val.length >= 12 },
                { id: 'req-up',  met: /[A-Z]/.test(val) },
                { id: 'req-low', met: /[a-z]/.test(val) },
                { id: 'req-num', met: /[0-9]/.test(val) },
                { id: 'req-spc', met: /[^A-Za-z0-9]/.test(val) },
            ];

            reqs.forEach(req => {
                const el = document.getElementById(req.id);
                if (!el) return;
                const icon = el.querySelector('i') || el.querySelector('svg');
                el.classList.toggle('met', req.met);
                if (icon) icon.setAttribute('data-lucide', req.met ? 'check-circle' : 'circle');
            });
            if (window.lucide) lucide.createIcons();

            segs.forEach(s => { if (s) s.className = 'strength-segment'; });
            const metCount = reqs.filter(r => r.met).length;

            if (val.length > 0) {
                if (metCount <= 2) {
                    segs[0] && segs[0].classList.add('active', 'danger');
                    if (label) label.textContent = 'Token Strength: Weak';
                } else if (metCount <= 4) {
                    [0, 1].forEach(i => segs[i] && segs[i].classList.add('active', 'warning'));
                    if (label) label.textContent = 'Token Strength: Fair';
                } else if (metCount < 6) {
                    [0, 1, 2].forEach(i => segs[i] && segs[i].classList.add('active', 'success'));
                    if (label) label.textContent = 'Token Strength: Good';
                } else {
                    segs.forEach(s => s && s.classList.add('active', 'success'));
                    if (label) label.textContent = 'Token Strength: Secure';
                }
            } else {
                if (label) label.textContent = 'Token Strength: None';
            }

            // Also re-check confirm mismatch after password changes
            if (confInput && confInput.value) {
                confInput.style.borderColor = confInput.value !== val ? '#ff5f57' : '';
            }
        });
    }

    // ── Form submit ────────────────────────────────────────────────────
    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();

            const email    = document.getElementById('email')?.value?.trim();
            const password = pwInput?.value;
            const confirm  = confInput?.value;
            const username = document.getElementById('username')?.value?.trim() || '';

            if (!email) { showErr('Email address is required.'); return; }
            if (!password) { showErr('Password is required.'); return; }
            if (password !== confirm) { showErr('Passwords do not match.'); return; }

            const submitBtn = form.querySelector('[type="submit"]');
            if (btnText)   btnText.textContent = 'Commissioning…';
            if (submitBtn) submitBtn.disabled = true;
            if (errMsg)    errMsg.classList.remove('visible');

            try {
                const result = await Auth.register(username, email, password);
                if (result.ok) {
                    if (btnText) btnText.textContent = 'Account Created!';
                    setTimeout(() => { window.location.href = '/'; }, 600);
                } else {
                    showErr(result.error || 'Registration failed. Please try again.');
                    if (btnText)   btnText.textContent = 'Create Account';
                    if (submitBtn) submitBtn.disabled = false;
                }
            } catch (err) {
                console.error('[register.js] Unexpected error:', err);
                showErr('An error occurred. Please try again.');
                if (btnText)   btnText.textContent = 'Create Account';
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }

    function showErr(msg) {
        if (!errMsg) return;
        if (errText) errText.textContent = msg;
        else errMsg.textContent = msg;
        errMsg.classList.add('visible');
    }
});