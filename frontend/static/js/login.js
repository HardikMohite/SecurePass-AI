/**
 * login.js — SecurePass AI Login Page
 * Wired to /api/auth/login
 *
 * FIXES:
 * - Reads the #remember checkbox and passes it to Auth.login()
 * - Clears error banner when the user starts typing again
 * - Guards against Auth not being defined (defensive fallback)
 */
document.addEventListener('DOMContentLoaded', () => {
    const form        = document.getElementById('loginForm');
    const btnText     = document.getElementById('loginBtnText');
    const errMsg      = document.getElementById('errMsg');
    const pwEye       = document.getElementById('pwEye');
    const pwInput     = document.getElementById('password');
    const emailInput  = document.getElementById('email');
    const rememberChk = document.getElementById('remember');

    // ── Sanity check: Auth must be loaded ──────────────────────────────
    if (typeof window.Auth === 'undefined') {
        console.error('[login.js] window.Auth is not defined. Make sure auth.js is loaded BEFORE login.js.');
    }

    // ── Password eye toggle ────────────────────────────────────────────
    if (pwEye && pwInput) {
        pwEye.addEventListener('click', () => {
            const isPw = pwInput.type === 'password';
            pwInput.type = isPw ? 'text' : 'password';
            const icon = pwEye.querySelector('i') || pwEye.querySelector('svg');
            if (icon) {
                icon.setAttribute('data-lucide', isPw ? 'eye-off' : 'eye');
                if (window.lucide) lucide.createIcons();
            }
        });
    }

    // ── Clear error as soon as user edits a field ──────────────────────
    [emailInput, pwInput].forEach(el => {
        if (el) el.addEventListener('input', () => {
            if (errMsg) errMsg.style.display = 'none';
        });
    });

    // ── Form submit ────────────────────────────────────────────────────
    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();

            const email    = emailInput?.value?.trim();
            const password = pwInput?.value;
            // FIX: read the remember checkbox value
            const remember = rememberChk?.checked || false;

            if (!email || !password) {
                showErr('Email and password are required.');
                return;
            }

            const submitBtn = form.querySelector('[type="submit"]');
            if (btnText)   btnText.textContent = 'Authenticating…';
            if (submitBtn) submitBtn.disabled = true;
            if (errMsg)    errMsg.style.display = 'none';

            try {
                // FIX: pass remember flag to Auth.login
                const result = await Auth.login(email, password, remember);
                if (result.ok) {
                    if (btnText) btnText.textContent = 'Success!';
                    setTimeout(() => { window.location.href = '/'; }, 500);
                } else {
                    showErr(result.error || 'Login failed. Please try again.');
                    if (btnText)   btnText.textContent = 'Sign In';
                    if (submitBtn) submitBtn.disabled = false;
                }
            } catch (err) {
                console.error('[login.js] Unexpected error:', err);
                showErr('An error occurred. Please try again.');
                if (btnText)   btnText.textContent = 'Sign In';
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }

    function showErr(msg) {
        if (!errMsg) return;
        errMsg.textContent = msg;
        errMsg.style.display = 'block';
    }
});