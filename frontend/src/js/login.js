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
    const errText     = document.getElementById('errText');
    const pwEye       = document.getElementById('pwEye');
    const pwInput     = document.getElementById('password');
    const emailInput  = document.getElementById('email');
    const rememberChk = document.getElementById('remember');
    const successMsg  = document.getElementById('successMsg');
    const successText = document.getElementById('successText');

    // ── Check for reset=success or registered=1 in URL ─────────────────
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('reset') === 'success') {
        if (successMsg && successText) {
            successText.textContent = 'Password updated successfully. You can now sign in.';
            successMsg.classList.add('visible');
        }
    } else if (urlParams.get('registered') === '1') {
        if (successMsg && successText) {
            successText.textContent = 'Account created! Please sign in with your credentials.';
            successMsg.classList.add('visible');
        }
    }

    // ── Sanity check: Auth must be loaded ──────────────────────────────
    if (typeof window.Auth === 'undefined') {
        console.error('[login.js] window.Auth is not defined. Make sure auth.js is loaded BEFORE login.js.');
    } else if (typeof window.Auth.checkAuth === 'function') {
        // If already logged in, seamlessly forward to dashboard or redirect target
        window.Auth.checkAuth().then(user => {
            if (user) {
                const target = urlParams.get('redirect') || '/';
                window.location.replace(target);
            }
        }).catch(() => {});
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
            if (errMsg) errMsg.classList.remove('visible');
        });
    });

    // ── Form submit ────────────────────────────────────────────────────
    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();

            const identifier = emailInput?.value?.trim();
            const password   = pwInput?.value;
            // 30 days if checked, 15 minutes if unchecked
            const remember   = rememberChk?.checked || false;

            if (!identifier || !password) {
                showErr('Email or username and password are required.');
                return;
            }

            const submitBtn = form.querySelector('[type="submit"]');
            if (btnText)   btnText.textContent = 'Authenticating…';
            if (submitBtn) submitBtn.disabled = true;
            if (errMsg)    errMsg.classList.remove('visible');

            try {
                const result = await Auth.login(identifier, password, remember);
                if (result.ok) {
                    if (btnText) btnText.textContent = 'Success!';
                    const target = urlParams.get('redirect') || '/';
                    setTimeout(() => { window.location.href = target; }, 400);
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
        if (errText) errText.textContent = msg;
        else errMsg.textContent = msg;
        errMsg.classList.add('visible');
    }
});