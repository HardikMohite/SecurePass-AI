/**
 * login.js — SecurePass AI Login Page
 * Wired to /api/auth/login
 */
document.addEventListener('DOMContentLoaded', () => {
    const form     = document.getElementById('loginForm');
    const btnText  = document.getElementById('loginBtnText');
    const errMsg   = document.getElementById('errMsg');
    const pwEye    = document.getElementById('pwEye');
    const pwInput  = document.getElementById('password');

    if (pwEye && pwInput) {
        pwEye.addEventListener('click', () => {
            const isPw = pwInput.type === 'password';
            pwInput.type = isPw ? 'text' : 'password';
            const icon = pwEye.querySelector('i') || pwEye.querySelector('svg');
            if (icon) { icon.setAttribute('data-lucide', isPw ? 'eye-off' : 'eye'); if (window.lucide) lucide.createIcons(); }
        });
    }

    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            const email    = document.getElementById('email')?.value?.trim();
            const password = pwInput?.value;
            if (!email || !password) { showErr('Email and password are required.'); return; }

            if (btnText) btnText.textContent = 'Authenticating...';
            const submitBtn = form.querySelector('[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;
            if (errMsg) errMsg.style.display = 'none';

            try {
                const result = await Auth.login(email, password);
                if (result.ok) {
                    if (btnText) btnText.textContent = 'Success!';
                    setTimeout(() => { window.location.href = '/'; }, 500);
                } else {
                    showErr(result.error || 'Login failed. Please try again.');
                    if (btnText) btnText.textContent = 'Sign In';
                    if (submitBtn) submitBtn.disabled = false;
                }
            } catch (err) {
                showErr('An error occurred. Please try again.');
                if (btnText) btnText.textContent = 'Sign In';
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