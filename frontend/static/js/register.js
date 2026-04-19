/**
 * register.js — SecurePass AI Register Page
 * Wired to /api/auth/register
 */
document.addEventListener('DOMContentLoaded', () => {
    const form      = document.getElementById('registerForm');
    const btnText   = document.getElementById('regBtnText');
    const errMsg    = document.getElementById('errMsg');
    const pwInput   = document.getElementById('password');
    const confInput = document.getElementById('confirm');
    const pwEye     = document.getElementById('pwEye');
    const confEye   = document.getElementById('confEye');

    // Eye toggles
    [{ btn: pwEye, inp: pwInput }, { btn: confEye, inp: confInput }].forEach(({ btn, inp }) => {
        if (btn && inp) {
            btn.addEventListener('click', () => {
                const isPw = inp.type === 'password';
                inp.type = isPw ? 'text' : 'password';
                const icon = btn.querySelector('i') || btn.querySelector('svg');
                if (icon) { icon.setAttribute('data-lucide', isPw ? 'eye-off' : 'eye'); if (window.lucide) lucide.createIcons(); }
            });
        }
    });

    // Password strength indicator
    if (pwInput) {
        pwInput.addEventListener('input', e => {
            const val = e.target.value;
            const label = document.getElementById('strengthLabel');
            const segs  = [0,1,2,3].map(i => document.getElementById('seg' + i));
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
                    segs[0] && segs[0].classList.add('active','danger');
                    if (label) label.textContent = 'Token Strength: Weak';
                } else if (metCount <= 4) {
                    [0,1].forEach(i => segs[i] && segs[i].classList.add('active','warning'));
                    if (label) label.textContent = 'Token Strength: Fair';
                } else if (metCount < 6) {
                    [0,1,2].forEach(i => segs[i] && segs[i].classList.add('active','success'));
                    if (label) label.textContent = 'Token Strength: Good';
                } else {
                    segs.forEach(s => s && s.classList.add('active','success'));
                    if (label) label.textContent = 'Token Strength: Secure';
                }
            } else {
                if (label) label.textContent = 'Token Strength: None';
            }
        });
    }

    // Form submit
    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            const email    = document.getElementById('email')?.value?.trim();
            const password = pwInput?.value;
            const confirm  = confInput?.value;
            const username = document.getElementById('username')?.value?.trim() || '';

            if (!email || !password) { showErr('Email and password are required.'); return; }
            if (password !== confirm) { showErr('Passwords do not match.'); return; }

            if (btnText) btnText.textContent = 'Commissioning...';
            const submitBtn = form.querySelector('[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;
            if (errMsg) errMsg.style.display = 'none';

            try {
                const result = await Auth.register(username, email, password);
                if (result.ok) {
                    if (btnText) btnText.textContent = 'Account Created!';
                    setTimeout(() => { window.location.href = '/'; }, 600);
                } else {
                    showErr(result.error || 'Registration failed. Please try again.');
                    if (btnText) btnText.textContent = 'Create Account';
                    if (submitBtn) submitBtn.disabled = false;
                }
            } catch (err) {
                showErr('An error occurred. Please try again.');
                if (btnText) btnText.textContent = 'Create Account';
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