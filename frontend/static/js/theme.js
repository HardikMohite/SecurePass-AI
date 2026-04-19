// Theme Manager for SecurePass AI
window.ThemeManager = {
    theme: localStorage.getItem('sp-theme') || 'dark',

    init() {
        this.applyTheme();
        const toggle = document.getElementById('themeToggle');
        if (toggle) toggle.onclick = () => this.toggle();
    },

    toggle() {
        this.theme = this.theme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('sp-theme', this.theme);
        this.applyTheme();
    },

    applyTheme() {
        document.documentElement.setAttribute('data-theme', this.theme);
        document.body.className = this.theme + '-mode';
        const moon = document.getElementById('moonIcon');
        const sun  = document.getElementById('sunIcon');
        if (this.theme === 'dark') {
            if (moon) moon.style.display = 'block';
            if (sun)  sun.style.display  = 'none';
        } else {
            if (moon) moon.style.display = 'none';
            if (sun)  sun.style.display  = 'block';
        }
    }
};

window.addEventListener('DOMContentLoaded', () => {
    window.ThemeManager.init();
});