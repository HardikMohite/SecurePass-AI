// Theme Manager for SecurePass AI — Pure Executive White UI
window.ThemeManager = {
    theme: 'light',

    init() {
        this.applyTheme();
        // Clear any old stored dark mode preference
        if (localStorage.getItem('sp-theme') === 'dark') {
            localStorage.setItem('sp-theme', 'light');
        }
    },

    applyTheme() {
        document.documentElement.setAttribute('data-theme', 'light');
        document.body.className = 'light-mode';
    }
};

window.addEventListener('DOMContentLoaded', () => {
    window.ThemeManager.init();
});