import { defineConfig } from 'vite';
import { resolve } from 'path';

const __dirname = import.meta.dirname;

// Multi-page build: each HTML page is wired up as its own Rollup entry
// point. Pages use relative asset paths (./src/...) and reference the
// backend only via relative /api/ and /static/ URLs, so the built output
// in dist/ is a fully static site — see frontend/vercel.json for how
// those API calls get proxied to the Render backend in production.
//
// DEV SERVER PROXY — local equivalent of vercel.json's rewrites.
// Without this, `vite dev` has no route for /api/*, so relative fetches
// from src/js/auth.js (e.g. fetch('/api/auth/register')) hit the Vite
// dev server itself instead of the Flask backend, fail to parse as JSON,
// and silently fall back to a generic "Registration failed." error with
// nothing ever reaching Flask or Supabase. This proxies /api and /static
// to the local Flask server (default port 5000, overridable via
// VITE_API_BASE_URL's host if you run Flask elsewhere).
const BACKEND_ORIGIN = process.env.VITE_API_BASE_URL || 'http://localhost:5000';

function multiPageRewritePlugin() {
  return {
    name: 'multi-page-rewrite',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url.split('?')[0];
        if (url === '/forgot-password' || url === '/forgot_pass' || url === '/forgot') {
          req.url = '/forgot_pass.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/reset-password' || url === '/reset_pass' || url === '/reset') {
          req.url = '/reset_password.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/check-mail' || url === '/check_mail') {
          req.url = '/check_mail.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/login') {
          req.url = '/login.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/register') {
          req.url = '/register.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/profile') {
          req.url = '/profile.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/403') {
          req.url = '/403.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/500') {
          req.url = '/500.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (url === '/404') {
          req.url = '/404.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        } else if (
          !url.startsWith('/api') &&
          !url.startsWith('/static') &&
          !url.startsWith('/@') &&
          !url.includes('.')
        ) {
          // Do not show 404 error to user — seamlessly route unknown paths to Dashboard
          req.url = '/index.html' + (req.url.includes('?') ? '?' + req.url.split('?')[1] : '');
        }
        next();
      });
    },
  };
}

export default defineConfig({
  root: __dirname,
  plugins: [multiPageRewritePlugin()],
  server: {
    proxy: {
      '/api': {
        target: BACKEND_ORIGIN,
        changeOrigin: true,
      },
      '/static': {
        target: BACKEND_ORIGIN,
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        login: resolve(__dirname, 'login.html'),
        register: resolve(__dirname, 'register.html'),
        profile: resolve(__dirname, 'profile.html'),
        forgot_pass: resolve(__dirname, 'forgot_pass.html'),
        check_mail: resolve(__dirname, 'check_mail.html'),
        reset_password: resolve(__dirname, 'reset_password.html'),
        forbidden_403: resolve(__dirname, '403.html'),
        server_error_500: resolve(__dirname, '500.html'),
        not_found_404: resolve(__dirname, '404.html'),
      },
    },
  },
});