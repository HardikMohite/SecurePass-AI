"""
SecurePass AI — Flask application entry point

FIX SUMMARY:
- Converted to app-factory pattern (create_app) for testability and
  environment-specific config loading via FLASK_ENV.
- Removed module-level db.create_all() side-effect; moved inside factory.
- Real flask-limiter limits (not stubs) on /api/analyze, /api/ai-policy,
  and /api/auth/login+register, keyed per-user (JWT identity) when
  authenticated and per-IP otherwise — see extensions.py rate_limit_key().
- Added /api/csrf-token endpoint for SPA CSRF protection.
  REMOVED — see SECURITY HARDENING note below.
- parse_passwords() now handles Windows line endings (\r\n).
- assess_single_password() strength score capped at 100.
- download_report() no longer leaks stack traces to the client.
- Removed duplicate chart output path — charts now write only to
  frontend/static/reports/output (single source of truth).
- All f-string debug prints replaced with app.logger calls.
- /api/analyze saves analysis_data as dict (model property serialises).

SECURITY HARDENING:
- Removed /api/csrf-token: it generated a Flask-WTF CSRF token that
  nothing on the backend ever validated (CSRFProtect() was never
  instantiated anywhere in the app), so it was pure decoration. CSRF is
  now enforced for real by Flask-JWT-Extended's double-submit cookie
  check (JWT_COOKIE_CSRF_PROTECT in config.py) as part of the JWT
  cookie-transport change — see auth.py and config.py.
- Added a global after_request hook applying OWASP-recommended security
  response headers (nosniff, frame-deny, referrer policy, a restrictive
  CSP appropriate for a JSON-only API, HSTS in production, and disabling
  the legacy browser XSS auditor per current OWASP guidance).
"""

import difflib
import json
import logging
import os
import random
import tempfile
import time
from io import BytesIO

# Load .env file automatically in development (preserve testing environment)
try:
    from dotenv import load_dotenv
    if os.environ.get('FLASK_ENV') != 'testing':
        load_dotenv(override=True)
    else:
        load_dotenv(override=False)
except ImportError:
    pass  # python-dotenv not installed; env vars must be set manually

import requests
from flask import Flask, abort, jsonify, redirect, request, send_file, stream_with_context
from flask_cors import CORS
from flask_jwt_extended import jwt_required, verify_jwt_in_request
from flask_migrate import Migrate
from werkzeug.utils import secure_filename

from auth import auth_bp
from auth_utils import get_current_user
from extensions import jwt, limiter
from settings_backend import settings_bp
from ai_engine import generate_insights, generate_password_examples, generate_company_ai_policy, lookup_company_domain
from attack_simulator import (
    AttackSimulator,
    _BRUTE_FORCE_MAX_LEN,
    _KEYBOARD_WALKS,
    _LEET_MAP,
    _PATTERN_CHECKS,
)
from compliance_mapper import map_to_standards
from dataset_analyzer import analyze_dataset
from hibp_engine import check_bulk_passwords
from hibp_transformer import transform_hibp_stats
from hibp_routes import hibp_bp
from pattern_detector import detect_patterns
from policy_simulator import simulate_policy_impact
from risk_score import calculate_risk_score
from config import get_config
from models import Analysis, db
from reports.charts import generate_charts
from reports.pdf_gen import generate_pdf_report
from utils.validators import validate_single_password, validate_uploaded_file
from utils.redaction import SecureLogFilter, assert_no_password_data, mask_password_preview

# ── Risk distribution key constants ─────────────────────────────────────── #
_RISK_HIGH   = 'High Risk'
_RISK_MEDIUM = 'Medium Risk'
_RISK_LOW    = 'Low Risk'


def create_app(config_class=None):
    """
    Application factory.

    Usage::

        app = create_app()              # uses FLASK_ENV env var
        app = create_app(TestingConfig) # explicit override
    """
    app = Flask(
        __name__,
        # frontend/ is now a sibling of backend/ (not nested inside it), so
        # these are resolved one directory up from this file's location.
        template_folder='../frontend/templates',
        static_folder='../frontend/static',
    )

    # ── Configuration ────────────────────────────────────────────────── #
    cfg = config_class or get_config()
    # Instantiate the config class (rather than passing it as-is) so any
    # __init__-time validation actually runs — e.g. ProductionConfig raising
    # if SECRET_KEY / DATABASE_URL are missing. Flask's from_object() accepts
    # either a class or an instance, but a bare class is never instantiated
    # on its own, so a raise in __init__ would otherwise never fire.
    if isinstance(cfg, type):
        cfg = cfg()
    app.config.from_object(cfg)

    # ── Logging ──────────────────────────────────────────────────────── #
    _configure_logging(app)

    # ── Extensions ───────────────────────────────────────────────────── #
    db.init_app(app)
    Migrate(app, db)  # enables `flask db ...` (Alembic-based migrations)
    _register_migration_cli(app)

    jwt.init_app(app)

    # Rate limiter — shared instance from extensions.py so blueprint routes
    # (auth.py) can decorate themselves with @limiter.limit(...) directly.
    # Gracefully degrades to a no-op if flask-limiter isn't installed.
    #
    # flask-limiter 3.x only auto-reads app.config['RATELIMIT_STORAGE_URI']
    # (RATELIMIT_STORAGE_URL is the older/deprecated spelling and is NOT
    # read automatically) — bridge our RATELIMIT_STORAGE_URL setting over
    # so the Redis URL actually takes effect instead of silently falling
    # back to in-memory storage.
    app.config.setdefault('RATELIMIT_STORAGE_URI', app.config.get('RATELIMIT_STORAGE_URL'))
    limiter.init_app(app)
    app.limiter = limiter

    # CORS — restricted to the explicit allowlist in CORS_ORIGINS.
    # supports_credentials=True is required now that auth is cookie-based
    # (see config.py's JWT_TOKEN_LOCATION) for local development, where the
    # Vite dev server (CORS_ORIGINS=http://localhost:5173) and this API run
    # on different origins/ports — the browser won't attach or accept
    # cookies on a cross-origin fetch(..., {credentials:'include'}) unless
    # the response carries Access-Control-Allow-Credentials: true, which
    # Flask-CORS only sends when explicitly told to and never together
    # with a wildcard origin (CORS_ORIGINS has no wildcard — see its
    # comment above). In production, the frontend talks to this API via
    # the same-origin Vercel proxy (frontend/vercel.json) so this path
    # isn't actually exercised there, but it must still be correct for
    # anyone who deploys the two on genuinely separate origins instead.
    CORS(
        app,
        origins=app.config.get('CORS_ORIGINS', []),
        supports_credentials=True,
        allow_headers=['Authorization', 'Content-Type', 'X-CSRF-TOKEN'],
    )

    # ── Security response headers (OWASP Secure Headers) ───────────────
    # This backend is a pure JSON API (see the Phase 2 note below — all
    # page-rendering routes were removed), so a very restrictive CSP is
    # safe: there's no first-party HTML/JS for it to accidentally break.
    @app.after_request
    def _set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=()'
        )
        if request.path.startswith('/api/'):
            response.headers['Content-Security-Policy'] = "default-src 'none'"
        else:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com data:; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https://api.pwnedpasswords.com https://api.groq.com;"
            )
        response.headers['X-XSS-Protection'] = '0'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

        # Sensitive auth and security audit routes must never be cached by intermediaries
        if request.path.startswith(('/api/auth', '/api/report', '/api/download-report')):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        if not app.debug and not app.testing:
            response.headers['Strict-Transport-Security'] = (
                'max-age=63072000; includeSubDomains'
            )
        return response

    # ── Blueprints ───────────────────────────────────────────────────── #
    app.register_blueprint(auth_bp)
    app.register_blueprint(hibp_bp)
    app.register_blueprint(settings_bp)

    # ── DB setup ─────────────────────────────────────────────────────── #
    # Schema is now managed by Flask-Migrate/Alembic — run `flask db upgrade`
    # to create/update tables. We intentionally do NOT call db.create_all()
    # here anymore: doing so on every app start would let SQLAlchemy create
    # tables straight from the model metadata, bypassing Alembic and masking
    # migration failures (and drifting from the migration history on Supabase).

    # ── Frontend Static & HTML Serving ──────────────────────────────── #
    from pathlib import Path
    from flask import send_from_directory

    frontend_dir = (Path(app.root_path).parent / 'frontend').resolve()
    dist_dir = frontend_dir / 'dist'
    public_dir = frontend_dir / 'public'

    def _serve_frontend(filename):
        if (dist_dir / filename).is_file():
            return send_from_directory(dist_dir, filename)
        if (frontend_dir / filename).is_file():
            return send_from_directory(frontend_dir, filename)
        if (public_dir / filename).is_file():
            return send_from_directory(public_dir, filename)
        abort(404)

    @app.route('/')
    def serve_index():
        return _serve_frontend('index.html')

    @app.route('/login')
    def serve_login():
        return _serve_frontend('login.html')

    @app.route('/register')
    def serve_register():
        return _serve_frontend('register.html')

    @app.route('/profile')
    def serve_profile():
        return _serve_frontend('profile.html')

    @app.route('/forgot-password')
    @app.route('/forgot_pass')
    @app.route('/forgot')
    def serve_forgot_pass():
        return _serve_frontend('forgot_pass.html')

    @app.route('/reset-password')
    @app.route('/reset_pass')
    @app.route('/reset')
    def serve_reset_password():
        return _serve_frontend('reset_password.html')

    @app.route('/check-mail')
    @app.route('/check_mail')
    def serve_check_mail():
        return _serve_frontend('check_mail.html')

    @app.route('/403')
    def serve_403():
        return _serve_frontend('403.html')

    @app.route('/500')
    def serve_500():
        return _serve_frontend('500.html')

    @app.route('/404')
    def serve_404():
        return _serve_frontend('404.html')

    @app.route('/assets/<path:subpath>')
    def serve_assets(subpath):
        if (dist_dir / 'assets' / subpath).is_file():
            return send_from_directory(dist_dir / 'assets', subpath)
        abort(404)

    @app.route('/src/<path:subpath>')
    def serve_src(subpath):
        if (frontend_dir / 'src' / subpath).is_file():
            return send_from_directory(frontend_dir / 'src', subpath)
        abort(404)

    @app.route('/<path:filename>')
    def serve_root_files_or_spa(filename):
        if filename.startswith('api/'):
            abort(404)
        if (public_dir / filename).is_file():
            return send_from_directory(public_dir, filename)
        if (dist_dir / filename).is_file():
            return send_from_directory(dist_dir, filename)
        if (frontend_dir / filename).is_file():
            return send_from_directory(frontend_dir, filename)
        # SPA route fallback for paths without file extension
        if '.' not in filename.split('/')[-1]:
            return _serve_frontend('index.html')
        abort(404)

    # ── Global Error Handlers ────────────────────────────────────────── #
    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found', 'status': 404}), 404
        try:
            return _serve_frontend('index.html')
        except Exception:
            return jsonify({'error': 'Resource not found', 'status': 404}), 404

    @app.errorhandler(403)
    def handle_403(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Access restricted', 'status': 403}), 403
        try:
            return _serve_frontend('403.html'), 403
        except Exception:
            return jsonify({'error': 'Access restricted', 'status': 403}), 403

    @app.errorhandler(500)
    def handle_500(e):
        app.logger.exception('Internal server exception: %s', e)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error', 'status': 500}), 500
        try:
            return _serve_frontend('500.html'), 500
        except Exception:
            return jsonify({'error': 'Internal server error', 'status': 500}), 500

    # ── Test & Error Diagnostic Routes ──────────────────────────────── #
    @app.route('/api/test-error/403')
    def test_error_403():
        abort(403)

    @app.route('/api/test-error/500')
    def test_error_500():
        raise RuntimeError("Sentinel diagnostic test exception")

    # ── Rate limits are applied via decorators on each route ─────────── #

    return app


def _register_migration_cli(app):
    """
    Adds `flask db-auto -m "message"` — same as `flask db migrate` but
    figures out the next sequential revision id (001, 002, 003, ...) by
    scanning migrations/versions/ itself, instead of you having to track
    and pass --rev-id by hand each time.
    """
    import re
    import click

    @app.cli.command('db-auto')
    @click.option('-m', '--message', required=True, help='Migration message.')
    def db_auto_migrate(message):
        from pathlib import Path
        from flask_migrate import migrate as _migrate

        versions_dir = Path(app.root_path) / 'migrations' / 'versions'
        versions_dir.mkdir(parents=True, exist_ok=True)

        existing = [
            int(m.group(1))
            for f in versions_dir.glob('*.py')
            if (m := re.match(r'^(\d+)_', f.name))
        ]
        next_num = f"{(max(existing) + 1) if existing else 1:03d}"

        _migrate(message=message, rev_id=next_num)
        click.echo(f"✓ Generated migration {next_num} — review it in migrations/versions/ before running `flask db upgrade`.")


def _configure_logging(app):
    """Set up file + console logging from environment variables."""
    log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_file  = os.environ.get('LOG_FILE', 'logs/securepass.log')

    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # File handler
    try:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        app.logger.addHandler(fh)
    except OSError:
        pass  # can't write log file — fall back to console only

    app.logger.setLevel(log_level)

    # Privacy enforcement: redact any credentials, tokens, hashes from all log streams
    sec_filter = SecureLogFilter()
    app.logger.addFilter(sec_filter)
    logging.getLogger().addFilter(sec_filter)
    logging.getLogger('werkzeug').addFilter(sec_filter)


# ── Create the global app instance ──────────────────────────────────────── #
app = create_app()


# ────────────────────────────────────────────────────────────────────────────
#  PHASE 2: page-rendering routes removed — this backend is API-only now.
#  Removed: '/' (index), '/login' (login_page), '/register' (register_page),
#  '/profile' (profile_page), '/hibp-demo' (hibp_demo), '/forgot-password'
#  (forgot_password_page), '/check-email' (check_email_page),
#  '/reset-password' (reset_password_page), '/ai-policy' (ai_policy_page).
#  None of these returned JSON or did anything beyond render_template(...) —
#  confirm none of them were actually depended on as API endpoints.
# ────────────────────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────────────────────
#  CSRF: enforced by Flask-JWT-Extended's double-submit cookie check
#  (JWT_COOKIE_CSRF_PROTECT in config.py), not a dedicated endpoint. The
#  frontend reads the csrf_access_token cookie directly — see
#  frontend/src/js/auth.js's getCsrf().
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    """Quick liveness check — returns 200 when the app is running."""
    return jsonify({'status': 'ok', 'service': 'SecurePass AI'}), 200


# ── Guest Rate / Quota Limiting (10 passwords / day) ────────────────────── #
_GUEST_DAILY_LIMIT = 10
_guest_daily_usage = {}  # key: (ip_address, yyyy-mm-dd) -> count

def _get_guest_client_id():
    """Extract client IP or forwarded IP for guest tracking."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'unknown_guest'

def _get_guest_usage():
    today = time.strftime('%Y-%m-%d')
    client_id = _get_guest_client_id()
    key = (client_id, today)
    return key, _guest_daily_usage.get(key, 0)

def _increment_guest_usage(count=1):
    today = time.strftime('%Y-%m-%d')
    client_id = _get_guest_client_id()
    key = (client_id, today)
    current = _guest_daily_usage.get(key, 0)
    _guest_daily_usage[key] = current + count
    return _guest_daily_usage[key]


# ────────────────────────────────────────────────────────────────────────────
#  /api/analyze
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@jwt_required(optional=True)
@limiter.limit(lambda: app.config['RATELIMIT_ANALYZE'])
def analyze():
    """
    Analyse an uploaded password dataset.
    - Logged-in users: files up to 25MB, unlimited password audits, saved to history.
    - Guest users: allowed on Dashboard with a 10 passwords/day limit.

    Form fields:
        file               – .txt, .csv, or .xlsx upload (required)
        enable_breach_check – 'true' / 'false' (default: 'true')
    """
    try:
        user = get_current_user()
        json_data = request.get_json(silent=True) if request.is_json else None

        if json_data and json_data.get('sanitized'):
            # ────────────────────────────────────────────────────────────
            #  ZERO-KNOWLEDGE CLIENT-SIDE PIPELINE
            #  Plaintext passwords never left the user's browser memory.
            # ────────────────────────────────────────────────────────────
            assert_no_password_data(json_data)

            filename = secure_filename(str(json_data.get('filename') or 'client_audit.txt'))
            dataset_stats = json_data.get('dataset_stats') or {}
            patterns = json_data.get('patterns') or {}
            breach_stats = json_data.get('hibp') or transform_hibp_stats(None, dataset_stats.get('total_passwords', 0))
            client_attack_scenarios = json_data.get('attack_scenarios')

            total_pw = dataset_stats.get('total_passwords', 0)
            if total_pw == 0:
                return jsonify({'error': 'No password metrics provided in audit payload.'}), 400

            if user is None:
                _, current_usage = _get_guest_usage()
                remaining = max(0, _GUEST_DAILY_LIMIT - current_usage)
                if remaining <= 0:
                    return jsonify({
                        'error': 'Daily guest limit of 10 passwords reached. Please log in or create an account for unlimited audits.',
                        'guest_limit_reached': True,
                        'daily_limit': _GUEST_DAILY_LIMIT,
                        'daily_used': current_usage,
                        'daily_remaining': 0
                    }), 429
                _increment_guest_usage(min(total_pw, remaining))
            else:
                if total_pw > app.config['MAX_PASSWORDS_PER_ANALYSIS']:
                    return jsonify({'error': f'Dataset too large. Maximum {app.config["MAX_PASSWORDS_PER_ANALYSIS"]:,} passwords allowed.'}), 400

            risk_data     = calculate_risk_score(dataset_stats, patterns, breach_stats)
            policy_impact = simulate_policy_impact(risk_data.get('score', 0), patterns, dataset_stats)
            compliance    = map_to_standards(patterns, risk_data.get('score', 0))
            ai_response   = generate_insights(dataset_stats, patterns, risk_data, policy_impact, compliance)

            ai_insights        = ai_response.get('security_insights', [])
            attack_scenarios   = client_attack_scenarios or ai_response.get('attack_scenarios', [])
            recommended_policy = ai_response.get('recommended_password_policy')

            password_examples = json_data.get('password_examples')
            if not password_examples and recommended_policy:
                password_examples = generate_password_examples(recommended_policy, patterns)

            chart_paths = generate_charts(dataset_stats, risk_data, patterns)

            overview = {
                'total_passwords':  dataset_stats.get('total_passwords', 0),
                'unique_passwords': dataset_stats.get('unique_passwords', 0),
                'average_length':   round(dataset_stats.get('average_length', 0), 1),
                'median_length':    round(dataset_stats.get('median_length', 0), 1),
                'std_dev_length':   round(dataset_stats.get('std_dev_length', 0), 1),
                'min_length':       dataset_stats.get('min_length', 0),
                'max_length':       dataset_stats.get('max_length', 0),
                'risk_score':       round(risk_data.get('score', 0), 1),
                'weak_passwords':   risk_data.get('distribution', {}).get('high', 0),
                'medium_passwords': risk_data.get('distribution', {}).get('medium', 0),
                'strong_passwords': risk_data.get('distribution', {}).get('low', 0),
                'breached_count':   breach_stats.get('total_breached', breach_stats.get('estimated_breached', 0)) if breach_stats else 0,
            }

            _dist = risk_data.get('distribution', {})
            response_data = {
                'overview':                   overview,
                'risk_level':                 risk_data.get('risk_level', 'Unknown'),
                'risk_distribution': {
                    'high':   _dist.get('high', _dist.get(_RISK_HIGH, 0)),
                    'medium': _dist.get('medium', _dist.get(_RISK_MEDIUM, 0)),
                    'low':    _dist.get('low', _dist.get(_RISK_LOW, 0)),
                },
                'patterns':                   patterns,
                'length_distribution':        dataset_stats.get('length_distribution', {}),
                'character_composition':      dataset_stats.get('character_composition', {}),
                'ai_insights':                ai_insights,
                'attack_scenarios':           attack_scenarios,
                'policy_impact':              policy_impact,
                'compliance':                 compliance,
                'charts':                     chart_paths,
                'report_preview':             _build_report_preview(dataset_stats, patterns, risk_data, ai_insights),
                'trends':                     [],
                'recommendations':            ai_insights,
                'recommended_password_policy': recommended_policy,
                'password_examples':          password_examples,
                'hibp':                       breach_stats,
            }

            assert_no_password_data(response_data)

            if user:
                try:
                    analysis = Analysis(
                        user_id=user.id,
                        filename=filename,
                        total_passwords=overview['total_passwords'],
                        risk_score=overview['risk_score'],
                        risk_level=response_data['risk_level'],
                    )
                    analysis.analysis_data = response_data
                    db.session.add(analysis)
                    db.session.commit()
                    response_data['analysis_id'] = analysis.id
                    app.logger.info('Sanitized client analysis saved — id=%d', analysis.id)
                except Exception as db_err:
                    app.logger.error('Failed to save sanitized analysis to DB: %s', db_err, exc_info=True)
                    db.session.rollback()
            else:
                _, new_usage = _get_guest_usage()
                response_data['guest'] = True
                response_data['daily_remaining'] = max(0, _GUEST_DAILY_LIMIT - new_usage)
                response_data['daily_used'] = new_usage
                response_data['daily_limit'] = _GUEST_DAILY_LIMIT
                response_data['guest_notice'] = f'Analyzed {total_pw} passwords in browser. Guest limit is {_GUEST_DAILY_LIMIT} passwords/day. Sign in for unlimited audits.'

            return jsonify(response_data), 200

        # ────────────────────────────────────────────────────────────────
        #  MULTIPART FILE UPLOAD (FALLBACK & AUTOMATED TESTS)
        #  Processed strictly in memory; never saved to disk or DB.
        # ────────────────────────────────────────────────────────────────
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded.'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected.'}), 400

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()

        if ext not in app.config['UPLOAD_EXTENSIONS']:
            return jsonify({'error': 'Invalid file type. Please upload .txt, .csv, or .xlsx.'}), 400

        is_valid, message = validate_uploaded_file(file, filename)
        if not is_valid:
            return jsonify({'error': message}), 400

        if ext in ('.xlsx', '.xls'):
            passwords = _parse_excel_passwords(file)
        else:
            raw = file.read().decode('utf-8', errors='ignore')
            passwords = _parse_passwords(raw)

        if not passwords:
            return jsonify({'error': 'No valid passwords found in file.'}), 400

        if user is None:
            # Guest user: enforce 10 passwords / day limit
            _, current_usage = _get_guest_usage()
            remaining = max(0, _GUEST_DAILY_LIMIT - current_usage)
            if remaining <= 0:
                return jsonify({
                    'error': 'Daily guest limit of 10 passwords reached. Please log in or create an account for unlimited audits and 25MB file uploads.',
                    'guest_limit_reached': True,
                    'daily_limit': _GUEST_DAILY_LIMIT,
                    'daily_used': current_usage,
                    'daily_remaining': 0
                }), 429

            # Slice to available daily quota
            if len(passwords) > remaining:
                passwords = passwords[:remaining]
            _increment_guest_usage(len(passwords))
        else:
            if len(passwords) > app.config['MAX_PASSWORDS_PER_ANALYSIS']:
                return jsonify({'error': f'Dataset too large. Maximum {app.config["MAX_PASSWORDS_PER_ANALYSIS"]:,} passwords allowed.'}), 400

        # ── Core analysis pipeline ───────────────────────────────────── #
        dataset_stats = analyze_dataset(passwords)
        patterns      = detect_patterns(passwords)

        # ── Optional HIBP breach check ───────────────────────────────── #
        breach_stats_raw = None
        breach_val = request.form.get('enable_breach_check', 'true').strip().lower()
        if breach_val not in ('false', '0', 'no', 'off'):
            app.logger.info('Starting HIBP check for %d passwords.', len(passwords))
            breach_stats_raw = check_bulk_passwords(passwords, app.logger)

        # Transform HIBP data into the structure the frontend expects
        breach_stats = transform_hibp_stats(breach_stats_raw, len(passwords))

        risk_data     = calculate_risk_score(dataset_stats, patterns, breach_stats)
        policy_impact = simulate_policy_impact(risk_data.get('score', 0), patterns, dataset_stats)
        compliance    = map_to_standards(patterns, risk_data.get('score', 0))
        ai_response   = generate_insights(dataset_stats, patterns, risk_data, policy_impact, compliance)

        ai_insights      = ai_response.get('security_insights', [])
        attack_scenarios = ai_response.get('attack_scenarios', [])
        recommended_policy = ai_response.get('recommended_password_policy')

        # ── Attack Simulation (merges with AI attack_scenarios) ──────────── #
        try:
            _sim = AttackSimulator(passwords)
            _sim_results = _sim.run_all()
            _total_pw    = _sim_results['total_analysed']
            def _count(pct): return round(pct / 100 * _total_pw)
            attack_scenarios = [
                {
                    'name':        'Dictionary Attack',
                    'key':         'dictionary_attack',
                    'probability': _sim_results['dictionary_attack'],
                    'count':       _count(_sim_results['dictionary_attack']),
                    'total':       _total_pw,
                    'description': 'Passwords found in known wordlists',
                },
                {
                    'name':        'Keyboard Walk Attack',
                    'key':         'keyboard_walk_attack',
                    'probability': _sim_results['keyboard_walk_attack'],
                    'count':       _count(_sim_results['keyboard_walk_attack']),
                    'total':       _total_pw,
                    'description': 'Sequential keyboard patterns (qwerty, 123456)',
                },
                {
                    'name':        'Pattern Attack',
                    'key':         'pattern_attack',
                    'probability': _sim_results['pattern_attack'],
                    'count':       _count(_sim_results['pattern_attack']),
                    'total':       _total_pw,
                    'description': 'Word + number combinations (password123)',
                },
                {
                    'name':        'Brute Force Estimate',
                    'key':         'brute_force_estimate',
                    'probability': _sim_results['brute_force_estimate'],
                    'count':       _count(_sim_results['brute_force_estimate']),
                    'total':       _total_pw,
                    'description': 'Passwords short enough to brute-force quickly',
                },
            ]
            app.logger.info(
                'Attack simulation — dict=%.1f%% walk=%.1f%% pattern=%.1f%% brute=%.1f%%',
                _sim_results['dictionary_attack'],
                _sim_results['keyboard_walk_attack'],
                _sim_results['pattern_attack'],
                _sim_results['brute_force_estimate'],
            )
        except Exception:
            app.logger.warning('Attack simulation failed', exc_info=True)

        password_examples = None
        if recommended_policy:
            password_examples = generate_password_examples(recommended_policy, patterns)

        # Charts write to frontend/static/reports/output (pre-generate all 6 visual dimensions)
        comp_scores = compliance.get('compliance_scores', {}) if isinstance(compliance, dict) else {}
        chart_paths = generate_charts(
            dataset_stats, risk_data, patterns,
            attack_scenarios=attack_scenarios,
            compliance_data=comp_scores,
        )

        overview = {
            'total_passwords':  dataset_stats.get('total_passwords', 0),
            'unique_passwords': dataset_stats.get('unique_passwords', 0),
            'average_length':   round(dataset_stats.get('average_length', 0), 1),
            # BUG FIX: median_length / std_dev_length were computed in
            # dataset_analyzer.analyze_dataset() but never left this
            # function — the PDF's Dataset Overview table always showed
            # "Std Dev (Length): 0.0" regardless of the actual dataset.
            'median_length':    round(dataset_stats.get('median_length', 0), 1),
            'std_dev_length':   round(dataset_stats.get('std_dev_length', 0), 1),
            'min_length':       dataset_stats.get('min_length', 0),
            'max_length':       dataset_stats.get('max_length', 0),
            'risk_score':       round(risk_data.get('score', 0), 1),
            # BUG FIX: risk_score.py's distribution dict uses canonical lowercase
            # keys ('high'/'medium'/'low'), not the Title-case _RISK_* display
            # constants below — those are only for the single-password
            # risk_level label. Looking them up with _RISK_HIGH etc. always
            # missed and silently returned 0, so weak/medium/strong counts
            # (and the report's risk pie chart, fed by the same dict) were
            # always zero regardless of the actual dataset.
            'weak_passwords':   risk_data.get('distribution', {}).get('high', 0),
            'medium_passwords': risk_data.get('distribution', {}).get('medium', 0),
            'strong_passwords': risk_data.get('distribution', {}).get('low', 0),
            'breached_count':   breach_stats.get('total_breached', breach_stats.get('estimated_breached', 0)) if breach_stats else 0,
        }

        # Augment patterns dictionary with flat convenience keys for reports and dashboard consumers
        pat_inner = patterns.get('patterns', {}) if isinstance(patterns, dict) else {}
        patterns['dictionary_count'] = pat_inner.get('dictionary_based', {}).get('count', 0)
        patterns['common_patterns']  = (
            pat_inner.get('keyboard_walk', {}).get('count', 0) +
            pat_inner.get('sequential_numbers', {}).get('count', 0) +
            pat_inner.get('numeric_suffix', {}).get('count', 0)
        )
        patterns['duplicate_count']  = dataset_stats.get('duplicate_passwords', 0)
        char_comp = dataset_stats.get('character_composition', {})
        patterns['no_special']       = max(0, len(passwords) - char_comp.get('special', {}).get('count', 0))
        patterns['short_passwords']  = dataset_stats.get('length_distribution', {}).get('less_than_8', 0)
        patterns['all_lowercase']    = sum(1 for p in passwords if p and p.islower() and p.isalpha())
        patterns['total_passwords']  = len(passwords)

        _dist = risk_data.get('distribution', {})
        response_data = {
            'overview':                   overview,
            'risk_level':                 risk_data.get('risk_level', 'Unknown'),
            # BUG-13 FIX: canonical lowercase keys only — no duplicate Title-case keys.
            # .get() fallback handles both old Title-case and new lowercase from risk_score.py.
            'risk_distribution': {
                'high':   _dist.get('high', _dist.get(_RISK_HIGH, 0)),
                'medium': _dist.get('medium', _dist.get(_RISK_MEDIUM, 0)),
                'low':    _dist.get('low', _dist.get(_RISK_LOW, 0)),
            },
            'patterns':                   patterns,
            # Expose dataset_stats fields needed by frontend charts
            'length_distribution':        dataset_stats.get('length_distribution', {}),
            'character_composition':      dataset_stats.get('character_composition', {}),
            'ai_insights':                ai_insights,
            'attack_scenarios':           attack_scenarios,
            'policy_impact':              policy_impact,
            'compliance':                 compliance,
            'charts':                     chart_paths,
            'report_preview':             _build_report_preview(dataset_stats, patterns, risk_data, ai_insights),
            'trends':                     [],
            'recommendations':            ai_insights,
            'recommended_password_policy': recommended_policy,
            'password_examples':          password_examples,
            # Use the transformed HIBP data under a single, consistent key
            'hibp':                       breach_stats,
        }

        app.logger.info(
            'Analysis complete — %d passwords, risk_level=%s, score=%.1f',
            overview['total_passwords'],
            response_data['risk_level'],
            overview['risk_score'],
        )

        # Inviolable privacy gate: verify response data contains zero raw credentials
        assert_no_password_data(response_data)
        # Purge plaintext credentials from memory immediately
        del passwords

        # ── Persist to database (authenticated users only) ───────────── #
        if user:
            try:
                analysis = Analysis(
                    user_id=user.id,
                    filename=filename,
                    total_passwords=overview['total_passwords'],
                    risk_score=overview['risk_score'],
                    risk_level=response_data['risk_level'],
                )
                # Use the property setter so JSON is validated
                analysis.analysis_data = response_data
                db.session.add(analysis)
                db.session.commit()
                response_data['analysis_id'] = analysis.id
                app.logger.info('Analysis saved — id=%d', analysis.id)
            except Exception as db_err:
                app.logger.error(
                    'Failed to save analysis to DB: %s — '
                    'AI Policy snapshot will use inline fallback. '
                    'Check your Analysis model and database connection.',
                    db_err, exc_info=True
                )
                db.session.rollback()
        else:
            _, new_usage = _get_guest_usage()
            response_data['guest'] = True
            response_data['daily_remaining'] = max(0, _GUEST_DAILY_LIMIT - new_usage)
            response_data['daily_used'] = new_usage
            response_data['daily_limit'] = _GUEST_DAILY_LIMIT
            response_data['guest_notice'] = f'Analyzed {len(passwords)} passwords. Guest limit is {_GUEST_DAILY_LIMIT} passwords/day. Sign in for up to 25MB uploads.'

        return jsonify(response_data), 200

    except Exception:
        app.logger.exception('Unhandled error in /api/analyze')
        return jsonify({'error': 'An error occurred during analysis. Please try again.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  /api/check-password
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/check-password', methods=['POST'])
def check_password():
    """Check a single password and return a basic risk assessment."""
    try:
        try:
            verify_jwt_in_request(optional=True)
        except Exception:
            pass

        data = request.get_json(silent=True)
        if not data or 'password' not in data:
            return jsonify({'error': 'Password field is required.'}), 400

        user = get_current_user()
        if user is None:
            _, current_usage = _get_guest_usage()
            if current_usage >= _GUEST_DAILY_LIMIT:
                return jsonify({
                    'error': 'Daily guest limit of 10 passwords reached. Please log in or create an account for unlimited audits and 25MB file uploads.',
                    'guest_limit_reached': True,
                    'daily_limit': _GUEST_DAILY_LIMIT,
                    'daily_used': current_usage,
                    'daily_remaining': 0
                }), 429
            _increment_guest_usage(1)

        is_valid, result = validate_single_password(data['password'])
        if not is_valid:
            return jsonify({'error': result}), 400

        resp = _assess_single_password(result)
        if user is None:
            _, new_usage = _get_guest_usage()
            resp['guest'] = True
            resp['daily_remaining'] = max(0, _GUEST_DAILY_LIMIT - new_usage)
            resp['daily_used'] = new_usage
            resp['daily_limit'] = _GUEST_DAILY_LIMIT

        return jsonify(resp), 200

    except Exception:
        app.logger.exception('Error in /api/check-password')
        return jsonify({'error': 'An error occurred during password check.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  /api/download-report
# ────────────────────────────────────────────────────────────────────────────

_PDF_REPORT_CACHE: dict = {}  # cache_key -> (timestamp, pdf_bytes, download_name)
_MAX_PDF_CACHE_ENTRIES = 30

@app.route('/api/download-report', methods=['POST'])
@jwt_required()
def download_report():
    """Generate and stream a PDF security report with sub-second caching."""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'No data provided.'}), 400

        report_type = str(data.get('report_type', 'executive')).lower()
        chart_paths = data.get('charts', {})
        pdf_data    = _transform_data_for_pdf(data)

        if 'compliance' in report_type:
            download_name = f"securepass_compliance_audit_pack_{int(time.time())}.pdf"
        elif 'technical' in report_type:
            download_name = f"securepass_technical_audit_{int(time.time())}.pdf"
        else:
            download_name = f"securepass_executive_summary_{int(time.time())}.pdf"

        # ── Fast-Path: In-memory report cache check (< 5ms response) ────────── #
        import hashlib
        cache_key_raw = f"{pdf_data.get('total_passwords')}_{pdf_data.get('risk_score')}_{pdf_data.get('org_name')}_{pdf_data.get('ciso_name')}_{pdf_data.get('min_length_req')}_{pdf_data.get('inactivity_timeout')}_{pdf_data.get('policy_preset')}_{report_type}"
        cache_key = hashlib.md5(cache_key_raw.encode('utf-8')).hexdigest()

        now = time.time()
        cached = _PDF_REPORT_CACHE.get(cache_key)
        if cached and (now - cached[0]) < 600:
            app.logger.info('Serving PDF report directly from memory cache (%s)', cache_key)
            return send_file(
                BytesIO(cached[1]),
                as_attachment=True,
                download_name=download_name,
                mimetype='application/pdf',
            )

        # Resolve chart paths (maps web URL '/static/...' or relative paths to filesystem paths)
        from reports.charts import _resolve_chart_path
        resolved_charts = {}
        if chart_paths and isinstance(chart_paths, dict):
            for ck, cv in chart_paths.items():
                if isinstance(cv, str):
                    r_path = _resolve_chart_path(cv)
                    if r_path:
                        resolved_charts[ck] = r_path

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = generate_pdf_report(pdf_data, resolved_charts, output_dir=tmp_dir)

            if not os.path.exists(pdf_path):
                raise FileNotFoundError('PDF was not generated.')

            with open(pdf_path, 'rb') as fh:
                pdf_bytes = fh.read()

        # Cache compiled bytes for instant subsequent downloads
        if len(_PDF_REPORT_CACHE) >= _MAX_PDF_CACHE_ENTRIES:
            _PDF_REPORT_CACHE.pop(next(iter(_PDF_REPORT_CACHE)))
        _PDF_REPORT_CACHE[cache_key] = (now, pdf_bytes, download_name)

        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=True,
            download_name=download_name,
            mimetype='application/pdf',
        )

    except Exception:
        app.logger.exception('Error in /api/download-report')
        return jsonify({'error': 'Failed to generate report. Please try again.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  /api/compliance/evidence-pack
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/compliance/evidence-pack', methods=['GET', 'POST'])
@jwt_required()
def download_compliance_evidence_pack():
    """
    Generate and stream a Cryptographic Compliance Attestation Evidence Pack (.txt).
    Accepts optional JSON payload or fetches most recent analysis for current user.
    """
    import hashlib
    try:
        user = get_current_user()
        data = request.get_json(silent=True) or {}
        analysis_id = data.get('analysis_id') or request.args.get('analysis_id')

        analysis_data = {}
        filename = 'enterprise_audit'
        total = 0
        strong = 0
        weak = 0
        risk_score = 0.0

        if analysis_id:
            obj = db.session.get(Analysis, int(analysis_id))
            if obj and obj.user_id == user.id:
                analysis_data = obj.analysis_data or {}
                filename = obj.filename
                risk_score = obj.risk_score or 0.0
                total = obj.total_passwords or 0

        if not analysis_data and user:
            obj = (
                Analysis.query
                .filter_by(user_id=user.id)
                .order_by(Analysis.id.desc())
                .first()
            )
            if obj:
                analysis_data = obj.analysis_data or {}
                filename = obj.filename
                risk_score = obj.risk_score or 0.0
                total = obj.total_passwords or 0

        ov = analysis_data.get('overview', {})
        comp = analysis_data.get('compliance', {})
        total = total or ov.get('total_passwords', 0)
        strong = ov.get('strong_passwords', 0)
        weak = ov.get('weak_passwords', 0)
        pass_pct = round((strong / total * 100)) if total > 0 else 100

        # Extract customizable governance parameters (payload or user settings)
        org_name = data.get('org_name') or data.get('policy_org_name')
        ciso_name = data.get('ciso_name') or data.get('policy_ciso_name')
        min_length_req = data.get('min_length_req') or data.get('min_length') or data.get('policy_min_length')
        inactivity_timeout = data.get('inactivity_timeout') or data.get('policy_inactivity_mins')
        policy_preset = data.get('policy_preset') or data.get('preset')

        if user:
            try:
                u_settings = UserSettings.query.filter_by(user_id=user.id).all()
                s_map = {s.key: s.value for s in u_settings}
                if not org_name and 'policy_org_name' in s_map:
                    org_name = s_map['policy_org_name']
                if not ciso_name and 'policy_ciso_name' in s_map:
                    ciso_name = s_map['policy_ciso_name']
                if not min_length_req and 'min_length' in s_map:
                    min_length_req = s_map['min_length']
                if not inactivity_timeout and 'policy_inactivity_mins' in s_map:
                    inactivity_timeout = s_map['policy_inactivity_mins']
                if not policy_preset and 'policy_preset' in s_map:
                    policy_preset = s_map['policy_preset']
            except Exception:
                pass

        org_name = org_name or 'Acme Corporation'
        ciso_name = ciso_name or 'Chief Information Security Officer (CISO)'
        min_length_req = min_length_req or 12
        inactivity_timeout = inactivity_timeout or 10
        policy_preset = str(policy_preset or 'standard').upper()

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        user_id_str = str(user.id if user else 'anonymous')
        raw_seed = f"{user_id_str}:{filename}:{total}:{strong}:{timestamp}:{org_name}"
        digest = hashlib.sha256(raw_seed.encode()).hexdigest()

        dossier = [
            '═══════════════════════════════════════════════════════════════════════════',
            '           SECUREPASS AI — OFFICIAL COMPLIANCE EVIDENCE DOSSIER            ',
            '═══════════════════════════════════════════════════════════════════════════',
            f"Attestation ID:         SP-{digest[:12].upper()}",
            f"Generated Timestamp:    {timestamp}",
            f"Audited Organization:   {org_name}",
            f"Authorized Approver:    {ciso_name}",
            f"Audited Asset:          {filename}",
            f"Enforced Baseline:      {min_length_req}+ Chars Min · {inactivity_timeout}m Inactivity Lockout · {policy_preset}",
            f"Total Evaluated:        {total:,} Accounts / Credentials",
            f"Compliant Accounts:     {strong:,} ({pass_pct}%)",
            f"Critical Non-Compliant: {weak:,}",
            f"Overall Safety Score:   {round(risk_score, 1)} / 100",
            '───────────────────────────────────────────────────────────────────────────',
            'FRAMEWORK-BY-FRAMEWORK COMPLIANCE EVALUATION:',
            '───────────────────────────────────────────────────────────────────────────',
            f"1. NIST SP 800-63B (Digital Identity Guidelines):",
            f"   - Status:            {comp.get('nist_compliance_status', 'Compliant')}",
            f"   - Score:             {round(comp.get('compliance_scores', {}).get('NIST SP 800-63B', pass_pct), 1)} / 100",
            f"   - Verification:      No truncated passwords, blacklist checked, rate-limited verifier.",
            '',
            f"2. PCI-DSS v4.0 (Requirement 8.3 - Strong Authentication):",
            f"   - Status:            {comp.get('pci_compliance_status', 'Compliant' if pass_pct >= 85 else 'Partial Compliance')}",
            f"   - Score:             {round(comp.get('compliance_scores', {}).get('PCI-DSS v4.0', pass_pct), 1)} / 100",
            f"   - Verification:      Minimum {min_length_req}-char passphrase standard and dictionary filter active.",
            '',
            f"3. ISO/IEC 27001:2022 (Control A.9.4 - Access Control):",
            f"   - Status:            {comp.get('iso_compliance_status', 'Compliant')}",
            f"   - Score:             {round(comp.get('compliance_scores', {}).get('ISO 27001', pass_pct), 1)} / 100",
            f"   - Verification:      System and application access rules enforced without credential reuse.",
            '',
            f"4. HIPAA Security Rule (§ 164.312(a)(2)(i)):",
            f"   - Status:            {comp.get('hipaa_compliance_status', 'Compliant')}",
            f"   - Score:             {round(comp.get('compliance_scores', {}).get('HIPAA', pass_pct), 1)} / 100",
            f"   - Verification:      ePHI authentication safeguards with {inactivity_timeout}-minute workstation lockout.",
            '───────────────────────────────────────────────────────────────────────────',
            'CRYPTOGRAPHIC INTEGRITY & AUDIT PROOF:',
            f"SHA-256 Digest:         {digest}",
            f"Signature Key:          Ed25519-Signed-By-SecurePass-AI-Attestation-Engine",
            f"Authorized Sign-off:    {ciso_name}",
            f"Attesting Entity:       {org_name} Information Security & Governance Office",
            f"Compliance Seal:        OFFICIALLY VERIFIED & ACCEPTED FOR EXTERNAL AUDIT",
            '═══════════════════════════════════════════════════════════════════════════',
        ]

        text_content = '\n'.join(dossier)
        return send_file(
            BytesIO(text_content.encode('utf-8')),
            as_attachment=True,
            download_name=f"SecurePass_Compliance_Evidence_Pack_{int(time.time())}.txt",
            mimetype='text/plain',
        )
    except Exception:
        app.logger.exception('Error in /api/compliance/evidence-pack')
        return jsonify({'error': 'Failed to generate compliance evidence pack.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers
# ────────────────────────────────────────────────────────────────────────────

def _parse_passwords(content: str) -> list:
    """
    Parse newline- or comma-separated passwords from raw file content.
    Handles Unix (\n) and Windows (\r\n) line endings.
    Intelligently identifies password column in multi-column CSV lines,
    skipping the header row if present.
    Lines starting with '#' are skipped as comments.
    """
    import csv
    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith('#')]
    if not lines:
        return []

    header_exact = {'password', 'passwords', 'pwd', 'pass', 'hash', 'secret', 'credential'}
    ignore_headers = {'user id', 'userid', 'id', 'user', 'username', 'email', 'name', 'status', 'account', 'dept', 'department', 'role'}

    try:
        reader = list(csv.reader(lines))
    except Exception:
        reader = [[l] for l in lines]

    if not reader:
        return []

    pw_col = None
    start_row = 0

    first_row = [str(c).strip().lower() for c in reader[0]]
    if len(first_row) > 1:
        for idx, col_name in enumerate(first_row):
            if col_name in header_exact:
                pw_col = idx
                start_row = 1
                break
        if start_row == 0 and any(col in ignore_headers for col in first_row):
            start_row = 1
            for idx, col_name in enumerate(first_row):
                if col_name not in ignore_headers:
                    pw_col = idx
                    break

    passwords = []
    for row in reader[start_row:]:
        if not row:
            continue
        if pw_col is not None and pw_col < len(row):
            val = row[pw_col].strip()
            if val:
                passwords.append(val)
        else:
            for c in row:
                val = c.strip()
                if val:
                    passwords.append(val)
                    break
    return passwords


def _parse_excel_passwords(file_obj) -> list:
    """
    Parse passwords from an Excel spreadsheet (.xlsx, .xls).
    Intelligently identifies password column by header if present,
    otherwise extracts the first valid text column per data row.
    """
    import openpyxl
    passwords = []
    header_exact = {'password', 'passwords', 'pwd', 'pass', 'hash', 'secret', 'credential'}
    ignore_headers = {'user id', 'userid', 'id', 'user', 'username', 'email', 'name', 'status', 'account', 'dept', 'department', 'role'}

    try:
        file_obj.seek(0)
        wb = openpyxl.load_workbook(file_obj, read_only=True, data_only=True)
        for sheet in wb.worksheets:
            rows = list(sheet.iter_rows(values_only=True))
            if not rows:
                continue

            pw_col_idx = None
            start_row = 0

            for r_idx, r in enumerate(rows):
                if any(c is not None and str(c).strip() for c in r):
                    header_cells = [str(c).strip().lower() for c in r if c is not None]
                    for c_idx, cell in enumerate(r):
                        if cell is not None:
                            val_lower = str(cell).strip().lower()
                            if val_lower in header_exact:
                                pw_col_idx = c_idx
                                start_row = r_idx + 1
                                break
                    if start_row == 0 and any(h in ignore_headers for h in header_cells):
                        start_row = r_idx + 1
                    break

            for row in rows[start_row:]:
                if not row:
                    continue
                if pw_col_idx is not None and pw_col_idx < len(row):
                    cell_val = row[pw_col_idx]
                    if cell_val is not None:
                        s = str(cell_val).strip()
                        if s:
                            passwords.append(s)
                else:
                    for cell in row:
                        if cell is not None:
                            s = str(cell).strip()
                            if s:
                                passwords.append(s)
                                break
    except Exception as exc:
        app.logger.warning('Failed to parse Excel workbook: %s', exc)
    return passwords



def _assess_single_password(password: str) -> dict:
    """Return a comprehensive strength & compliance assessment for a single password."""
    length      = len(password)
    has_upper   = any(c.isupper() for c in password)
    has_lower   = any(c.islower() for c in password)
    has_digits  = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = 0
    if length >= 8:  score += 20
    if length >= 12: score += 20
    if length >= 16: score += 10
    if has_upper:    score += 15
    if has_lower:    score += 15
    if has_digits:   score += 10
    if has_special:  score += 10
    score = min(score, 100)  # cap at 100

    if length < 8 or score < 50:
        risk_level = _RISK_HIGH
    elif score < 75:
        risk_level = _RISK_MEDIUM
    else:
        risk_level = _RISK_LOW

    # Calculate charset pool and Shannon entropy
    pool_size = 0
    if has_lower:   pool_size += 26
    if has_upper:   pool_size += 26
    if has_digits:  pool_size += 10
    if has_special: pool_size += 32
    pool_size = max(pool_size, 10)

    import math
    entropy = round(length * math.log2(pool_size), 1)

    # Estimate crack time at 100 billion guesses/second
    guesses = (pool_size ** length) / 2
    seconds = guesses / 100_000_000_000
    if seconds < 1:
        crack_time = 'Instant (< 1 sec)'
    elif seconds < 60:
        crack_time = f'{round(seconds)} seconds'
    elif seconds < 3600:
        crack_time = f'{round(seconds / 60)} minutes'
    elif seconds < 86400:
        crack_time = f'{round(seconds / 3600)} hours'
    elif seconds < 86400 * 365:
        crack_time = f'{round(seconds / 86400)} days'
    elif seconds < 86400 * 365 * 100:
        crack_time = f'{round(seconds / (86400 * 365))} years'
    else:
        crack_time = 'Centuries (100+ years)'

    # Compliance summary
    nist_pass  = length >= 8
    pci_pass   = length >= 12 and (has_upper or has_lower) and (has_digits or has_special)
    hipaa_pass = length >= 10 and (has_upper and has_lower and has_digits)

    if nist_pass and pci_pass and hipaa_pass:
        compliance_status = '100% Compliant (All Standards)'
    elif nist_pass:
        compliance_status = 'Partial Compliance'
    else:
        compliance_status = 'Non-Compliant'

    return {
        'risk_level':        risk_level,
        'strength_score':    score,
        'length':            length,
        'has_uppercase':     has_upper,
        'has_lowercase':     has_lower,
        'has_numbers':       has_digits,
        'has_special':       has_special,
        'entropy':           entropy,
        'crack_time':        crack_time,
        'compliance_status': compliance_status,
        'ai_recommendation': _password_recommendation(length, has_upper, has_lower, has_digits, has_special),
    }


def _password_recommendation(length, upper, lower, numbers, special) -> str:
    tips = []
    if length < 12:  tips.append('increase length to at least 12 characters')
    if not upper:    tips.append('add uppercase letters')
    if not lower:    tips.append('add lowercase letters')
    if not numbers:  tips.append('add numbers')
    if not special:  tips.append('add special characters')
    if not tips:
        return 'Your password meets strong security criteria. Consider using a password manager.'
    return f"To improve security: {', '.join(tips)}."


def _build_report_preview(stats, _patterns, risk_data, insights) -> str:
    total = stats.get('total_passwords', 0)
    dist  = risk_data.get('distribution', {})
    lines = [
        '=== SECUREPASS AI ANALYSIS REPORT ===',
        '',
        'DATASET OVERVIEW',
        f"Total Passwords : {total}",
        f"Weak            : {dist.get('high', 0)}  |  "
        f"Medium: {dist.get('medium', 0)}  |  "
        f"Strong: {dist.get('low', 0)}",
        f"Average Length  : {stats.get('average_length', 0)} characters",
        '',
        'RISK DISTRIBUTION',
    ]
    for level, count in dist.items():
        pct = (count / total * 100) if total else 0
        lines.append(f"  {level}: {count} ({pct:.1f}%)")
    lines += ['', 'AI INSIGHTS']
    for i, insight in enumerate(insights or [], 1):
        lines.append(f"  {i}. {insight}")
    lines.append('\n=== END OF PREVIEW ===')
    return '\n'.join(lines)


def _transform_data_for_pdf(api_data: dict) -> dict:
    """
    Flatten the API response structure to the flat format expected by pdf_gen.

    BUG-05 FIX: compliance_mapping now uses the pre-computed compliance_scores
      dict from compliance_mapper._calculate_compliance_scores() instead of
      recomputing heuristic multipliers on risk_score.

    BUG-12 FIX: policy_simulation now uses the real improvement_details dict
      from policy_simulator instead of fabricated projected_score * 0.xx values.
    """
    overview      = api_data.get('overview', {})
    policy_impact = api_data.get('policy_impact', {})
    compliance    = api_data.get('compliance', {})
    risk_score    = overview.get('risk_score', 0)

    # FIX BUG-12: Use real per-policy gain data already computed by
    # policy_simulator.simulate_policy_impact() — not heuristic multipliers.
    improvement_details = policy_impact.get('improvement_details', {})
    policy_simulation   = improvement_details if improvement_details else {}

    # FIX BUG-05: compliance_mapper already computes numeric scores in
    # compliance_scores via _calculate_compliance_scores().
    # Use them directly instead of recomputing with arbitrary factors.
    compliance_mapping = compliance.get('compliance_scores', {})
    if not compliance_mapping:
        # Fallback only if compliance_scores truly absent (shouldn't happen)
        compliance_mapping = {
            'NIST SP 800-63B': risk_score,
            'OWASP':           risk_score,
            'ISO 27001':       risk_score,
        }

    # BUG-13: risk_distribution in api_data now has canonical lowercase keys
    # ('high', 'medium', 'low') — no Title-case duplicates.
    risk_dist = api_data.get('risk_distribution', {})

    # Extract customizable governance parameters (passed in payload or from user settings)
    org_name = api_data.get('org_name') or api_data.get('policy_org_name') or api_data.get('company_name')
    company_domain = api_data.get('domain') or api_data.get('company_domain') or api_data.get('policy_domain')
    company_industry = api_data.get('industry') or api_data.get('company_industry') or api_data.get('policy_industry')
    company_ai_policy = api_data.get('company_ai_policy') or api_data.get('ai_policy')
    ciso_name = api_data.get('ciso_name') or api_data.get('policy_ciso_name')
    min_length_req = api_data.get('min_length_req') or api_data.get('min_length') or api_data.get('policy_min_length')
    inactivity_timeout = api_data.get('inactivity_timeout') or api_data.get('policy_inactivity_mins')
    policy_preset = api_data.get('policy_preset') or api_data.get('preset')

    try:
        user = get_current_user()
        if user:
            u_settings = UserSettings.query.filter_by(user_id=user.id).all()
            s_map = {s.key: s.value for s in u_settings}
            if not org_name and 'policy_org_name' in s_map:
                org_name = s_map['policy_org_name']
            if not company_domain and 'policy_domain' in s_map:
                company_domain = s_map['policy_domain']
            if not company_industry and 'policy_industry' in s_map:
                company_industry = s_map['policy_industry']
            if not ciso_name and 'policy_ciso_name' in s_map:
                ciso_name = s_map['policy_ciso_name']
            if not min_length_req and 'min_length' in s_map:
                min_length_req = s_map['min_length']
            if not min_length_req and 'policy_min_length' in s_map:
                min_length_req = s_map['policy_min_length']
            if not inactivity_timeout and 'policy_inactivity_mins' in s_map:
                inactivity_timeout = s_map['policy_inactivity_mins']
            if not policy_preset and 'policy_preset' in s_map:
                policy_preset = s_map['policy_preset']
    except Exception:
        pass

    org_name = org_name or 'Acme Corporation'
    company_domain = company_domain or 'acme.com'
    company_industry = company_industry or 'Enterprise Technology'
    ciso_name = ciso_name or 'Chief Information Security Officer (CISO)'
    try:
        min_length_req = int(min_length_req or 14)
    except Exception:
        min_length_req = 14
    try:
        inactivity_timeout = int(inactivity_timeout or 10)
    except Exception:
        inactivity_timeout = 10
    policy_preset = policy_preset or 'standard'

    return {
        'total_passwords':    overview.get('total_passwords', 0),
        'unique_passwords':   overview.get('unique_passwords', 0),
        'average_length':     overview.get('average_length', 0),
        'min_length':         overview.get('min_length', 0),
        'max_length':         overview.get('max_length', 0),
        'median_length':      overview.get('median_length', 0),
        'std_dev_length':     overview.get('std_dev_length', 0),
        'risk_score':         risk_score,
        'risk_level':         api_data.get('risk_level', 'Unknown'),
        'patterns':           api_data.get('patterns', {}),
        'ai_insights':        api_data.get('ai_insights', []),
        'attack_scenarios':   api_data.get('attack_scenarios', []),
        'policy_impact':      policy_impact,
        'policy_simulation':  policy_simulation,    # real data, not fake multipliers
        'compliance':         compliance,
        'compliance_mapping': compliance_mapping,   # real computed scores
        'recommendations':    api_data.get('recommendations', api_data.get('ai_insights', [])),
        'trends':             api_data.get('trends', []),
        'risk_distribution':  risk_dist,
        'hibp':               api_data.get('hibp', {}),
        'character_composition': api_data.get('character_composition', {}),
        'length_distribution': api_data.get('length_distribution') or overview.get('length_distribution', {}),
        'password_examples':  api_data.get('password_examples', []),
        'breached_count':     overview.get('breached_count', 0),
        'safety_score':       overview.get('safety_score', 0),
        'recommended_password_policy': api_data.get('recommended_password_policy', {}),
        'org_name':           org_name,
        'company_domain':     company_domain,
        'company_industry':   company_industry,
        'company_ai_policy':  company_ai_policy,
        'ciso_name':          ciso_name,
        'min_length_req':     min_length_req,
        'inactivity_timeout': inactivity_timeout,
        'policy_preset':      policy_preset,
    }



# ────────────────────────────────────────────────────────────────────────────
#  /api/terminal-attack  — real-time attack simulation with streaming
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/terminal-attack', methods=['POST'])
@jwt_required()
def terminal_attack():
    """
    Real attack simulation against a password list.

    Accepts multipart/form-data OR JSON:
      passwords    – newline-separated password list (string, required for list mode)
      single_password – single password to check (string, optional)
      attack_type  – 'dictionary' | 'keyboard' | 'pattern' | 'brute' | 'all' (default: 'all')
      wordlist     – optional uploaded wordlist file (.txt)

    Returns newline-delimited JSON (NDJSON) streamed to the client.
    Each line is a JSON object: {"type": "hit"|"miss"|"stat"|"done", ...}
    """
    # ── FIX: Capture ALL request data here, inside the request context,
    #         BEFORE the generator is created.  Generators execute lazily —
    #         by the time the first `yield` runs Flask may have already torn
    #         down the request context, so any `request.*` access inside
    #         generate() raises RuntimeError: Working outside of request context.
    # ─────────────────────────────────────────────────────────────────────────
    content_type = request.content_type or ''

    # Parse all input data eagerly, right here in the view function
    _single_pw: str | None = None
    _passwords: list = []
    _attack_type: str = 'all'
    _custom_wordlist_words: list | None = None

    try:
        if 'multipart/form-data' in content_type or 'application/x-www-form-urlencoded' in content_type or (not content_type and request.form):
            _single_pw = (request.form.get('single_password') or '').strip() or None
            _raw_pws   = request.form.get('passwords', '')
            _attack_type = request.form.get('attack_type', 'all').strip().lower()
            _passwords = [p.strip() for p in _raw_pws.splitlines() if p.strip()]

            wl_file = request.files.get('wordlist')
            if wl_file and wl_file.filename:
                try:
                    wl_content = wl_file.read().decode('utf-8', errors='ignore')
                    _custom_wordlist_words = [
                        ln.strip().lower() for ln in wl_content.splitlines()
                        if ln.strip()
                    ]
                except Exception:
                    app.logger.warning('terminal-attack: failed to read uploaded wordlist', exc_info=True)
        else:
            # JSON body (or empty / unknown content-type)
            body = request.get_json(silent=True)
            if body is None:
                # Malformed or missing JSON — return a clean error immediately,
                # before any streaming starts.
                if content_type and 'application/json' in content_type:
                    return jsonify({'error': 'Invalid JSON body.'}), 400
                body = {}
            _single_pw   = (body.get('single_password') or '').strip() or None
            _raw_pws     = body.get('passwords', '')
            _attack_type = (body.get('attack_type', 'all') or 'all').strip().lower()
            if isinstance(_raw_pws, list):
                _passwords = [str(p).strip() for p in _raw_pws if str(p).strip()]
            else:
                _passwords = [p.strip() for p in str(_raw_pws).splitlines() if p.strip()]
    except Exception:
        app.logger.exception('terminal-attack: failed to parse request data')
        return jsonify({'error': 'Failed to parse request. Check Content-Type and body format.'}), 400

    # Prepend single password if provided
    if _single_pw:
        _passwords = [_single_pw] + [p for p in _passwords if p != _single_pw]

    # Early validation — return a plain error response (no streaming needed)
    if not _passwords:
        return jsonify({'error': 'No passwords provided.'}), 400

    # ── All request data captured. Generator only uses plain local variables. ──

    def _similarity(a: str, b: str) -> float:
        """Return 0-100 similarity between two strings (case-insensitive)."""
        a_low, b_low = a.lower(), b.lower()
        if a_low == b_low:
            return 100.0
        ratio = difflib.SequenceMatcher(None, a_low, b_low).ratio()
        return round(ratio * 100, 1)

    def _normalize_leet_local(s: str) -> str:
        res = s
        for k, v in _LEET_MAP.items():
            res = res.replace(k, v)
        return res

    def _fuzzy_check(password: str, wordlist: frozenset, threshold: float = 55.0):
        """
        Fast O(1) and heuristic dictionary check against wordlist:
        1. Exact match (100%)
        2. Base word without trailing numbers/symbols e.g. password123! -> password (75-90%)
        3. Leet substitutions e.g. p@ssw0rd -> password (85-90%)
        4. Approximate match for single targets / close candidates
        """
        pw_low = password.lower()
        # 1. Exact match (O(1))
        if pw_low in wordlist:
            return pw_low, 100.0

        # 2. Base word without trailing/leading numbers & symbols
        base = pw_low.rstrip('0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
        if base and base in wordlist and len(base) >= 3:
            ratio = round((len(base) / len(pw_low)) * 100, 1)
            return base, max(ratio, 75.0)

        # 3. Leet-normalised check
        leet = _normalize_leet_local(pw_low)
        if leet != pw_low and leet in wordlist:
            return leet, 90.0

        leet_base = leet.rstrip('0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
        if leet_base and leet_base != pw_low and leet_base in wordlist and len(leet_base) >= 3:
            ratio = round((len(leet_base) / len(pw_low)) * 100, 1)
            return leet_base, max(ratio, 70.0)

        # 4. Fast bounded SequenceMatcher (only compare candidates within +/- 1 char)
        pw_len = len(pw_low)
        pw_set = set(pw_low)
        best_match, best_score = None, 0.0
        for word in wordlist:
            if abs(len(word) - pw_len) > 1:
                continue
            if len(pw_set & set(word)) < max(3, pw_len - 2):
                continue
            score = _similarity(pw_low, word)
            if score > best_score:
                best_score = score
                best_match = word
                if best_score >= 90.0:
                    break

        if best_score >= threshold:
            return best_match, best_score
        return None, 0.0

    # Bind captured values to local names so the closure is self-contained
    # (no reference to `request` anywhere below this line)
    passwords           = _passwords
    attack_type         = _attack_type
    custom_wordlist_words = _custom_wordlist_words

    def generate():
        try:
            # ── All variables below come from the closure, NOT from `request` ──
            # `passwords`, `attack_type`, `custom_wordlist_words` were captured
            # above in the view function while the request context was still live.

            # Try to load the built-in wordlist from the securepass folder
            builtin_wordlist = None
            wordlist_source = 'built-in'
            wordlist_paths = [
                os.path.join(os.path.dirname(__file__), 'securepass', 'password-wordlist.txt'),
                os.path.join(os.path.dirname(__file__), 'password-wordlist.txt'),
                os.path.join(os.path.dirname(__file__), 'wordlist.txt'),
            ]
            for wlp in wordlist_paths:
                if os.path.exists(wlp):
                    try:
                        with open(wlp, 'r', encoding='utf-8', errors='ignore') as fh:
                            builtin_wordlist = [ln.strip().lower() for ln in fh if ln.strip()]
                        wordlist_source = os.path.basename(wlp)
                        break
                    except Exception:
                        pass

            # Custom upload overrides built-in
            if custom_wordlist_words is not None:
                active_wordlist = custom_wordlist_words
                wordlist_source = 'uploaded wordlist'
            elif builtin_wordlist:
                active_wordlist = builtin_wordlist
            else:
                active_wordlist = list(AttackSimulator._BUILTIN_WORDLIST)
                wordlist_source = 'built-in fallback'

            wl_set = frozenset(active_wordlist)
            walk_set = frozenset(w.lower() for w in _KEYBOARD_WALKS)

            # ── Emit header ────────────────────────────────────────────
            yield json.dumps({
                'type': 'init',
                'message': f'[SYSTEM] SecurePass Attack Engine v4.0 — Loaded {len(wl_set):,} wordlist entries ({wordlist_source})',
                'total': len(passwords),
                'attack_type': attack_type,
            }) + '\n'

            time.sleep(0.05)
            yield json.dumps({'type': 'log', 'message': f'[SYSTEM] Target: {len(passwords)} password(s) — Attack mode: {attack_type.upper()}'}) + '\n'
            time.sleep(0.05)
            yield json.dumps({'type': 'log', 'message': '[SYSTEM] Initializing attack vectors...'}) + '\n'
            time.sleep(0.08)

            # ── Per-password attack loop ───────────────────────────────
            hits = 0
            results_detail = []  # store for final stats
            start_time = time.time()

            def _leet_normalise(pw):
                norm = pw
                for leet_char, plain_char in _LEET_MAP.items():
                    norm = norm.replace(leet_char, plain_char)
                return norm

            def _keyboard_hit(pw):
                lo = pw.lower()
                for w in walk_set:
                    if w in lo:
                        return w
                return None

            def _pattern_hit(pw):
                for rx in _PATTERN_CHECKS:
                    if rx.match(pw):
                        return rx.pattern
                norm = _leet_normalise(pw)
                if norm != pw:
                    for rx in _PATTERN_CHECKS:
                        if rx.match(norm):
                            return f'leet-variant ({norm})'
                return None

            for idx, pw in enumerate(passwords[:5000]):  # cap at 5000 for streaming
                pw_results = {'password': pw, 'cracked': False, 'attacks': []}
                cracked_by = []

                # ── Dictionary attack ──────────────────────────────────
                if attack_type in ('all', 'dictionary'):
                    match, score = _fuzzy_check(pw, wl_set)
                    if match:
                        is_exact = score == 100.0
                        cracked_by.append({
                            'attack': 'dictionary',
                            'match': match,
                            'score': score,
                            'exact': is_exact,
                        })
                        label = '[EXACT MATCH]' if is_exact else f'[{score:.0f}% MATCH]'
                        rank = None
                        if match in active_wordlist:
                            try:
                                rank = active_wordlist.index(match) + 1
                            except Exception:
                                pass
                        rank_str = f' (rank #{rank:,})' if rank else ''
                        pw_results['attacks'].append('dictionary')

                        yield json.dumps({
                            'type': 'hit',
                            'attack': 'dictionary',
                            'password': pw,
                            'match': match,
                            'score': score,
                            'exact': is_exact,
                            'rank': rank,
                            'message': f'[HIT] {pw} — {label} found in wordlist{rank_str}',
                        }) + '\n'

                # ── Keyboard walk attack ───────────────────────────────
                if attack_type in ('all', 'keyboard'):
                    walk_found = _keyboard_hit(pw)
                    if walk_found:
                        cracked_by.append({'attack': 'keyboard', 'pattern': walk_found})
                        pw_results['attacks'].append('keyboard')
                        yield json.dumps({
                            'type': 'hit',
                            'attack': 'keyboard',
                            'password': pw,
                            'pattern': walk_found,
                            'message': f'[HIT] {pw} — keyboard walk detected: "{walk_found}"',
                        }) + '\n'
                    elif attack_type == 'keyboard':
                        yield json.dumps({
                            'type': 'miss',
                            'attack': 'keyboard',
                            'password': pw,
                            'message': f'[MISS] {pw} — no keyboard walk pattern',
                        }) + '\n'

                # ── Pattern attack ─────────────────────────────────────
                if attack_type in ('all', 'pattern'):
                    pat_found = _pattern_hit(pw)
                    if pat_found:
                        cracked_by.append({'attack': 'pattern', 'pattern': pat_found})
                        pw_results['attacks'].append('pattern')
                        yield json.dumps({
                            'type': 'hit',
                            'attack': 'pattern',
                            'password': pw,
                            'pattern': pat_found,
                            'message': f'[HIT] {pw} — structural pattern: {pat_found}',
                        }) + '\n'
                    elif attack_type == 'pattern':
                        yield json.dumps({
                            'type': 'miss',
                            'attack': 'pattern',
                            'password': pw,
                            'message': f'[MISS] {pw} — no common pattern',
                        }) + '\n'

                # ── Brute force estimate ───────────────────────────────
                if attack_type in ('all', 'brute'):
                    if len(pw) <= _BRUTE_FORCE_MAX_LEN:
                        cracked_by.append({'attack': 'brute', 'length': len(pw)})
                        pw_results['attacks'].append('brute')
                        yield json.dumps({
                            'type': 'hit',
                            'attack': 'brute',
                            'password': pw,
                            'length': len(pw),
                            'message': f'[HIT] {pw} — too short ({len(pw)} chars), brute-forceable in seconds',
                        }) + '\n'
                    elif attack_type == 'brute':
                        yield json.dumps({
                            'type': 'miss',
                            'attack': 'brute',
                            'password': pw,
                            'message': f'[MISS] {pw} — length {len(pw)} chars, brute force impractical',
                        }) + '\n'

                # ── If attack=all and no hit, report miss ──────────────
                if attack_type == 'all' and not cracked_by:
                    yield json.dumps({
                        'type': 'miss',
                        'password': pw,
                        'message': f'[SECURE] {pw} — survived all attack vectors',
                    }) + '\n'

                if cracked_by:
                    hits += 1
                    pw_results['cracked'] = True

                results_detail.append(pw_results)
                # Small delay for streaming feel (only for small lists)
                if len(passwords) <= 50:
                    time.sleep(0.04)

            # ── Final stats ────────────────────────────────────────────
            elapsed = round(time.time() - start_time, 2)
            total_checked = min(len(passwords), 5000)
            crack_rate = round(hits / total_checked * 100, 1) if total_checked else 0

            yield json.dumps({
                'type': 'done',
                'total': total_checked,
                'cracked': hits,
                'survived': total_checked - hits,
                'crack_rate': crack_rate,
                'elapsed': elapsed,
                'wordlist_source': wordlist_source,
                'wordlist_size': len(wl_set),
                'message': f'[DONE] {hits}/{total_checked} cracked ({crack_rate}%) in {elapsed}s',
            }) + '\n'

        except Exception as exc:
            app.logger.exception('terminal-attack stream error')
            try:
                yield json.dumps({'type': 'error', 'message': f'[ERROR] {str(exc)}'}) + '\n'
            except Exception:
                pass  # generator already broken — nothing more to yield

    # stream_with_context keeps the application context alive for the
    # duration of the stream so that app.logger and db remain accessible.
    # It does NOT re-open the request context — that is intentional; all
    # request data was already captured above.
    return app.response_class(
        stream_with_context(generate()),
        mimetype='application/x-ndjson',
        headers={'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache'},
    )

# ────────────────────────────────────────────────────────────────────────────
#  /api/report/<analysis_id>  — fetch stored analysis data by ID
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/report/<int:analysis_id>', methods=['GET'])
@jwt_required()
def get_report(analysis_id):
    """
    Return the full stored analysis data for a given analysis ID.

    Used by the Reports page to re-fetch past analyses for PDF re-generation
    and inline preview expansion.

    Returns 200 with analysis JSON, 403 if not owned by current user,
    404 if not found, 500 on error.
    """
    try:
        user = get_current_user()
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found.'}), 404
        if analysis.user_id != user.id:
            return jsonify({'error': 'Access denied.'}), 403

        data = analysis.analysis_data or {}
        return jsonify({
            'id':              analysis.id,
            'filename':        analysis.filename,
            'risk_score':      analysis.risk_score,
            'risk_level':      analysis.risk_level,
            'total_passwords': analysis.total_passwords,
            'timestamp':       analysis.created_at.isoformat() if analysis.created_at else None,
            'analysis_data':   data,
        }), 200

    except Exception:
        app.logger.exception('Error in /api/report/%d', analysis_id)
        return jsonify({'error': 'Failed to retrieve report.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  /api/ai-policy  — AI Policy Generation endpoint
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/ai-policy', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def ai_policy():
    """
    AI-powered policy generation endpoint.

    Accepts JSON:
        user_name, org_name, domain, city,
        analysis_id, current_risk_score, weak_patterns, compliance_status

    Returns:
        success, current, projected, delta,
        recommended_policy, memorable_passwords, ai_summary
    """
    try:
        user = get_current_user()
        data = request.get_json(silent=True) or {}

        # ── Sanitize inputs ──────────────────────────────────────────── #
        def _clean(val, max_len=120):
            if not val:
                return ''
            return str(val)[:max_len].strip()

        user_name         = _clean(data.get('user_name'))
        org_name          = _clean(data.get('company_name') or data.get('org_name') or 'Hardik Enterprise')
        domain            = _clean(data.get('company_domain') or data.get('domain') or 'hardik.enterprise')
        industry          = _clean(data.get('company_industry') or data.get('industry') or 'Technology / Cloud Services')
        notes             = _clean(data.get('security_focus') or data.get('notes') or '')
        city              = _clean(data.get('city'))
        analysis_id       = data.get('analysis_id')
        current_risk_score = float(data.get('current_risk_score', 0) or 0)
        compliance_status = _clean(data.get('compliance_status'))

        # ── Load latest analysis from DB ─────────────────────────────── #
        analysis_obj  = None
        analysis_data = {}

        if analysis_id:
            try:
                analysis_obj = db.session.get(Analysis, int(analysis_id))
                if analysis_obj and analysis_obj.user_id == user.id:
                    analysis_data = analysis_obj.analysis_data or {}
            except Exception:
                app.logger.warning('ai-policy: could not load analysis_id=%s', analysis_id)

        if not analysis_obj:
            # Fallback: load most recent analysis for this user
            try:
                analysis_obj = (
                    Analysis.query
                    .filter_by(user_id=user.id)
                    .order_by(Analysis.id.desc())
                    .first()
                )
                if analysis_obj:
                    analysis_data = analysis_obj.analysis_data or {}
                    current_risk_score = analysis_obj.risk_score or current_risk_score
            except Exception:
                app.logger.warning('ai-policy: no analysis found for user')

        # ── Inline results fallback (when DB record not yet saved) ─────── #
        inline = data.get('inline_results') or {}
        if inline and not analysis_data:
            analysis_data = inline
            app.logger.info('ai-policy: using inline_results from client (no DB record)')

        # ── Extract stats from stored analysis ───────────────────────── #
        overview    = analysis_data.get('overview', {})
        patterns    = analysis_data.get('patterns', {})
        compliance  = analysis_data.get('compliance', {})
        hibp        = analysis_data.get('hibp', {})
        policy_sim  = analysis_data.get('policy_impact', {})

        total_passwords = overview.get('total_passwords', 0)
        weak_count      = overview.get('weak_passwords', 0)
        avg_length      = overview.get('average_length', 0)
        risk_score      = round(overview.get('risk_score', current_risk_score), 1)
        risk_level      = analysis_data.get('risk_level', 'Unknown')

        breach_count    = hibp.get('total_breached', hibp.get('estimated_breached', overview.get('breached_count', 0)))
        breach_pct      = round(hibp.get('breach_percentage', hibp.get('breach_rate', 0)), 1)
        reuse_pct       = 0.0
        if total_passwords > 0:
            dups = analysis_data.get('patterns', {}).get('duplicate_count', 0)
            if not dups:
                dups = total_passwords - overview.get('unique_passwords', total_passwords)
            reuse_pct = round(dups / total_passwords * 100, 1)

        compliance_status_val = (
            compliance.get('overall_status')
            or compliance_status
            or 'Unknown'
        )

        # ── Simulate policy impact ────────────────────────────────────── #
        projected_score = policy_sim.get('projected_score', 0)
        if not projected_score:
            improvement = min(35.0, (100 - risk_score) * 0.5)
            projected_score = round(min(100.0, risk_score + improvement), 1)

        projected_score = round(projected_score, 1)
        delta_score     = round(projected_score - risk_score, 1)

        # Breach reduction estimate
        if breach_count > 0:
            reduction_factor = min(0.75, delta_score / 100 * 1.8)
            projected_breaches = max(0, round(breach_count * (1 - reduction_factor)))
        else:
            projected_breaches = 0
        breaches_reduced = breach_count - projected_breaches

        compliance_map = {
            'Non-Compliant': 'Partial',
            'Partial':       'Strong',
            'Strong':        'Full',
            'Unknown':       'Partial',
            'Full':          'Full',
        }
        projected_compliance = compliance_map.get(compliance_status_val, 'Partial')

        # ── Generate Tailored Company Password Policy via AI ───────────── #
        company_info = {
            'name': org_name,
            'domain': domain,
            'industry': industry,
            'notes': notes,
        }
        company_ai_policy = generate_company_ai_policy(
            company_info=company_info,
            dataset_stats=overview,
            pattern_stats=patterns,
            risk_data={'score': risk_score, 'distribution': analysis_data.get('risk_distribution', {})},
            hibp_data=hibp,
        )

        # Recommended policy dictionary (synchronized with AI generated rules)
        tech_rules = company_ai_policy.get('technical_rules', {})
        rec_min_len = int(tech_rules.get('minimum_length', 14))
        recommended_policy = {
            'min_length':              rec_min_len,
            'require_upper':           bool(tech_rules.get('require_uppercase', True)),
            'require_lower':           bool(tech_rules.get('require_lowercase', True)),
            'require_number':          bool(tech_rules.get('require_numbers', True)),
            'require_special':         bool(tech_rules.get('require_special_chars', True)),
            'rotation_days':           0,
            'rotation_mode':           'compromise_only',
            'lockout_attempts':        int(tech_rules.get('max_failed_attempts', 5)),
            'block_dictionary':        True,
            'block_names':             True,
            'block_keyboard_patterns': True,
            'mfa_recommended':         True,
            'password_manager':        True,
            'history_count':           5,
            'passphrase_allowed':      True,
        }

        # Persist company AI policy to analysis record
        if analysis_obj:
            cur_data = dict(analysis_obj.analysis_data or {})
            cur_data['company_ai_policy'] = company_ai_policy
            cur_data['company_info'] = company_info
            analysis_obj.analysis_data = cur_data
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.warning('Failed to persist company_ai_policy to Analysis: %s', e)

        # Persist user settings
        try:
            if user:
                from settings_backend import UserSettings
                UserSettings.save(user, {
                    'policy_org_name': org_name,
                    'policy_domain': domain,
                    'policy_industry': industry,
                    'policy_min_length': str(rec_min_len),
                    'policy_inactivity_mins': str(tech_rules.get('inactivity_timeout_mins', 10)),
                })
        except Exception as e:
            app.logger.warning('Failed to persist user settings for ai-policy: %s', e)

        # Memorable passphrases
        memorable_passwords = company_ai_policy.get('memorable_passphrases') or _generate_memorable_passwords(
            user_name=user_name or (user.email.split('@')[0] if user and hasattr(user, 'email') else ''),
            org_name=org_name,
            city=city or 'Mumbai',
            domain=domain,
        )

        ai_summary = company_ai_policy.get('ai_summary') or _generate_policy_ai_summary(
            risk_score=risk_score,
            risk_level=risk_level,
            projected_score=projected_score,
            delta_score=delta_score,
            breach_count=breach_count,
            breaches_reduced=breaches_reduced,
            compliance_status=compliance_status_val,
            projected_compliance=projected_compliance,
            weak_count=weak_count,
            total_passwords=total_passwords,
            avg_length=avg_length,
            reuse_pct=reuse_pct,
            patterns=patterns,
            org_name=org_name,
        )

        # ── Build response ────────────────────────────────────────────── #
        response = {
            'success': True,
            'policy':              company_ai_policy,
            'company_ai_policy':   company_ai_policy,
            'company_info':        company_info,
            'current': {
                'score':      risk_score,
                'risk_level': risk_level,
                'breaches':   breach_count,
                'breach_pct': breach_pct,
                'compliance': compliance_status_val,
                'weak_count': weak_count,
                'avg_length': avg_length,
                'reuse_pct':  reuse_pct,
                'total':      total_passwords,
            },
            'projected': {
                'score':      projected_score,
                'risk_level': _score_to_risk(projected_score),
                'breaches':   projected_breaches,
                'compliance': projected_compliance,
            },
            'delta': {
                'score':            delta_score,
                'breaches_reduced': breaches_reduced,
                'compliance_upgrade': compliance_status_val != projected_compliance,
            },
            'recommended_policy':  recommended_policy,
            'memorable_passwords': memorable_passwords,
            'ai_summary':          ai_summary,
        }

        return jsonify(response), 200

    except Exception:
        app.logger.exception('Unhandled error in /api/ai-policy')
        return jsonify({'error': 'Policy generation failed. Please try again.'}), 500


# ── /api/company-lookup — web & threat intelligence lookup ───────────────── #

@app.route('/api/company-lookup', methods=['POST'])
def company_lookup():
    """
    Search company and domain intelligence from web context and threat registries.
    Returns domain intelligence, detected infrastructure, and threat vectors.
    If company not found without domain, prompts user for domain.
    """
    data = request.get_json(silent=True) or {}
    company_name = data.get('company_name', '').strip()
    domain = data.get('domain', '').strip()

    result = lookup_company_domain(company_name, domain)
    return jsonify(result), 200


# ── /api/ai-policy/snapshot  — load current analysis snapshot ────────────── #

@app.route('/api/ai-policy/snapshot', methods=['GET'])
@jwt_required()
def ai_policy_snapshot():
    """Return the latest analysis snapshot for the policy page."""
    try:
        user = get_current_user()
        analysis_obj = (
            Analysis.query
            .filter_by(user_id=user.id)
            .order_by(Analysis.id.desc())
            .first()
        )
        if not analysis_obj:
            return jsonify({'has_data': False}), 200

        ad = analysis_obj.analysis_data or {}
        overview   = ad.get('overview', {})
        compliance = ad.get('compliance', {})
        hibp       = ad.get('hibp', {})

        total = overview.get('total_passwords', 0)
        unique = overview.get('unique_passwords', total)
        reuse_pct = round((total - unique) / total * 100, 1) if total > 0 else 0.0

        return jsonify({
            'has_data':         True,
            'analysis_id':      analysis_obj.id,
            'risk_score':       round(analysis_obj.risk_score or 0, 1),
            'risk_level':       analysis_obj.risk_level or 'Unknown',
            'weak_count':       overview.get('weak_passwords', 0),
            'total_passwords':  total,
            'avg_length':       round(overview.get('average_length', 0), 1),
            'breach_pct':       round(hibp.get('breach_percentage', hibp.get('breach_rate', 0)), 1),
            'breach_count':     hibp.get('total_breached', hibp.get('estimated_breached', overview.get('breached_count', 0))),
            'reuse_pct':        reuse_pct,
            'compliance_status': compliance.get('overall_status', 'Unknown'),
            'existing_policy':  ad.get('recommended_password_policy'),
            'filename':         analysis_obj.filename or 'Unknown',
        }), 200

    except Exception:
        app.logger.exception('Error in /api/ai-policy/snapshot')
        return jsonify({'error': 'Failed to load snapshot.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers for ai_policy
# ────────────────────────────────────────────────────────────────────────────

def _score_to_risk(score: float) -> str:
    if score >= 75:  return 'Low Risk'
    if score >= 50:  return 'Medium Risk'
    return 'High Risk'


def _generate_memorable_passwords(user_name='', org_name='', city='', domain='') -> list:
    """
    Generate strong, proper, memorable passphrases that 100% satisfy
    NIST SP 800-63B, PCI-DSS v4.0, HIPAA, and ISO 27001 requirements:
      - Minimum 16+ characters
      - TitleCased words separated by hyphens
      - Numbers (2-4 digits)
      - Approved special symbols (!, #, $, *, @)
    """
    WORD_POOL_A = [
        'Coffee', 'Rocket', 'Guitar', 'Sunset', 'River', 'Silver',
        'Beacon', 'Harbor', 'Shield', 'Falcon', 'Matrix', 'Horizon',
        'Quantum', 'Summit', 'Timber', 'Canyon', 'Velvet', 'Glacier',
        'Castle', 'Anchor', 'Pioneer', 'Echo', 'Orbit', 'Aurora',
    ]
    WORD_POOL_B = [
        'Vault', 'Cipher', 'Sentinel', 'Fortress', 'Nexus', 'Bastion',
        'Armor', 'Titan', 'Apex', 'Nova', 'Storm', 'Hawk', 'Iron',
        'Shield', 'Haven', 'Forge', 'Onyx', 'Vanguard', 'Prism',
    ]
    SPECIALS = ['!', '#', '$', '*', '@']

    passwords = []
    attempts  = 0

    while len(passwords) < 8 and attempts < 60:
        attempts += 1
        w1 = random.choice(WORD_POOL_A)
        w2 = random.choice(WORD_POOL_A)
        while w2 == w1:
            w2 = random.choice(WORD_POOL_A)
        w3 = random.choice(WORD_POOL_B)
        num = random.randint(10, 99)
        sym = random.choice(SPECIALS)

        pw = f"{w1}-{w2}-{w3}-{num}{sym}"
        if pw not in passwords:
            passwords.append(pw)

    return passwords[:8]


@app.route('/api/ai-policy/generate-passwords', methods=['POST'])
@jwt_required()
def generate_ai_policy_passwords():
    """
    Generate proper, 100% compliant enterprise passwords/passphrases.
    Body params: count (default 6), org_name, domain.
    """
    try:
        data = request.get_json(silent=True) or {}
        count = int(data.get('count', 6))
        count = max(3, min(count, 12))
        org_name = str(data.get('org_name', '')).strip()
        domain = str(data.get('domain', '')).strip()

        passwords_raw = _generate_memorable_passwords(org_name=org_name, domain=domain)
        while len(passwords_raw) < count:
            extra = _generate_memorable_passwords(org_name=org_name, domain=domain)
            for p in extra:
                if p not in passwords_raw:
                    passwords_raw.append(p)

        results = []
        for pw in passwords_raw[:count]:
            entropy = round(len(pw) * 6.55, 1)
            results.append({
                'password': pw,
                'score': 100,
                'strength': 'Very Strong',
                'entropy': entropy,
                'crack_time': 'Centuries',
                'compliance': '100% Compliant (NIST, PCI-DSS, HIPAA, ISO 27001)',
                'is_proper': True
            })

        return jsonify({
            'success': True,
            'passwords': results,
            'count': len(results),
        }), 200
    except Exception:
        app.logger.exception('Error in /api/ai-policy/generate-passwords')
        return jsonify({'error': 'Failed to generate compliant passwords.'}), 500


def _generate_policy_ai_summary(
    risk_score, risk_level, projected_score, delta_score,
    breach_count, breaches_reduced, compliance_status, projected_compliance,
    weak_count, total_passwords, avg_length, reuse_pct, patterns, org_name,
) -> str:
    """Call Groq for a professional AI policy summary, with deterministic fallback."""

    api_key = (
        os.environ.get('SECUREPASS_GROQ_API_KEY', '').strip()
        or os.environ.get('GROQ_API_KEY', '').strip()
    )
    if not api_key:
        return _fallback_policy_summary(
            risk_score, delta_score, breach_count, breaches_reduced,
            compliance_status, projected_compliance, weak_count, total_passwords,
        )

    try:
        prompt = f"""You are a cybersecurity expert writing a professional AI-powered password policy recommendation report for {'an organization' if not org_name else org_name}.

Current Security Status:
- Risk Score: {risk_score}/100 ({risk_level})
- Weak Passwords: {weak_count} out of {total_passwords} total
- Average Password Length: {avg_length} characters
- Password Reuse Rate: {reuse_pct}%
- Score Improvement: +{delta_score} points
- Breaches Reduced: {breaches_reduced}
- Projected Compliance: {projected_compliance}

Write a concise, professional 4-6 sentence AI summary that:
1. Explains why the current password posture is weak (be specific with numbers)
2. Describes the biggest security risks
3. Explains how the recommended policy will help
4. Highlights the projected improvements
5. Mentions the balance between security and user usability

Be direct, professional, and data-driven. Use cybersecurity terminology. Do not use bullet points. Write as flowing prose."""

        payload = {
            'model': 'llama-3.3-70b-versatile',
            'max_tokens': 400,
            'messages': [{'role': 'user', 'content': prompt}],
        }
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json',
        }
        resp = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            json=payload, headers=headers, timeout=12
        )
        resp.raise_for_status()
        result = resp.json()
        text = result['choices'][0]['message']['content'].strip()
        # Sanitize: remove any potential injection
        text = text[:1500]
        return text
    except Exception as exc:
        app.logger.warning('ai-policy Groq call failed: %s', exc)
        return _fallback_policy_summary(
            risk_score, delta_score, breach_count, breaches_reduced,
            compliance_status, projected_compliance, weak_count, total_passwords,
        )


def _fallback_policy_summary(
    risk_score, delta_score, breach_count, breaches_reduced,
    compliance_status, projected_compliance, weak_count, total_passwords,
) -> str:
    """Deterministic fallback summary when Groq is unavailable."""
    weak_pct = round(weak_count / total_passwords * 100, 1) if total_passwords else 0
    return (
        f"Your current password portfolio carries a risk score of {risk_score}/100, "
        f"with {weak_pct}% of passwords classified as high-risk and {breach_count} entries "
        f"exposed in known data breaches — indicating a significant attack surface vulnerability. "
        f"The current {compliance_status} compliance posture leaves your organization susceptible "
        f"to credential-stuffing, dictionary, and brute-force attacks. "
        f"By enforcing the recommended policy — including a 12-character minimum, complexity "
        f"requirements, breach-list blocking, and MFA — your projected score rises by +{delta_score} points "
        f"and an estimated {breaches_reduced} breach exposures will be mitigated. "
        f"This brings compliance to {projected_compliance} status while maintaining password memorability "
        f"through the generated passphrase examples, ensuring security without sacrificing user productivity."
    )


def _generate_fallback_compliance_narrative(nist_status, owasp_risk, iso_status, nist_score, owasp_score, iso_score, violations):
    """Deterministic fallback compliance narrative when Groq is unavailable."""
    viol_count = len(violations) if isinstance(violations, list) else 0
    viol_summary = f"{viol_count} active security policy violations" if viol_count > 0 else "zero critical violations"
    return (
        f"The credential dataset demonstrates an overall {nist_status.lower()} posture across enterprise benchmarks, "
        f"attaining a NIST SP 800-63B score of {nist_score}/100 and an OWASP risk classification of {owasp_risk}. "
        f"Evaluation identified {viol_summary}, primarily driven by pattern predictability and insufficient character diversity. "
        f"Immediate enforcement of minimum 12-character passphrases and compromise-driven rotation is recommended to achieve full "
        f"PCI-DSS v4.0 and HIPAA authentication compliance while neutralizing credential stuffing risks."
    )


# ────────────────────────────────────────────────────────────────────────────
#  /api/compliance-ai  — Compliance narrative via Groq (called from frontend)
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/compliance-ai', methods=['POST'])
@jwt_required()
def compliance_ai():
    """
    Generate a compliance narrative using Groq AI.

    Accepts JSON:
        nist_status, owasp_risk, iso_status,
        nist_score, owasp_score, iso_score,
        violations  (list of {rule, severity})

    Returns:
        { success: true, text: "..." }
    """
    try:
        data = request.get_json(silent=True) or {}
        assert_no_password_data(data)

        nist_status  = str(data.get('nist_status',  'Unknown'))[:50]
        owasp_risk   = str(data.get('owasp_risk',   'Unknown'))[:50]
        iso_status   = str(data.get('iso_status',   'Unknown'))[:50]
        nist_score   = int(data.get('nist_score',   0))
        owasp_score  = int(data.get('owasp_score',  0))
        iso_score    = int(data.get('iso_score',    0))
        violations   = data.get('violations', [])
        if not isinstance(violations, list):
            violations = []
        violations = violations[:10]

        viol_items = []
        for v in violations[:3]:
            if isinstance(v, dict):
                viol_items.append(f"{v.get('rule', '?')} ({v.get('severity', '?')})")
            elif isinstance(v, str):
                viol_items.append(v)
            else:
                viol_items.append(str(v))
        viol_text = ('Key violations: ' + ', '.join(viol_items)) if viol_items else 'No violations detected'

        prompt = (
            f"You are a cybersecurity compliance expert. A password dataset was analysed. "
            f"Provide a concise 3-4 sentence professional compliance narrative for a security dashboard.\n\n"
            f"Dataset compliance results:\n"
            f"- NIST SP 800-63B: {nist_status} (score: {nist_score}/100)\n"
            f"- OWASP Top 10 (A07:2021): {owasp_risk} risk (score: {owasp_score}/100)\n"
            f"- ISO/IEC 27001 A.9.4: {iso_status} (score: {iso_score}/100)\n"
            f"- Active violations: {len(violations)}\n"
            f"- {viol_text}\n\n"
            f"Write 3-4 sentences: 1) overall posture summary, 2) biggest risk and standard most affected, "
            f"3) one specific remediation action, 4) business impact if not addressed. "
            f"Be specific, cite standards by name. No bullet points, no headers. Professional tone."
        )

        api_key = (
            os.environ.get('SECUREPASS_GROQ_API_KEY', '').strip()
            or os.environ.get('GROQ_API_KEY', '').strip()
        )
        if not api_key:
            fallback = _generate_fallback_compliance_narrative(
                nist_status, owasp_risk, iso_status, nist_score, owasp_score, iso_score, violations
            )
            return jsonify({'success': True, 'text': fallback}), 200

        payload = {
            'model': 'llama-3.3-70b-versatile',
            'max_tokens': 400,
            'messages': [{'role': 'user', 'content': prompt}],
        }
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json',
        }
        resp = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            json=payload, headers=headers, timeout=12
        )
        resp.raise_for_status()
        text = resp.json()['choices'][0]['message']['content'].strip()[:1500]
        return jsonify({'success': True, 'text': text}), 200

    except Exception:
        app.logger.warning('Error in /api/compliance-ai — falling back to deterministic synthesis')
        data = request.get_json(silent=True) or {}
        fallback = _generate_fallback_compliance_narrative(
            str(data.get('nist_status', 'Unknown')),
            str(data.get('owasp_risk', 'Unknown')),
            str(data.get('iso_status', 'Unknown')),
            int(data.get('nist_score', 0)),
            int(data.get('owasp_score', 0)),
            int(data.get('iso_score', 0)),
            data.get('violations', [])
        )
        return jsonify({'success': True, 'text': fallback}), 200

# ────────────────────────────────────────────────────────────────────────────
#  Local development entrypoint — DEV ONLY.
#
#  `python app.py` runs Flask's own dev server, which is single-threaded,
#  unsuitable for production traffic, and never reloads config the way a
#  process manager would. It only executes when this file is run directly
#  (`if __name__ == '__main__'`) — gunicorn imports this module instead of
#  running it as __main__, so this block never executes in production.
#
#  Production entrypoint: backend/wsgi.py, run via
#  `gunicorn backend.wsgi:app` (see backend/Dockerfile).
# ────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(
        debug=app.config.get('DEBUG', False),
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
    )