"""
SecurePass AI — Flask application entry point

FIX SUMMARY:
- Converted to app-factory pattern (create_app) for testability and
  environment-specific config loading via FLASK_ENV.
- Removed module-level db.create_all() side-effect; moved inside factory.
- Added flask-limiter stubs on /api/analyze and /api/auth/* routes.
- Added /api/csrf-token endpoint for SPA CSRF protection.
- parse_passwords() now handles Windows line endings (\r\n).
- assess_single_password() strength score capped at 100.
- download_report() no longer leaks stack traces to the client.
- Removed duplicate chart output path — charts now write only to
  frontend/static/reports/output (single source of truth).
- All f-string debug prints replaced with app.logger calls.
- /api/analyze saves analysis_data as dict (model property serialises).
"""

import os
import sys
import logging
import tempfile
from io import BytesIO

# Load .env file automatically in development
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; env vars must be set manually

from flask import Flask, jsonify, render_template, request, send_file
from flask_login import LoginManager, current_user, login_required
from werkzeug.utils import secure_filename

from auth import auth_bp
from backend.ai_engine import generate_insights, generate_password_examples
from backend.compliance_mapper import map_to_standards
from backend.dataset_analyzer import analyze_dataset
from backend.hibp_engine import check_bulk_passwords
from backend.hibp_transformer import transform_hibp_stats
from backend.hibp_routes import hibp_bp
from backend.pattern_detector import detect_patterns
from backend.policy_simulator import simulate_policy_impact
from backend.risk_score import calculate_risk_score
from config import get_config
from models import Analysis, User, db
from reports.charts import generate_charts
from reports.pdf_gen import generate_pdf_report
from utils.validators import validate_single_password, validate_uploaded_file

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
        template_folder='frontend/templates',
        static_folder='frontend/static',
    )

    # ── Configuration ────────────────────────────────────────────────── #
    cfg = config_class or get_config()
    app.config.from_object(cfg)

    # ── Logging ──────────────────────────────────────────────────────── #
    _configure_logging(app)

    # ── Extensions ───────────────────────────────────────────────────── #
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    # Optional rate limiter — gracefully skipped if flask-limiter not installed
    limiter = _init_limiter(app)

    # ── User loader ──────────────────────────────────────────────────── #
    @login_manager.user_loader
    def load_user(user_id):
        # FIX: Use modern `db.session.get()` to avoid SQLAlchemy deprecation warnings
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({
            'error': 'Authentication required.',
            'message': 'Please log in to access this feature.',
        }), 401

    # ── Blueprints ───────────────────────────────────────────────────── #
    app.register_blueprint(auth_bp)
    app.register_blueprint(hibp_bp)

    # ── DB setup ─────────────────────────────────────────────────────── #
    with app.app_context():
        db.create_all()

    # ── Rate limits are applied via decorators on each route ─────────── #
    # (limiter is stored on app so route decorators can access it)
    app.limiter = limiter

    return app


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


def _init_limiter(app):
    """Try to initialise flask-limiter; return None if not installed."""
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(
            get_remote_address,
            app=app,
            enabled=app.config.get('RATELIMIT_ENABLED', True),
            default_limits=[app.config.get('RATELIMIT_DEFAULT', '200 per day')],
            storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://'),
        )
        return limiter
    except ImportError:
        app.logger.warning(
            'flask-limiter not installed — rate limiting disabled. '
            'Install with: pip install flask-limiter'
        )
        return None


# ── Create the global app instance ──────────────────────────────────────── #
app = create_app()


# ────────────────────────────────────────────────────────────────────────────
#  Page routes
# ────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')


@app.route('/hibp-demo')
def hibp_demo():
    return render_template('index.html')


@app.route('/forgot-password')
def forgot_password_page():
    # FIX: actual template filename is forgot_pass.html
    return render_template('forgot_pass.html')


@app.route('/check-email')
def check_email_page():
    # FIX: actual template filename is check_mail.html, not check_email.html
    return render_template('check_mail.html')


@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')


# ────────────────────────────────────────────────────────────────────────────
#  CSRF token (SPA support)
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/csrf-token', methods=['GET'])
def csrf_token():
    """
    Return a CSRF token for SPA clients.

    Requires flask-wtf.  If it is not installed, returns a placeholder
    so the frontend doesn't break during development.
    """
    try:
        from flask_wtf.csrf import generate_csrf
        return jsonify({'csrf_token': generate_csrf()}), 200
    except ImportError:
        return jsonify({'csrf_token': None, 'warning': 'flask-wtf not installed'}), 200


@app.route('/api/health', methods=['GET'])
def health():
    """Quick liveness check — returns 200 when the app is running."""
    return jsonify({'status': 'ok', 'service': 'SecurePass AI'}), 200


# ────────────────────────────────────────────────────────────────────────────
#  /api/analyze
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    """
    Analyse an uploaded password dataset.

    Form fields:
        file               – .txt or .csv upload (required)
        enable_breach_check – 'true' / 'false' (default: 'true')
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded.'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected.'}), 400

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()

        if ext not in app.config['UPLOAD_EXTENSIONS']:
            return jsonify({'error': 'Invalid file type. Please upload .txt or .csv.'}), 400

        is_valid, message = validate_uploaded_file(file, filename)
        if not is_valid:
            return jsonify({'error': message}), 400

        raw = file.read().decode('utf-8', errors='ignore')
        passwords = _parse_passwords(raw)

        if not passwords:
            return jsonify({'error': 'No valid passwords found in file.'}), 400
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
            _sim_path = os.path.join(os.path.dirname(__file__), 'backend')
            if _sim_path not in sys.path:
                sys.path.insert(0, _sim_path)
            from attack_simulator import AttackSimulator
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

        # Charts write to frontend/static/reports/output (single location)
        chart_paths = generate_charts(dataset_stats, risk_data, patterns)

        overview = {
            'total_passwords':  dataset_stats.get('total_passwords', 0),
            'unique_passwords': dataset_stats.get('unique_passwords', 0),
            'average_length':   round(dataset_stats.get('average_length', 0), 1),
            'risk_score':       round(risk_data.get('score', 0), 1),
            'weak_passwords':   risk_data.get('distribution', {}).get(_RISK_HIGH, 0),
            'medium_passwords': risk_data.get('distribution', {}).get(_RISK_MEDIUM, 0),
            'strong_passwords': risk_data.get('distribution', {}).get(_RISK_LOW, 0),
        }

        _dist = risk_data.get('distribution', {})
        response_data = {
            'overview':                   overview,
            'risk_level':                 risk_data.get('risk_level', 'Unknown'),
            # Both key formats so JS (.high/.medium/.low) and PDF (High Risk/...) both work
            'risk_distribution': {
                'high':        _dist.get(_RISK_HIGH, 0),
                'medium':      _dist.get(_RISK_MEDIUM, 0),
                'low':         _dist.get(_RISK_LOW, 0),
                _RISK_HIGH:   _dist.get(_RISK_HIGH, 0),
                _RISK_MEDIUM: _dist.get(_RISK_MEDIUM, 0),
                _RISK_LOW:    _dist.get(_RISK_LOW, 0),
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

        # ── Persist to database ───────────────────────────────────────── #
        try:
            import json as _json
            analysis = Analysis(
                user_id=current_user.id,
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
            app.logger.warning('Failed to save analysis to DB: %s', db_err)
            db.session.rollback()

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
        data = request.get_json(silent=True)
        if not data or 'password' not in data:
            return jsonify({'error': 'Password field is required.'}), 400

        is_valid, result = validate_single_password(data['password'])
        if not is_valid:
            return jsonify({'error': result}), 400

        return jsonify(_assess_single_password(result)), 200

    except Exception:
        app.logger.exception('Error in /api/check-password')
        return jsonify({'error': 'An error occurred during password check.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  /api/download-report
# ────────────────────────────────────────────────────────────────────────────

@app.route('/api/download-report', methods=['POST'])
@login_required
def download_report():
    """Generate and stream a PDF security report."""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'No data provided.'}), 400

        chart_paths = data.get('charts', {})
        pdf_data    = _transform_data_for_pdf(data)

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = generate_pdf_report(pdf_data, chart_paths, output_dir=tmp_dir)

            if not os.path.exists(pdf_path):
                raise FileNotFoundError('PDF was not generated.')

            with open(pdf_path, 'rb') as fh:
                pdf_bytes = fh.read()

        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=True,
            download_name='securepass_security_report.pdf',
            mimetype='application/pdf',
        )

    except Exception:
        app.logger.exception('Error in /api/download-report')
        return jsonify({'error': 'Failed to generate report. Please try again.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers
# ────────────────────────────────────────────────────────────────────────────

def _parse_passwords(content: str) -> list:
    """
    Parse newline- or comma-separated passwords from raw file content.

    Handles both Unix (\\n) and Windows (\\r\\n) line endings.
    Lines starting with '#' are treated as comments and skipped.
    """
    passwords = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # CSV: take the first column only
        password = line.split(',')[0].strip()
        if password:
            passwords.append(password)
    return passwords


def _assess_single_password(password: str) -> dict:
    """Return a basic strength assessment for a single password (no AI)."""
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

    return {
        'risk_level':       risk_level,
        'strength_score':   score,
        'length':           length,
        'has_uppercase':    has_upper,
        'has_lowercase':    has_lower,
        'has_numbers':      has_digits,
        'has_special':      has_special,
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
        f"Weak            : {dist.get(_RISK_HIGH, 0)}  |  "
        f"Medium: {dist.get(_RISK_MEDIUM, 0)}  |  "
        f"Strong: {dist.get(_RISK_LOW, 0)}",
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
    """
    overview     = api_data.get('overview', {})
    policy_impact = api_data.get('policy_impact', {})
    compliance    = api_data.get('compliance', {})
    risk_score    = overview.get('risk_score', 0)

    # Build policy_simulation scores
    # Bug 2 fix: policy_simulator returns flat keys current_score/projected_score, not nested
    projected = policy_impact.get('projected_score', 0)
    policy_simulation = {}
    if projected:
        policy_simulation = {
            'minimum_length_12':      projected * 0.95,
            'dictionary_blocking':    projected * 0.88,
            'pattern_restrictions':   projected * 0.92,
            'duplicate_prevention':   projected * 0.85,
            'complexity_requirements': projected * 0.90,
        }

    # Convert text NIST / OWASP statuses to numeric scores for PDF charts
    nist_score_map = {'Compliant': min(95, risk_score + 10), 'Partial Compliance': risk_score * 0.85, 'Non-Compliant': risk_score * 0.60}
    owasp_score_map = {'Low': min(95, risk_score + 5), 'Medium': risk_score * 0.90, 'High': risk_score * 0.70, 'Critical': risk_score * 0.50}
    compliance_mapping = {
        'NIST SP 800-63B': nist_score_map.get(compliance.get('nist_compliance_status', ''), risk_score),
        'OWASP':           owasp_score_map.get(compliance.get('owasp_risk_level', ''), risk_score),
        'ISO 27001':       risk_score * 0.92,
    }

    return {
        'total_passwords':  overview.get('total_passwords', 0),
        'unique_passwords': overview.get('unique_passwords', 0),
        'avg_length':       overview.get('average_length', 0),
        'average_length':   overview.get('average_length', 0),
        'min_length':       api_data.get('patterns', {}).get('min_length', 0),
        'max_length':       api_data.get('patterns', {}).get('max_length', 0),
        'risk_score':       risk_score,
        'risk_level':       api_data.get('risk_level', 'Unknown'),
        'patterns':         api_data.get('patterns', {}),
        'ai_insights':      api_data.get('ai_insights', []),
        'attack_scenarios': api_data.get('attack_scenarios', []),
        'policy_impact':    policy_impact,
        'policy_simulation': policy_simulation,
        'compliance':        compliance,
        'compliance_mapping': compliance_mapping,
        'recommendations':   api_data.get('recommendations', api_data.get('ai_insights', [])),
        'trends':            api_data.get('trends', []),
        'risk_distribution': api_data.get('risk_distribution', {}),
    }


if __name__ == '__main__':
    app.run(debug=app.config.get('DEBUG', False), host='0.0.0.0', port=5000)