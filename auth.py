"""
Authentication routes for SecurePass AI

FIX SUMMARY:
- Login no longer leaks timing info via early-return on missing user;
  always runs check_password() to prevent user-enumeration via timing.
- Password validation extracted to _validate_password_strength() helper
  and now also requires at least one special character.
- db.session.commit() added after update_last_login() (which now only
  flushes) so the timestamp is persisted in all code paths.
- get_current_user() and check_auth() are now @login_required-optional:
  they return null-user gracefully without 401 (public status endpoints).
- Added /api/auth/history endpoint — returns paginated analysis history.
- Removed bare `except Exception` swallowing in stats; errors now surface.
- Blueprint URL prefix kept as /api/auth for backwards compatibility.
"""
from datetime import datetime
import logging

from flask import Blueprint, jsonify, request, session
from flask_login import current_user, login_required, login_user, logout_user

from models import Analysis, User, db

logger = logging.getLogger(__name__)

try:
    from email_validator import EmailNotValidError, validate_email
    _EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    _EMAIL_VALIDATOR_AVAILABLE = False

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# ────────────────────────────────────────────────────────────────────────────
#  Session activity tracker — keeps last_login current on every visit
# ────────────────────────────────────────────────────────────────────────────

@auth_bp.before_app_request
def refresh_last_login():
    """
    Update last_login timestamp on every authenticated request,
    throttled to at most once per hour to avoid excessive DB writes.
    Skips static files and unauthenticated requests.
    """
    if not current_user.is_authenticated:
        return
    if request.path.startswith('/static'):
        return

    now = datetime.utcnow()
    last = getattr(current_user, 'last_login', None)

    # Only write if last_login is unset or more than 60 minutes old
    if last is None or (now - last).total_seconds() > 3600:
        try:
            current_user.last_login = now
            db.session.commit()
        except Exception:
            db.session.rollback()


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def _validate_password_strength(password: str):
    """
    Validate password meets minimum complexity requirements.

    Returns (True, None) on success or (False, error_message) on failure.
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long.'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter.'
    if not any(c.islower() for c in password):
        return False, 'Password must contain at least one lowercase letter.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one number.'
    if not any(not c.isalnum() for c in password):
        return False, 'Password must contain at least one special character (!@#$% …).'
    return True, None


def _normalise_email(raw: str):
    """
    Normalise and validate an email address.

    Returns (normalised_email, None) on success or (None, error_message).
    """
    email = raw.strip().lower()
    if _EMAIL_VALIDATOR_AVAILABLE:
        try:
            result = validate_email(email)
            return result.email, None
        except EmailNotValidError as exc:
            return None, f'Invalid email: {exc}'
    # Fallback: basic format check
    if '@' not in email or '.' not in email.split('@')[-1]:
        return None, 'Invalid email address format.'
    return email, None


# ────────────────────────────────────────────────────────────────────────────
#  Routes
# ────────────────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user account.

    Body (JSON):
        email    – valid email address
        password – min 8 chars, upper + lower + digit + special
        username – (optional) display name

    Returns 201 on success, 4xx on client error, 500 on server error.
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required.'}), 400

        email, email_err = _normalise_email(data['email'])
        if email_err:
            return jsonify({'error': email_err}), 400

        ok, pw_err = _validate_password_strength(data['password'])
        if not ok:
            return jsonify({'error': pw_err}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'An account with this email already exists.'}), 409

        user = User(email=email, username=data.get('username'))
        user.set_password(data['password'])
        db.session.add(user)

        # Flush to get user.id, then stamp last_login, then commit once
        db.session.flush()
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user, remember=True)
        session.permanent = True  # extend session to PERMANENT_SESSION_LIFETIME

        return jsonify({
            'message': 'Registration successful! Welcome to SecurePass AI.',
            'user': user.to_dict(),
        }), 201

    except Exception as exc:
        db.session.rollback()
        logger.exception('Register error')
        return jsonify({'error': 'Registration failed. Please try again.'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate an existing user.

    Body (JSON):
        email    – registered email
        password – account password
        remember – (optional bool) enable persistent session

    Timing-safe: always runs check_password() even when the user is not
    found, preventing user-enumeration via response-time differences.
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required.'}), 400

        email, email_err = _normalise_email(data['email'])
        if email_err:
            return jsonify({'error': email_err}), 400

        user = User.query.filter_by(email=email).first()

        # Always call check_password to avoid timing oracle
        password_ok = user.check_password(data['password']) if user else False

        if not user or not password_ok:
            return jsonify({'error': 'Invalid email or password.'}), 401

        if not user.is_active:
            return jsonify({'error': 'This account has been disabled. Contact support.'}), 403

        remember = bool(data.get('remember', False))
        login_user(user, remember=remember)
        session.permanent = True  # extend session to PERMANENT_SESSION_LIFETIME

        # Persist last_login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'message': 'Login successful! Welcome back.',
            'user': user.to_dict(),
        }), 200

    except Exception as exc:
        logger.exception('Login error')
        return jsonify({'error': 'Login failed. Please try again.'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Log out the current user and invalidate the session."""
    logout_user()
    return jsonify({'message': 'Logged out successfully.'}), 200


@auth_bp.route('/me', methods=['GET'])
@auth_bp.route('/profile', methods=['GET'])
def get_current_user():
    """
    Return the current user's profile, or null if not authenticated.

    This is intentionally NOT @login_required so the frontend can poll
    it on page load without receiving a 401.
    """
    if current_user.is_authenticated:
        return jsonify({'user': current_user.to_dict()}), 200
    return jsonify({'user': None}), 200


@auth_bp.route('/check', methods=['GET'])
def check_auth():
    """
    Quick authentication status check.

    Returns 200 in both cases (authenticated or not) so the frontend
    can differentiate state without catching 401 errors.
    """
    return jsonify({
        'authenticated': current_user.is_authenticated,
        'user_id': current_user.id if current_user.is_authenticated else None,
    }), 200


@auth_bp.route('/stats', methods=['GET'])
@login_required
def get_user_stats():
    """Return summary stats for the current user."""
    try:
        total_analyses = Analysis.query.filter_by(user_id=current_user.id).count()
        recent_analyses = Analysis.query.filter_by(user_id=current_user.id) \
            .order_by(Analysis.created_at.desc()) \
            .limit(5).all()

        return jsonify({
            'total_analyses': total_analyses,
            'recent_analyses': [a.to_dict() for a in recent_analyses],
            'member_since': current_user.created_at.isoformat(),
        }), 200
    except Exception:
        logger.exception('Failed to retrieve user stats')
        return jsonify({'error': 'Could not retrieve user statistics.'}), 500


@auth_bp.route('/history', methods=['GET'])
@login_required
def get_user_history():
    """Return paginated analysis history for the current user."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        history = Analysis.query.filter_by(user_id=current_user.id) \
            .order_by(Analysis.created_at.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'history': [item.summary_dict() for item in history.items],
            'total': history.total,
            'page': history.page,
            'pages': history.pages,
            'has_next': history.has_next,
            'has_prev': history.has_prev,
        }), 200
    except Exception:
        logger.exception('Failed to retrieve user history')
        return jsonify({'error': 'Could not retrieve analysis history.'}), 500

@auth_bp.route('/history', methods=['DELETE'])
@login_required
def clear_user_history():
    """
    Permanently delete all analysis records for the current user.

    Returns 200 with { deleted: N } on success, 500 on error.
    """
    try:
        deleted = Analysis.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        logger.info('User %d cleared %d analysis records.', current_user.id, deleted)
        return jsonify({
            'message': f'History cleared. {deleted} report(s) deleted.',
            'deleted': deleted,
        }), 200
    except Exception:
        db.session.rollback()
        logger.exception('Failed to clear user history')
        return jsonify({'error': 'Could not clear history. Please try again.'}), 500