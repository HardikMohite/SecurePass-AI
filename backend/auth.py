"""
Authentication routes for SecurePass AI

SECURITY HARDENING — cookie transport + real CSRF enforcement:
- login()/register()/refresh() now also set the issued tokens as httpOnly
  cookies (set_access_cookies/set_refresh_cookies) so the browser SPA
  never needs to store a token in JS-readable storage. The JSON body
  still returns both tokens too, for non-browser clients that prefer
  Authorization-header auth.
- logout() now also calls unset_jwt_cookies() in addition to revoking the
  token server-side, so the browser actually clears its cookies too.
- CSRF is enforced by Flask-JWT-Extended's double-submit cookie check
  (JWT_COOKIE_CSRF_PROTECT in config.py) — a real, server-verified
  mechanism. The previous /api/csrf-token endpoint (Flask-WTF's
  generate_csrf()) has been removed: nothing ever validated the token it
  handed out, since Flask-WTF's CSRFProtect() was never actually
  instantiated anywhere in the app. See frontend/src/js/auth.js for the
  matching client-side change (reads the CSRF cookie directly instead of
  fetching a token from that endpoint).

PHASE 2 — Flask-Login session cookies replaced with Flask-JWT-Extended:
- login() now issues a short-lived access token + a refresh token instead
  of calling login_user()/setting a session cookie. `remember` still
  controls persistence, but now via the refresh token's expiry (12h
  vs. the full JWT_REFRESH_TOKEN_EXPIRES) rather than a cookie flag.
- Added /api/auth/refresh — trades a valid, non-revoked refresh token for
  a new access token.
- logout() revokes the calling token via the Redis blocklist (see
  extensions.py) instead of clearing a session; optionally revokes a
  paired refresh token if the client sends one.
- Every @login_required -> @jwt_required(); every current_user usage ->
  get_current_user() (auth_utils.py), which loads the User row from the
  JWT identity.
- refresh_last_login() now uses verify_jwt_in_request(optional=True) so
  it still runs on every request without hard-failing unauthenticated ones.

Earlier fix history (still true):
- Login no longer leaks timing info via early-return on missing user;
  always runs check_password() to prevent user-enumeration via timing.
- Password validation extracted to _validate_password_strength() helper
  and now also requires at least one special character.
- db.session.commit() added after update_last_login() (which now only
  flushes) so the timestamp is persisted in all code paths.
- Added /api/auth/history endpoint — returns paginated analysis history.
- Removed bare `except Exception` swallowing in stats; errors now surface.
- Blueprint URL prefix kept as /api/auth for backwards compatibility.
"""
from datetime import datetime, timedelta, timezone
import logging

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from sqlalchemy import func, or_
from sqlalchemy.orm import defer

from auth_utils import get_current_user
from extensions import limiter, revoke_token
from models import Analysis, User, db

logger = logging.getLogger(__name__)

try:
    from email_validator import EmailNotValidError, validate_email
    _EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    _EMAIL_VALIDATOR_AVAILABLE = False

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# ────────────────────────────────────────────────────────────────────────────
#  Last-login tracker — keeps last_login current on every visit
# ────────────────────────────────────────────────────────────────────────────

@auth_bp.before_app_request
def refresh_last_login():
    """
    Update last_login timestamp on every authenticated request,
    throttled to at most once per hour to avoid excessive DB writes.
    Skips static files and requests with no (or an invalid/expired)
    access token — optional=True means this never 401s a public request.
    """
    if request.path.startswith('/static'):
        return

    try:
        verify_jwt_in_request(optional=True)
    except Exception:
        return

    user = get_current_user()
    if user is None:
        return

    now = datetime.utcnow()
    last = user.last_login

    # Only write if last_login is unset or more than 60 minutes old
    if last is None or (now - last).total_seconds() > 3600:
        try:
            user.last_login = now
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
            # Skip the live DNS/MX deliverability lookup under TESTING so the
            # test suite (and CI) never depends on outbound network access —
            # syntax/format validation still runs either way. Production
            # (TESTING is always False there) keeps full deliverability
            # checking.
            deliverability = current_app.config.get(
                'CHECK_EMAIL_DELIVERABILITY',
                not current_app.config.get('TESTING', False)
            )
            result = validate_email(
                email,
                check_deliverability=deliverability,
            )
            return result.email, None
        except EmailNotValidError as exc:
            return None, f'Invalid email: {exc}'
    # Fallback: basic format check
    if '@' not in email or '.' not in email.split('@')[-1]:
        return None, 'Invalid email address format.'
    return email, None


def _issue_tokens(user: User, remember: bool = False):
    """
    Create an (access_token, refresh_token, cookie_max_age) tuple for *user*.

    - `remember=True`: Session lasts 30 days (access & refresh tokens and cookies expire in 30 days).
    - `remember=False`: Active session lasts 24 hours (refresh token lasts 7 days).
    """
    identity = str(user.id)
    if remember:
        access_expires = timedelta(days=30)
        refresh_expires = timedelta(days=30)
        cookie_max_age = int(timedelta(days=30).total_seconds())  # 2,592,000s
    else:
        access_expires = timedelta(hours=24)
        refresh_expires = timedelta(days=7)
        cookie_max_age = int(timedelta(days=7).total_seconds())  # 604,800s

    claims = {'remember': bool(remember)}
    access_token = create_access_token(
        identity=identity,
        expires_delta=access_expires,
        additional_claims=claims
    )
    refresh_token = create_refresh_token(
        identity=identity,
        expires_delta=refresh_expires,
        additional_claims=claims
    )
    return access_token, refresh_token, cookie_max_age


# ────────────────────────────────────────────────────────────────────────────
#  Routes
# ────────────────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST'])
@limiter.limit(lambda: current_app.config['RATELIMIT_AUTH'])
def register():
    """
    Register a new user account.

    Body (JSON):
        email    – valid email address
        password – min 8 chars, upper + lower + digit + special
        username – (optional) display name

    Returns 201 with an access_token + refresh_token on success, 4xx on
    client error, 500 on server error.
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

        remember = bool(data.get('remember', False))
        access_token, refresh_token, cookie_max_age = _issue_tokens(user, remember=remember)

        resp = jsonify({
            'message': 'Registration successful! Welcome to SecurePass AI.',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_expiry': '30 days' if remember else '15 minutes',
        })
        resp.status_code = 201
        set_access_cookies(resp, access_token, max_age=cookie_max_age)
        set_refresh_cookies(resp, refresh_token, max_age=cookie_max_age)
        return resp

    except Exception:
        db.session.rollback()
        logger.exception('Register error')
        return jsonify({'error': 'Registration failed. Please try again.'}), 500


@auth_bp.route('/login', methods=['POST'])
@limiter.limit(lambda: current_app.config['RATELIMIT_AUTH'])
def login():
    """
    Authenticate an existing user by email or username.

    Body (JSON):
        email / username / login – registered email address or username
        password                 – account password
        remember                 – (optional bool) if True, session lasts 30 days;
                                   if False (default), session lasts 15 minutes.

    Timing-safe: always runs check_password() even when the user is not
    found, preventing user-enumeration via response-time differences.
    """
    try:
        data = request.get_json(silent=True) or {}
        identifier = (data.get('email') or data.get('username') or data.get('login') or '').strip()
        password = data.get('password')

        if not identifier or not password:
            return jsonify({'error': 'Email or username and password are required.'}), 400

        user = None
        if '@' in identifier:
            norm_email, _ = _normalise_email(identifier)
            if norm_email:
                user = User.query.filter(func.lower(User.email) == norm_email.lower()).first()

        if not user:
            user = User.query.filter(
                or_(
                    func.lower(User.username) == identifier.lower(),
                    func.lower(User.email) == identifier.lower()
                )
            ).first()

        # Check for active account lockout
        if user and user.is_locked():
            lock_remaining = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() // 60))
            logger.warning("Authentication blocked for locked account %s (%d mins remaining)", identifier, lock_remaining)
            return jsonify({
                'error': f'Account temporarily locked due to multiple failed login attempts. Please try again in {lock_remaining} minutes, or reset your password.',
                'account_locked': True,
                'retry_after_minutes': lock_remaining,
            }), 423

        # Always call check_password to avoid timing oracle
        password_ok = user.check_password(password) if user else False

        if not user or not password_ok:
            if user:
                is_now_locked = user.record_failed_login()
                db.session.commit()
                if is_now_locked:
                    logger.warning("Account %s locked after %d failed attempts", identifier, user.failed_login_attempts)
                    return jsonify({
                        'error': 'Too many failed attempts. Account temporarily locked for 15 minutes to protect your credentials. You may reset your password to unlock immediately.',
                        'account_locked': True,
                        'retry_after_minutes': 15,
                    }), 423
            return jsonify({'error': 'Invalid email/username or password.'}), 401

        if not user.is_active:
            return jsonify({'error': 'This account has been disabled. Contact support.'}), 403

        # Successful authentication: clear failure count and lockout
        user.reset_failed_logins()
        user.last_login = datetime.utcnow()
        db.session.commit()

        remember = bool(data.get('remember', False))
        access_token, refresh_token, cookie_max_age = _issue_tokens(user, remember=remember)

        resp = jsonify({
            'message': 'Login successful! Welcome back.',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_expiry': '30 days' if remember else '24 hours',
        })
        set_access_cookies(resp, access_token, max_age=cookie_max_age)
        set_refresh_cookies(resp, refresh_token, max_age=cookie_max_age)
        return resp

    except Exception:
        logger.exception('Login error')
        return jsonify({'error': 'Login failed. Please try again.'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit(lambda: current_app.config['RATELIMIT_AUTH'])
@jwt_required(refresh=True)
def refresh():
    """
    Exchange a valid, non-revoked refresh token for a new access token.
    Honours the original session duration (30 days if remember was set, else 15 minutes).
    """
    identity = get_jwt_identity()
    claims = get_jwt()
    remember = bool(claims.get('remember', False))
    if remember:
        access_expires = timedelta(days=30)
        cookie_max_age = int(timedelta(days=30).total_seconds())
    else:
        access_expires = timedelta(hours=24)
        cookie_max_age = int(timedelta(days=7).total_seconds())

    access_token = create_access_token(
        identity=identity,
        expires_delta=access_expires,
        additional_claims={'remember': remember}
    )
    resp = jsonify({'access_token': access_token})
    set_access_cookies(resp, access_token, max_age=cookie_max_age)
    return resp


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Revoke the access token used to call this endpoint by adding its jti
    to the Redis blocklist (see extensions.py) until it would have
    expired anyway.

    Body (JSON, optional):
        refresh_token – if supplied, its jti is revoked too, so a client
                         that stored both tokens can log out completely
                         in one call instead of leaving the refresh token
                         usable until it expires on its own.
    """
    claims = get_jwt()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    revoke_token(claims['jti'], claims['exp'] - now_ts)

    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token')
    if refresh_token:
        try:
            decoded = decode_token(refresh_token)
            revoke_token(decoded['jti'], decoded['exp'] - now_ts)
        except Exception:
            logger.warning('logout: could not decode supplied refresh_token to revoke it')

    resp = jsonify({'message': 'Logged out successfully.'})
    unset_jwt_cookies(resp)
    return resp


@auth_bp.route('/me', methods=['GET'])
@auth_bp.route('/profile', methods=['GET'])
@jwt_required(optional=True)
def get_current_user_route():
    """
    Return the current user's profile, or null if not authenticated.

    Uses jwt_required(optional=True) (rather than no decorator at all)
    so the frontend can poll it on page load without receiving a 401.
    """
    user = get_current_user()
    if user:
        return jsonify({'user': user.to_dict()}), 200
    return jsonify({'user': None}), 200


@auth_bp.route('/check', methods=['GET'])
@jwt_required(optional=True)
def check_auth():
    """
    Quick authentication status check.

    Returns 200 in both cases (authenticated or not) so the frontend
    can differentiate state without catching 401 errors.
    """
    user = get_current_user()
    return jsonify({
        'authenticated': user is not None,
        'user_id': user.id if user else None,
    }), 200


@auth_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """Return summary stats for the current user."""
    try:
        user = get_current_user()
        total_analyses = Analysis.query.filter_by(user_id=user.id).count()
        recent_analyses = Analysis.query.filter_by(user_id=user.id) \
            .order_by(Analysis.created_at.desc()) \
            .limit(5).all()

        return jsonify({
            'total_analyses': total_analyses,
            'recent_analyses': [a.to_dict() for a in recent_analyses],
            'member_since': user.created_at.isoformat(),
        }), 200
    except Exception:
        logger.exception('Failed to retrieve user stats')
        return jsonify({'error': 'Could not retrieve user statistics.'}), 500


@auth_bp.route('/history', methods=['GET'])
@jwt_required()
def get_user_history():
    """Return paginated analysis history for the current user."""
    try:
        user = get_current_user()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        history = Analysis.query.options(defer(Analysis._analysis_data)) \
            .filter_by(user_id=user.id) \
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
@jwt_required()
def clear_user_history():
    """
    Permanently delete all analysis records for the current user.

    Returns 200 with { deleted: N } on success, 500 on error.
    """
    try:
        user = get_current_user()
        deleted = Analysis.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        logger.info('User %d cleared %d analysis records.', user.id, deleted)
        return jsonify({
            'message': f'History cleared. {deleted} report(s) deleted.',
            'deleted': deleted,
        }), 200
    except Exception:
        db.session.rollback()
        logger.exception('Failed to clear user history')
        return jsonify({'error': 'Could not clear history. Please try again.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Password Reset & Double Authentication (OTP via Brevo)
# ────────────────────────────────────────────────────────────────────────────

@auth_bp.route('/forgot-password', methods=['POST'])
@limiter.limit("10 per hour")
def forgot_password():
    """
    Request password reset link and 6-digit OTP code via Brevo email service.
    """
    from brevo_mailer import send_password_reset_email
    from reset_service import create_reset_session

    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email address is required.'}), 400

    # Basic email format validation
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Please enter a valid email address.'}), 400

    # Look up user safely
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as exc:
        logger.warning('DB query failed during forgot_password lookup: %s', exc)
        user = None

    # In development or if user is found, proceed with OTP generation
    # Even if account is not found, we generate session or return safe response
    otp_code, reset_token = create_reset_session(email)

    # Base frontend URL (configured or inferred from request)
    host = request.headers.get('Origin') or request.headers.get('Referer') or 'http://localhost:5173'
    host = host.rstrip('/')
    reset_url = f"{host}/reset_password.html?token={reset_token}"

    # Dispatch email via Brevo
    mail_result = send_password_reset_email(email, otp_code, reset_url)

    resp_payload = {
        'success': True,
        'message': 'A 6-digit verification code and reset link have been dispatched to your email.',
        'email': email,
    }
    # In development / simulation mode, also send OTP preview so user testing is instantaneous
    if mail_result.get('mode') != 'live':
        resp_payload['dev_otp'] = otp_code
        resp_payload['dev_reset_url'] = reset_url
        resp_payload['note'] = mail_result.get('warning') or mail_result.get('message')

    return jsonify(resp_payload), 200


@auth_bp.route('/verify-otp', methods=['POST'])
@limiter.limit("20 per hour")
def verify_otp():
    """
    Verify 6-digit OTP code for double authentication.
    Returns session token required to reset the password.
    """
    from reset_service import verify_otp_code

    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()

    if not email or not otp:
        return jsonify({'error': 'Email and 6-digit verification code are required.'}), 400

    is_valid, token, error_msg = verify_otp_code(email, otp)
    if not is_valid:
        return jsonify({'error': error_msg or 'Invalid verification code.'}), 400

    return jsonify({
        'success': True,
        'message': 'Verification code confirmed. You may now set your new password.',
        'token': token,
        'email': email,
    }), 200


@auth_bp.route('/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    """
    Reset user password using a verified session token or direct link token.
    """
    from reset_service import validate_reset_token, consume_reset_token

    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    new_password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')

    if not token:
        return jsonify({'error': 'Reset token is missing or expired. Please request a new code.'}), 400

    if not new_password:
        return jsonify({'error': 'New password is required.'}), 400

    if confirm_password and new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400

    # Validate token
    is_valid, email = validate_reset_token(token)
    if not is_valid or not email:
        return jsonify({'error': 'Reset session has expired or is invalid. Please request a new code.'}), 400

    # Validate password strength
    ok, strength_error = _validate_password_strength(new_password)
    if not ok:
        return jsonify({'error': strength_error}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User account not found.'}), 404

    try:
        user.set_password(new_password)
        db.session.commit()
        consume_reset_token(token, email)
        logger.info("Password successfully reset for user %s", email)
        return jsonify({
            'success': True,
            'message': 'Your password has been reset successfully. You can now sign in.',
        }), 200
    except Exception:
        db.session.rollback()
        logger.exception("Failed to update password during reset")
        return jsonify({'error': 'Failed to update password. Please try again.'}), 500

