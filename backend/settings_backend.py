"""
settings_backend.py — SecurePass AI Settings Blueprint

Provides all /api/settings/* routes consumed by settings.js:

    GET  /api/settings                 — load user settings
    PUT  /api/settings                 — save settings (partial update)
    GET  /api/settings/session         — live session info (browser, IP, timestamps)
    GET  /api/settings/storage         — storage / analysis-count stats
    PUT  /api/settings/profile         — update display name
    POST /api/settings/change-password — change password
    GET  /api/settings/export          — download settings as JSON
    POST /api/settings/import          — import settings from JSON
    DELETE /api/settings/delete-analyses — wipe all analyses for current user
    DELETE /api/settings/account       — permanently delete account

UserSettings model stores per-user preferences as a JSON blob in the DB.
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from auth_utils import get_current_user
from models import Analysis, User, db

settings_bp = Blueprint('settings', __name__)

# ── Default settings applied for new users / missing keys ──────────────── #
_DEFAULTS = {
    # Appearance
    'accent_color':           '#00e5ff',
    'density':                'comfortable',
    'font_scale':             1,
    # Audit
    'default_compliance':     'nist',
    'risk_high_threshold':    40,
    'risk_medium_threshold':  70,
    'enable_pattern_attack':  True,
    'enable_bruteforce':      True,
    'enable_dictionary':      True,
    'enable_keyboard_walk':   True,
    'enable_wordlist':        True,
    'require_uppercase':      True,
    'require_numbers':        True,
    'require_special':        False,
    'min_length':             8,
    # Notifications
    'weekly_report':          True,
    'breach_alerts':          True,
    'score_alerts':           False,
    'email_notifications':    True,
    'digest_frequency':       'daily',
    # Data
    'retention_days':         90,
    # Policy Governance & Audit
    'policy_preset':          'standard',
    'policy_org_name':        'Acme Corporation',
    'policy_ciso_name':       'Chief Information Security Officer (CISO)',
    'policy_inactivity_mins': 10,
    'policy_mfa_requirement': 'all',
}

# Allowed keys for PUT /api/settings — prevents arbitrary column injection
_ALLOWED_KEYS = set(_DEFAULTS.keys())


# ── UserSettings model (stored as JSON in User.settings_json) ──────────── #
# We piggyback on the existing User model rather than adding a new table.
# `settings_json` is a real mapped column on User (see models.py) and is
# created/managed by Alembic — no runtime column-add is needed anymore.

class UserSettings:
    """Thin wrapper that reads/writes JSON settings on the User row."""

    @staticmethod
    def get(user: User) -> dict:
        raw = user.settings_json
        try:
            stored = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            stored = {}
        # Merge defaults so new keys are always present
        return {**_DEFAULTS, **stored}

    @staticmethod
    def save(user: User, updates: dict) -> dict:
        current = UserSettings.get(user)
        # Only update known keys
        for k, v in updates.items():
            if k in _ALLOWED_KEYS:
                current[k] = v
        user.settings_json = json.dumps(current)
        db.session.commit()
        return current


# ── Helpers ────────────────────────────────────────────────────────────── #

def _parse_user_agent(ua_string: str) -> tuple:
    """
    Return (browser_label, os_label) from a User-Agent string.
    Avoids heavy dependencies — simple substring matching is sufficient.
    """
    ua = ua_string or ''

    # Browser
    if 'Edg/' in ua or 'Edge/' in ua:
        browser = 'Microsoft Edge'
    elif 'OPR/' in ua or 'Opera' in ua:
        browser = 'Opera'
    elif 'Chrome/' in ua and 'Safari/' in ua:
        browser = 'Chrome'
    elif 'Firefox/' in ua:
        browser = 'Firefox'
    elif 'Safari/' in ua and 'Chrome/' not in ua:
        browser = 'Safari'
    elif 'MSIE' in ua or 'Trident/' in ua:
        browser = 'Internet Explorer'
    else:
        browser = 'Browser'

    # OS
    if 'Windows NT' in ua:
        os_name = 'Windows'
    elif 'Mac OS X' in ua:
        os_name = 'macOS'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_name = 'iOS'
    elif 'Linux' in ua:
        os_name = 'Linux'
    else:
        os_name = ''

    return browser, os_name


def _get_client_ip() -> str:
    """Return best-guess client IP, respecting common proxy headers."""
    for header in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        val = request.headers.get(header)
        if val:
            return val.split(',')[0].strip()
    return request.remote_addr or '—'


def _iso(dt) -> str | None:
    """Return ISO-8601 UTC string from a datetime, or None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Assume stored as UTC naive
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ── Routes ─────────────────────────────────────────────────────────────── #

@settings_bp.route('/api/settings', methods=['GET'])
@jwt_required()
def get_settings():
    """Return the current user's settings merged with defaults."""
    user = get_current_user()
    settings = UserSettings.get(user)
    return jsonify({'settings': settings}), 200


@settings_bp.route('/api/settings', methods=['PUT'])
@jwt_required()
def update_settings():
    """Partial-update settings — only keys in _ALLOWED_KEYS are written."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    saved = UserSettings.save(user, data)
    return jsonify({'settings': saved}), 200


@settings_bp.route('/api/settings/session', methods=['GET'])
@jwt_required()
def get_session_info():
    """
    Return live session data for the Security tab:
        browser, os, ip, last_login (ISO UTC), created_at (ISO UTC),
        total_analyses
    """
    ua = request.headers.get('User-Agent', '')
    browser, os_name = _parse_user_agent(ua)
    ip = _get_client_ip()
    user = get_current_user()

    # Update last_login timestamp on every settings page visit
    now = datetime.now(timezone.utc)
    try:
        if hasattr(user, 'last_login'):
            user.last_login = now
            db.session.commit()
    except Exception:
        db.session.rollback()

    # Count analyses
    try:
        total_analyses = Analysis.query.filter_by(user_id=user.id).count()
    except Exception:
        total_analyses = 0

    return jsonify({
        'browser':         browser,
        'os':              os_name,
        'ip':              ip,
        'last_login':      _iso(getattr(user, 'last_login', now)),
        'created_at':      _iso(getattr(user, 'created_at', None)),
        'total_analyses':  total_analyses,
    }), 200


@settings_bp.route('/api/settings/storage', methods=['GET'])
@jwt_required()
def get_storage():
    """
    Return storage usage stats for the Data tab:
        used_mb, analysis_count, limit_mb, used_pct
    """
    user = get_current_user()
    try:
        analysis_count = Analysis.query.filter_by(user_id=user.id).count()
    except Exception:
        analysis_count = 0

    # Estimate storage: each analysis averages ~50 KB of JSON
    used_mb   = round(analysis_count * 0.05, 2)
    limit_mb  = 500
    used_pct  = round(min(used_mb / limit_mb * 100, 100), 1)

    return jsonify({
        'used_mb':        used_mb,
        'analysis_count': analysis_count,
        'limit_mb':       limit_mb,
        'used_pct':       used_pct,
    }), 200


@settings_bp.route('/api/settings/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update the display name (username) for the current user."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()[:64]

    if not username:
        return jsonify({'error': 'Name cannot be empty.'}), 400

    try:
        user.username = username
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update profile.'}), 500

    return jsonify({
        'user': {
            'username':   user.username,
            'email':      user.email,
            'created_at': _iso(getattr(user, 'created_at', None)),
            'last_login': _iso(getattr(user, 'last_login', None)),
        }
    }), 200


@settings_bp.route('/api/settings/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Verify the current password then set the new one."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')

    if not current_pw or not new_pw:
        return jsonify({'error': 'Both current and new passwords are required.'}), 400

    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters.'}), 400

    # Support both password_hash and password attribute names
    pw_hash = getattr(user, 'password_hash', None) or getattr(user, 'password', None)
    if not pw_hash or not check_password_hash(pw_hash, current_pw):
        return jsonify({'error': 'Current password is incorrect.'}), 400

    try:
        new_hash = generate_password_hash(new_pw)
        if hasattr(user, 'password_hash'):
            user.password_hash = new_hash
        else:
            user.password = new_hash
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to update password.'}), 500

    return jsonify({'message': 'Password updated successfully.'}), 200


@settings_bp.route('/api/settings/export', methods=['GET'])
@jwt_required()
def export_settings():
    """Download current settings as a JSON file."""
    user = get_current_user()
    settings = UserSettings.get(user)
    export_data = {
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'version':     '1.0',
        'settings':    settings,
    }
    import io
    buf = io.BytesIO(json.dumps(export_data, indent=2).encode('utf-8'))
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name='securepass_preferences.json',
        mimetype='application/json',
    )


@settings_bp.route('/api/settings/import', methods=['POST'])
@jwt_required()
def import_settings():
    """Import settings from a JSON body (exported by /api/settings/export)."""
    user = get_current_user()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON body.'}), 400

    # Accept both {settings: {...}} and flat {...} shapes
    incoming = data.get('settings') if isinstance(data.get('settings'), dict) else data

    # Strip unknown keys before saving
    filtered = {k: v for k, v in incoming.items() if k in _ALLOWED_KEYS}
    if not filtered:
        return jsonify({'error': 'No valid settings keys found in file.'}), 400

    saved = UserSettings.save(user, filtered)
    return jsonify({'settings': saved}), 200


@settings_bp.route('/api/settings/delete-analyses', methods=['DELETE'])
@jwt_required()
def delete_analyses():
    """Permanently delete all saved analyses for the current user."""
    user = get_current_user()
    try:
        deleted = Analysis.query.filter_by(user_id=user.id).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete analyses.'}), 500

    return jsonify({'deleted': deleted, 'message': f'{deleted} analyses deleted.'}), 200


@settings_bp.route('/api/settings/account', methods=['DELETE'])
@jwt_required()
def delete_account():
    """
    Permanently delete the current user's account and all associated data.

    Requires the current password in the JSON body (re-authentication for
    a destructive, irreversible action — same principle as
    change_password() above) to guard against a hijacked/forgotten-open
    session being used to delete the account without the owner's
    knowledge. Revokes the calling access token afterward — there's no
    server-side session to clear with JWTs, but there's no reason a token
    for a now-deleted account should keep validating until it naturally
    expires.
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    current_pw = data.get('current_password', '')

    pw_hash = getattr(user, 'password_hash', None) or getattr(user, 'password', None)
    if not current_pw or not pw_hash or not check_password_hash(pw_hash, current_pw):
        return jsonify({'error': 'Current password is incorrect.'}), 400

    try:
        user_id = user.id
        # Delete child records first to avoid FK constraint errors
        Analysis.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete account.'}), 500

    from datetime import datetime, timezone as _tz
    from flask_jwt_extended import get_jwt
    from extensions import revoke_token
    claims = get_jwt()
    revoke_token(claims['jti'], claims['exp'] - int(datetime.now(_tz.utc).timestamp()))

    return jsonify({'message': 'Account deleted successfully.'}), 200


# ── /api/auth/me  — used by settings.js loadAll() ──────────────────────── #
# If auth_bp already exposes this route, this one won't register (Flask
# raises AssertionError on duplicate endpoints).  Guard with try/except.

try:
    @settings_bp.route('/api/auth/me', methods=['GET'])
    @jwt_required()
    def auth_me():
        """Return minimal current-user profile for the settings page."""
        user = get_current_user()
        return jsonify({
            'user': {
                'id':         user.id,
                'username':   getattr(user, 'username', None),
                'email':      user.email,
                'created_at': _iso(getattr(user, 'created_at', None)),
                'last_login': _iso(getattr(user, 'last_login', None)),
                'plan':       getattr(user, 'plan', 'Free'),
            }
        }), 200
except AssertionError:
    pass  # auth_bp already registered /api/auth/me — that version takes precedence