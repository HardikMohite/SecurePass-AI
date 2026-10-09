"""
test_security_hardening.py — Enterprise Security Hardening Test Suite
Verifies:
1. Account Lockout on 5 consecutive failed login attempts (HTTP 423)
2. Account Lockout reset upon successful authentication
3. Global JWT session revocation when user password is changed/reset
4. Formula injection sanitization (CSV/Spreadsheet DDE protection)
5. Defense-in-depth security response headers and sensitive route cache controls
"""
import pytest
import time
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token

from app import create_app
from models import db, User
from utils.redaction import sanitize_formula_injection
from extensions import _check_if_token_revoked


@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': 'test-secret-key-security-hardening',
        'JWT_COOKIE_CSRF_PROTECT': False,
        'RATELIMIT_ENABLED': False,
    })

    with app.app_context():
        db.create_all()
        # Seed test user
        user = User(email='test_security@example.com', username='SecUser')
        user.set_password('StrongPassword123!')
        db.session.add(user)
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_account_lockout_trigger(client, app):
    """5 consecutive invalid password attempts must lock account and return 423."""
    with app.app_context():
        user = User.query.filter_by(email='test_security@example.com').first()
        assert not user.is_locked()
        assert user.failed_login_attempts == 0

    # Attempt 4 invalid logins
    for attempt in range(1, 5):
        resp = client.post('/api/auth/login', json={
            'email': 'test_security@example.com',
            'password': 'WrongPassword123!'
        })
        assert resp.status_code == 401
        data = resp.get_json()
        assert 'Invalid email/username or password' in data.get('error', '')

    # 5th invalid attempt triggers account lockout
    resp_5 = client.post('/api/auth/login', json={
        'email': 'test_security@example.com',
        'password': 'WrongPassword123!'
    })
    assert resp_5.status_code == 423
    data_5 = resp_5.get_json()
    assert data_5.get('account_locked') is True

    with app.app_context():
        user = User.query.filter_by(email='test_security@example.com').first()
        assert user.is_locked()
        assert user.failed_login_attempts == 5
        assert user.locked_until > datetime.utcnow()

    # Even with correct password, login is blocked while locked
    resp_locked = client.post('/api/auth/login', json={
        'email': 'test_security@example.com',
        'password': 'StrongPassword123!'
    })
    assert resp_locked.status_code == 423
    assert resp_locked.get_json().get('account_locked') is True


def test_account_lockout_reset_on_success(client, app):
    """Successful login resets failed attempt counter and clears lock."""
    # 2 failed attempts
    for _ in range(2):
        client.post('/api/auth/login', json={
            'email': 'test_security@example.com',
            'password': 'WrongPassword!'
        })

    with app.app_context():
        user = User.query.filter_by(email='test_security@example.com').first()
        assert user.failed_login_attempts == 2

    # Successful login
    resp = client.post('/api/auth/login', json={
        'email': 'test_security@example.com',
        'password': 'StrongPassword123!'
    })
    assert resp.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email='test_security@example.com').first()
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


def test_global_jwt_revocation_on_password_change(app):
    """Tokens issued before a password change are automatically revoked."""
    with app.app_context():
        user = User.query.filter_by(email='test_security@example.com').first()

        # Token created with past iat
        token = create_access_token(identity=str(user.id))
        from flask_jwt_extended import decode_token
        decoded = decode_token(token)

        # Before password change: token is not revoked
        assert not _check_if_token_revoked({}, decoded)

        # Wait a moment, then change password
        time.sleep(1.0)
        user.set_password('NewHardenedPassword999!')
        db.session.commit()

        # The old token iat is now older than user.password_changed_at
        # Token must be rejected
        assert _check_if_token_revoked({}, decoded) is True


def test_formula_injection_sanitization():
    """Formulas starting with dangerous characters must be safely escaped."""
    dangerous_inputs = [
        '=cmd|\' /C calc\'!A0',
        '+1+2',
        '-5+2',
        '@SUM(1,2)',
        '\t=malicious',
        '\r=cmd',
    ]
    for inp in dangerous_inputs:
        escaped = sanitize_formula_injection(inp)
        assert escaped.startswith("'"), f"Failed to escape formula: {inp}"

    safe_inputs = [
        'Hardik Enterprise',
        'StandardPassword123',
        'user@example.com',
        '12345',
    ]
    for safe in safe_inputs:
        assert sanitize_formula_injection(safe) == safe


def test_defense_in_depth_headers(client):
    """Response headers must enforce strict cross-origin policies and sensitive no-cache."""
    resp = client.get('/api/auth/csrf')
    assert resp.headers.get('X-Permitted-Cross-Domain-Policies') == 'none'
    assert resp.headers.get('Cross-Origin-Opener-Policy') == 'same-origin'
    assert resp.headers.get('Cross-Origin-Resource-Policy') == 'same-origin'
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'

    # Sensitive route must enforce no-store
    assert 'no-store' in resp.headers.get('Cache-Control', '')
