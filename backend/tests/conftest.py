"""
backend/tests/conftest.py — shared pytest fixtures for the SecurePass AI
backend test suite.

Key decisions, spelled out because they're easy to trip over later:

1. FLASK_ENV is forced to "testing" *before* `app` (the project-root
   module) is ever imported. app.py builds its module-level `app` object
   once at import time via `app = create_app()`, and most of its
   API routes (/api/analyze, /api/health, ...) are
   attached directly to that one Flask instance rather than inside
   create_app() itself (only the auth/hibp/settings blueprints are
   registered inside the factory). That means a *second* call to
   create_app(TestingConfig) from a test — the seemingly obvious way to
   get an isolated test app — would produce a Flask instance missing all
   of those routes. Importing the already-built singleton after forcing
   FLASK_ENV=testing gets the real, fully-routed app AND TestingConfig
   (config.py's get_config() reads FLASK_ENV and returns TestingConfig
   for "testing"), which is what every fixture here relies on.

2. The JWT revocation blocklist (extensions.py) is backed by Redis in
   every other environment. Tests replace `extensions.redis_client` with
   an in-memory fakeredis instance *before* importing `app`, so the full
   JWT stack (issue/verify/revoke) is exercised for real without the
   suite depending on a live Redis instance. flask-limiter's storage is
   separately pointed at memory:// via TestingConfig for the same reason
   (see config.py).

3. SQLALCHEMY_DATABASE_URI is sqlite:///:memory: only via TestingConfig
   (config.py) — this is the one place in the project SQLite is
   intentionally still used; everywhere else assumes Postgres.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["FLASK_ENV"] = "testing"

import fakeredis  # noqa: E402
import pytest  # noqa: E402

import extensions  # noqa: E402

# Must happen before `from app import app`, since auth.py's logout route
# and extensions.py's JWT blocklist loader both read the module-level
# `extensions.redis_client` at call time.
extensions.redis_client = fakeredis.FakeStrictRedis(decode_responses=True)

from app import app as _flask_app  # noqa: E402
from models import db  # noqa: E402


@pytest.fixture(scope="session")
def app():
    """The single, fully-routed Flask app, configured via TestingConfig."""
    assert _flask_app.config["TESTING"] is True
    assert _flask_app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"
    yield _flask_app


@pytest.fixture(autouse=True)
def _fresh_database(app):
    """Give every test function a clean, empty schema."""
    with app.app_context():
        db.create_all()
    yield
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Werkzeug test client for making requests against the app."""
    return app.test_client()


@pytest.fixture
def register_user(client):
    """
    Factory fixture: register (and thereby also log in) a user, returning
    the parsed JSON response body (message, user, access_token,
    refresh_token).
    """

    def _register(email="user@example.com", password="Str0ng!Pass", username="tester"):
        resp = client.post(
            "/api/auth/register",
            json={"email": email, "password": password, "username": username},
        )
        assert resp.status_code == 201, resp.get_json()
        return resp.get_json()

    return _register


@pytest.fixture
def auth_headers(register_user):
    """A ready-to-use Authorization header for a freshly registered user."""
    body = register_user()
    return {"Authorization": f"Bearer {body['access_token']}"}
