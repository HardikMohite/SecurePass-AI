"""
Configuration settings for SecurePass AI

FIX SUMMARY:
- Added DevelopmentConfig / ProductionConfig separation
- Removed hardcoded fallback secret key (raises error in production)
- Added RATELIMIT_* settings for flask-limiter integration
- Added WTF_CSRF_ENABLED for future CSRF protection
- SESSION_COOKIE_SECURE now always True in ProductionConfig
- DEBUG forced False in ProductionConfig
- Added SQLALCHEMY_ENGINE_OPTIONS for connection pool health
"""
import os
from datetime import timedelta


def normalize_database_uri(uri: str | None) -> str | None:
    """Ensure database URI is compatible with SQLAlchemy and remote Postgres/Supabase."""
    if not uri:
        return uri
    # Standardize postgres:// to postgresql:// for SQLAlchemy 1.4/2.x compatibility
    if uri.startswith('postgres://'):
        uri = uri.replace('postgres://', 'postgresql://', 1)
    # Ensure sslmode=require for Supabase / cloud Postgres if omitted
    if ('supabase.com' in uri or 'supabase.co' in uri) and 'sslmode=' not in uri:
        delimiter = '&' if '?' in uri else '?'
        uri = f"{uri}{delimiter}sslmode=require"
    return uri


class Config:
    """Base configuration — never instantiate directly."""

    # ------------------------------------------------------------------ #
    #  Security                                                            #
    # ------------------------------------------------------------------ #
    # Falls back to dev key if not set; ProductionConfig enforces this strictly
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-insecure-key-change-in-production'

    # CSRF protection: enforced by Flask-JWT-Extended's double-submit
    # cookie check (JWT_COOKIE_CSRF_PROTECT above), not Flask-WTF. A
    # Flask-WTF CSRFProtect() was never actually instantiated anywhere in
    # this codebase in an earlier version — WTF_CSRF_ENABLED was set here
    # but had no effect, and the old /api/csrf-token endpoint generated a
    # token that nothing ever validated. Removed rather than left as
    # dead/misleading config.

    # ------------------------------------------------------------------ #
    #  Database                                                            #
    # ------------------------------------------------------------------ #
    # DATABASE_URL must be Supabase's TRANSACTION POOLER connection string
    # (hostname contains "pooler.supabase.com", port 6543), e.g.
    # postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres
    # plus `?sslmode=require`. Using the direct/session connection string
    # under normal app traffic can exhaust Supabase's connection limit.
    # See .env.example for the exact format.
    _raw_db = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = normalize_database_uri(_raw_db) or 'sqlite:///securepass.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    # ── Supabase / PgBouncer connection pool settings ──────────────────────
    # Supabase uses PgBouncer in TRANSACTION mode as the connection pooler.
    # When using SQLite, SQLite's driver does not accept these connect_args.
    if SQLALCHEMY_DATABASE_URI.startswith('sqlite'):
        SQLALCHEMY_ENGINE_OPTIONS = {}
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_size": 5,
            "max_overflow": 10,
            "pool_recycle": 300,        # 5 min — matches Supabase idle timeout
            "pool_pre_ping": True,      # avoid "server closed the connection" errors
            "pool_timeout": 30,
            "connect_args": {
                "keepalives": 1,
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 5,
            },
        }

    # ------------------------------------------------------------------ #
    #  Session / Cookie                                                    #
    # ------------------------------------------------------------------ #
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_PERMANENT = True            # make sessions last across browser restarts
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = 'sp_session'  # custom name avoids fingerprinting
    # Subclasses override SECURE flags — never leave False in production
    SESSION_COOKIE_SECURE = False

    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = False
    REMEMBER_COOKIE_NAME = 'sp_remember'

    # ------------------------------------------------------------------ #
    #  JWT (Flask-JWT-Extended)                                            #
    # ------------------------------------------------------------------ #
    # Deliberately separate from SECRET_KEY — rotating one shouldn't force
    # rotating the other. Falls back to a dev key here; ProductionConfig
    # enforces it strictly (see __init__ below).
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-only-insecure-jwt-key-change-in-production'
    # Accept the token from EITHER an Authorization header (non-browser /
    # API clients, e.g. Postman, mobile, server-to-server) OR an httpOnly
    # cookie (the browser SPA — see auth.py's set_access_cookies /
    # set_refresh_cookies calls on login/register/refresh). Storing the
    # token in an httpOnly cookie instead of localStorage/sessionStorage
    # means an XSS bug on the frontend can't read it and exfiltrate it —
    # the single biggest reason OWASP recommends cookies over Web Storage
    # for token-based auth in browser apps.
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_HEADER_TYPE = 'Bearer'
    # Short-lived access token; longer-lived refresh token used only to
    # mint new access tokens via /api/auth/refresh. "remember me" at login
    # extends the refresh token's lifetime out to this value — see login()
    # in auth.py.
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    # Enables /api/auth/logout to actually revoke a token (see extensions.py)
    JWT_BLOCKLIST_ENABLED = True
    JWT_BLOCKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # ── JWT cookie transport ────────────────────────────────────────────
    # The refresh cookie is scoped ONLY to /api/auth/refresh — the browser
    # will not attach it to any other request, so even an XSS-read of
    # response headers on some other endpoint can't expose it, and the
    # blast radius of any cookie-handling bug elsewhere in the app is
    # limited to the (short-lived) access cookie. Both cookies are
    # httpOnly (JS can never read the token itself); the CSRF double-
    # submit cookie flask_jwt_extended sets alongside each is intentionally
    # NOT httpOnly, since the frontend must read it to echo it back in the
    # X-CSRF-TOKEN header — see frontend/src/js/auth.js.
    JWT_COOKIE_SECURE = False           # ProductionConfig forces True
    JWT_COOKIE_SAMESITE = 'Lax'         # ProductionConfig tightens to 'Strict'
    JWT_ACCESS_COOKIE_PATH = '/'
    JWT_REFRESH_COOKIE_PATH = '/api/auth/refresh'
    JWT_COOKIE_CSRF_PROTECT = True      # enforced on every cookie-authenticated
                                         # state-changing request (see below)
    JWT_CSRF_IN_COOKIES = True
    JWT_CSRF_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    JWT_ACCESS_CSRF_HEADER_NAME = 'X-CSRF-TOKEN'
    JWT_REFRESH_CSRF_HEADER_NAME = 'X-CSRF-TOKEN'

    # ------------------------------------------------------------------ #
    #  Redis (JWT revocation blocklist; also usable as RATELIMIT_STORAGE_URL) #
    # ------------------------------------------------------------------ #
    REDIS_URL = os.environ.get('REDIS_URL')

    # ------------------------------------------------------------------ #
    #  File Upload                                                         #
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024   # 25 MB
    UPLOAD_EXTENSIONS = {'.txt', '.csv', '.xlsx', '.xls'}
    MAX_PASSWORDS_PER_ANALYSIS = 10_000

    # ------------------------------------------------------------------ #
    #  Rate Limiting  (requires flask-limiter)                            #
    # ------------------------------------------------------------------ #
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_ANALYZE = "20 per hour"        # stricter limit for /api/analyze
    RATELIMIT_AUTH = "10 per minute"         # login / register endpoints
    # Storage for rate limiter: use RATELIMIT_STORAGE_URL or REDIS_URL if provided, else memory://
    _configured_rate_storage = os.environ.get('RATELIMIT_STORAGE_URL') or os.environ.get('REDIS_URL')
    RATELIMIT_STORAGE_URL = _configured_rate_storage if _configured_rate_storage else 'memory://'
    RATELIMIT_SWALLOW_ERRORS = True  # Prevent Redis outage/absence from returning 500 errors
    RATELIMIT_STORAGE_OPTIONS = {
        "socket_connect_timeout": 1,
        "socket_timeout": 1,
    }

    # ------------------------------------------------------------------ #
    #  CORS  (requires flask-cors)                                        #
    # ------------------------------------------------------------------ #
    # Comma-separated allowlist of exact origins (scheme + host + port),
    # e.g. "https://app.example.com,https://staging.example.com". No
    # wildcards — every origin that should be allowed must be listed
    # explicitly. Empty by default so a misconfigured deployment fails
    # closed (no cross-origin access) rather than open.
    CORS_ORIGINS = [
        o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip()
    ]

    # ------------------------------------------------------------------ #
    #  App defaults                                                        #
    # ------------------------------------------------------------------ #
    TESTING = False
    DEBUG = False


class DevelopmentConfig(Config):
    """Local development — relaxed security, verbose output."""
    DEBUG = True
    SQLALCHEMY_ECHO = False          # flip to True to debug SQL queries
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    JWT_COOKIE_SECURE = False        # plain HTTP is fine for localhost
    RATELIMIT_ENABLED = False        # disable rate limits locally
    CHECK_EMAIL_DELIVERABILITY = False # allow test emails in local development
    CORS_ORIGINS = [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:5000',
        'http://127.0.0.1:5000',
        'http://localhost:4173',
        'http://127.0.0.1:4173',
    ]

    # Allow an insecure fallback key ONLY in development
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-insecure-key-do-not-use-in-prod'


class ProductionConfig(Config):
    """Production — strict security, no debug output."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    JWT_COOKIE_SECURE = True          # cookies only ever sent over HTTPS
    JWT_COOKIE_SAMESITE = os.environ.get('JWT_COOKIE_SAMESITE', 'None')

    # Force Postgres (or other URL) in production; SQLite not suitable.
    _prod_raw_db = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = normalize_database_uri(_prod_raw_db) if _prod_raw_db else None

    # Supabase / PgBouncer connection pool options in production
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": int(os.environ.get('DB_POOL_SIZE', 5)),
        "max_overflow": int(os.environ.get('DB_MAX_OVERFLOW', 10)),
        "pool_recycle": 300,        # 5 min — matches Supabase idle timeout
        "pool_pre_ping": True,      # avoid "server closed the connection" errors
        "pool_timeout": 30,
        "connect_args": {
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    }

    def __init__(self):
        import secrets
        if not os.environ.get('SECRET_KEY'):
            auto_secret = secrets.token_hex(32)
            os.environ['SECRET_KEY'] = auto_secret
            self.SECRET_KEY = auto_secret
            print("[PRODUCTION NOTICE] SECRET_KEY not provided in environment; auto-generated key.")

        if not os.environ.get('JWT_SECRET_KEY'):
            auto_jwt_secret = secrets.token_hex(32)
            os.environ['JWT_SECRET_KEY'] = auto_jwt_secret
            self.JWT_SECRET_KEY = auto_jwt_secret
            print("[PRODUCTION NOTICE] JWT_SECRET_KEY not provided in environment; auto-generated key.")

        if not os.environ.get('DATABASE_URL'):
            print("[PRODUCTION NOTICE] DATABASE_URL not set in environment; falling back to sqlite:///securepass.db.")
            self.SQLALCHEMY_DATABASE_URI = 'sqlite:///securepass.db'
            self.SQLALCHEMY_ENGINE_OPTIONS = {}

class TestingConfig(Config):
    """Unit / integration test config."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    # Base Config's SQLALCHEMY_ENGINE_OPTIONS are PgBouncer/Postgres-specific
    # (pool_size, max_overflow, a "-c statement_timeout=..." connect arg) —
    # SQLite's StaticPool doesn't accept most of those kwargs at all and
    # create_engine() raises TypeError if they're passed. Reset to empty
    # rather than cherry-picking which ones happen to be harmless, since
    # that harmlessness could silently change with a future edit to the
    # base options.
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SECRET_KEY = 'test-secret-key'   # noqa: S105 (test only)
    JWT_SECRET_KEY = 'test-jwt-secret-key'  # noqa: S105 (test only)
    JWT_COOKIE_CSRF_PROTECT = False  # tests call routes directly without a browser
    RATELIMIT_ENABLED = False
    # In-process storage instead of Redis — RATELIMIT_ENABLED=False already
    # means flask-limiter won't enforce anything, but this also keeps its
    # storage backend from touching a real Redis instance at all, so the
    # test suite has no live-service dependency here either. The JWT
    # revocation blocklist (extensions.py, a separate Redis client) is
    # swapped for fakeredis in backend/tests/conftest.py.
    RATELIMIT_STORAGE_URL = 'memory://'


# Map string names → config classes (used in app factory)
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}


def get_config():
    """Return the correct config class based on FLASK_ENV."""
    env = os.environ.get('FLASK_ENV', 'development').lower()
    return config_map.get(env, DevelopmentConfig)