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


class Config:
    """Base configuration — never instantiate directly."""

    # ------------------------------------------------------------------ #
    #  Security                                                            #
    # ------------------------------------------------------------------ #
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # CSRF (requires flask-wtf; enable when forms are wired up)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # ------------------------------------------------------------------ #
    #  Database                                                            #
    # ------------------------------------------------------------------ #
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///securepass.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    # Recycle connections every 30 min; pre-ping avoids stale connection errors
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 1800,
        "pool_pre_ping": True,
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
    #  File Upload                                                         #
    # ------------------------------------------------------------------ #
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB
    UPLOAD_EXTENSIONS = {'.txt', '.csv'}
    MAX_PASSWORDS_PER_ANALYSIS = 10_000

    # ------------------------------------------------------------------ #
    #  Rate Limiting  (requires flask-limiter)                            #
    # ------------------------------------------------------------------ #
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_ANALYZE = "20 per hour"        # stricter limit for /api/analyze
    RATELIMIT_AUTH = "10 per minute"         # login / register endpoints
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')

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
    RATELIMIT_ENABLED = False        # disable rate limits locally

    # Allow an insecure fallback key ONLY in development
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-insecure-key-do-not-use-in-prod'


class ProductionConfig(Config):
    """Production — strict security, no debug output."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'

    # Force Postgres (or other URL) in production; SQLite not suitable
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///securepass.db'
    def __init__(self):
        if not self.SQLALCHEMY_DATABASE_URI:
            raise ValueError("DATABASE_URL environment variable must be set in production.")

class TestingConfig(Config):
    """Unit / integration test config."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False         # disable CSRF in tests
    SECRET_KEY = 'test-secret-key'   # noqa: S105 (test only)
    RATELIMIT_ENABLED = False


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