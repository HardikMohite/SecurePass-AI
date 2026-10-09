"""
extensions.py — Shared Flask extension instances.

Instantiated here (uninitialised) and bound to the app in create_app() via
<ext>.init_app(app). Keeping them out of app.py lets blueprints and helper
modules (auth_utils.py, auth.py, settings_backend.py, backend/hibp_routes.py)
import an already-configured extension without pulling in the whole app
module and risking circular imports.

── JWT revocation strategy ──────────────────────────────────────────────
Flask-JWT-Extended needs somewhere to record "this token's jti is revoked"
so /api/auth/logout can actually invalidate a token before it naturally
expires. Two options exist:

  1. In-memory set/dict on the Flask process.
  2. An external store (Redis) shared by every process.

We use Redis. An in-memory blocklist is process-local: it's wiped on every
restart/deploy (a "logged out" token becomes valid again), and with more
than one gunicorn worker or app instance behind a load balancer, a token
revoked on worker A is still accepted by worker B — logout would only
work about 1/N of the time. Redis fixes both: it's a shared store every
instance reads from, and we set each blocklist entry to expire (via
SETEX) at the same time the token itself would have expired anyway, so
the blocklist never grows unbounded and needs no manual cleanup job.
The project is already planning to run Redis for flask-limiter, so this
reuses that same infrastructure rather than introducing a new dependency.
"""
import os

import redis
from flask import jsonify
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request

# ── JWT ──────────────────────────────────────────────────────────────────
jwt = JWTManager()

# ── Redis ────────────────────────────────────────────────────────────────
# redis.from_url() connects lazily with short connect timeout to avoid blocking
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=0.1, socket_timeout=0.1)

_BLOCKLIST_PREFIX = 'jwt_blocklist:'
_in_memory_blocklist = {}
_redis_available = None
_last_redis_check = 0


def _is_redis_alive() -> bool:
    """Fast liveness check with 15-second negative caching to prevent socket timeouts."""
    global _redis_available, _last_redis_check
    import time
    now = time.time()
    if _redis_available is False and (now - _last_redis_check) < 15:
        return False
    try:
        redis_client.ping()
        _redis_available = True
        _last_redis_check = now
        return True
    except Exception:
        _redis_available = False
        _last_redis_check = now
        return False


def revoke_token(jti: str, expires_in: int) -> None:
    """
    Mark a token's jti as revoked in Redis (or in-memory fallback if Redis
    is unreachable) until it would have expired naturally anyway.
    """
    if expires_in > 0:
        if _is_redis_alive():
            try:
                redis_client.setex(f'{_BLOCKLIST_PREFIX}{jti}', expires_in, 'revoked')
                return
            except Exception:
                pass
        import time
        _in_memory_blocklist[jti] = time.time() + expires_in


@jwt.token_in_blocklist_loader
def _check_if_token_revoked(jwt_header, jwt_payload) -> bool:
    jti = jwt_payload.get('jti')
    if not jti:
        return True

    # 1. Check explicit JTI blocklist (Redis or in-memory fallback)
    if _is_redis_alive():
        try:
            if redis_client.exists(f'{_BLOCKLIST_PREFIX}{jti}') == 1:
                return True
        except Exception:
            pass
    import time
    exp = _in_memory_blocklist.get(jti)
    if exp and exp > time.time():
        return True

    # 2. Check password_changed_at global invalidation (NIST SP 800-63B)
    user_id = jwt_payload.get('sub')
    token_iat = jwt_payload.get('iat')
    if user_id and token_iat:
        try:
            import datetime
            from models import User
            user = User.query.get(int(user_id))
            if user and user.password_changed_at:
                dt = user.password_changed_at
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                pw_changed_ts = int(dt.timestamp())
                if token_iat < pw_changed_ts:
                    return True
        except Exception:
            pass

    return False


# ── Error responses ────────────────────────────────────────────────────── #
# Mirrors the JSON shape the old flask_login `unauthorized_handler` returned,
# split out per failure mode now that Flask-JWT-Extended distinguishes them.

@jwt.unauthorized_loader
def _missing_token(reason):
    return jsonify({
        'error': 'Authentication required.',
        'message': 'Please log in to access this feature.',
    }), 401


@jwt.invalid_token_loader
def _invalid_token(reason):
    return jsonify({
        'error': 'Invalid authentication token.',
        'message': 'Please log in again.',
    }), 401


@jwt.expired_token_loader
def _expired_token(jwt_header, jwt_payload):
    token_type = jwt_payload.get('type', 'token')
    return jsonify({
        'error': 'Token expired.',
        'message': 'Please refresh your session.' if token_type == 'access' else 'Please log in again.',
    }), 401


@jwt.revoked_token_loader
def _revoked_token(jwt_header, jwt_payload):
    return jsonify({
        'error': 'Token revoked.',
        'message': 'Please log in again.',
    }), 401


# ── Rate limiting ──────────────────────────────────────────────────────── #
# Constructed here (not in app.py) so blueprint routes in auth.py and
# backend/hibp_routes.py can `from extensions import limiter` and apply
# @limiter.limit(...) directly — those decorators execute at import time,
# before create_app() has built an app, so the Limiter object itself must
# exist at module-import time too. limiter.init_app(app) (called from
# create_app()) binds it to the real app and reads RATELIMIT_STORAGE_URL /
# RATELIMIT_DEFAULT / RATELIMIT_ENABLED from app.config.
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _LIMITER_AVAILABLE = True
except ImportError:
    _LIMITER_AVAILABLE = False


def rate_limit_key() -> str:
    """
    Per-user rate limiting when a valid JWT is present, falling back to
    per-IP otherwise.

    Now that auth is JWT-based (not session-cookie-based), keying purely
    on IP would be wrong in both directions: several users can share one
    IP (NAT, office wifi, mobile carrier), and one user can rotate IPs.
    So once a request carries a valid access token we key on the user's
    identity instead. Endpoints with no token yet — /api/auth/login,
    /api/auth/register — and requests with a missing/invalid/expired
    token still fall back to the caller's IP, which is what actually
    protects those endpoints from credential-stuffing / brute force.
    """
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
    except Exception:
        identity = None
    return f'user:{identity}' if identity else f'ip:{get_remote_address()}'


if _LIMITER_AVAILABLE:
    limiter = Limiter(key_func=rate_limit_key)
else:
    class _NullLimiter:
        """No-op stand-in so `@limiter.limit(...)` still works if flask-limiter isn't installed."""

        def init_app(self, app):
            app.logger.warning(
                'flask-limiter not installed — rate limiting disabled. '
                'Install with: pip install "Flask-Limiter[redis]"'
            )

        def limit(self, *_args, **_kwargs):
            def _decorator(f):
                return f
            return _decorator

    limiter = _NullLimiter()
