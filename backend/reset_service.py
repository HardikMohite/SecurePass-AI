"""
Password Reset & OTP Token Service for SecurePass AI
Handles 6-digit OTP generation, expiration, validation, and session tokens.
Supports Redis storage with automatic in-memory fallback.
"""
import time
import secrets
import random
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Fallback in-memory storage: {email: {"otp": str, "token": str, "expires": float, "verified": bool}}
_IN_MEMORY_RESETS = {}
_TOKEN_TO_EMAIL = {}

OTP_EXPIRY_SECONDS = 600  # 10 minutes


def _get_redis_client():
    """Try to import and use the Redis client from extensions if connected."""
    try:
        from extensions import redis_client
        redis_client.ping()
        return redis_client
    except Exception:
        return None


def create_reset_session(email: str) -> Tuple[str, str]:
    """
    Generate a 6-digit numeric OTP and a 32-byte URL-safe reset token for an email.
    Saves to Redis (with 10-min TTL) or in-memory fallback.
    Returns (otp_code, reset_token).
    """
    email_clean = email.strip().lower()
    otp_code = f"{random.randint(100000, 999999)}"
    reset_token = secrets.token_urlsafe(32)
    now = time.time()
    expires_at = now + OTP_EXPIRY_SECONDS

    # 1. Try Redis
    r = _get_redis_client()
    if r:
        try:
            r.setex(f"otp:{email_clean}", OTP_EXPIRY_SECONDS, otp_code)
            r.setex(f"reset_token:{reset_token}", OTP_EXPIRY_SECONDS, email_clean)
            r.setex(f"otp_verified:{email_clean}", OTP_EXPIRY_SECONDS, "0")
            logger.info("Saved OTP & reset token in Redis for %s", email_clean)
            return otp_code, reset_token
        except Exception as exc:
            logger.warning("Redis write failed, falling back to memory: %s", exc)

    # 2. In-memory store
    _IN_MEMORY_RESETS[email_clean] = {
        "otp": otp_code,
        "token": reset_token,
        "expires": expires_at,
        "verified": False,
    }
    _TOKEN_TO_EMAIL[reset_token] = {
        "email": email_clean,
        "expires": expires_at,
    }

    # Clean old expired entries
    for em, data in list(_IN_MEMORY_RESETS.items()):
        if data["expires"] < now:
            _IN_MEMORY_RESETS.pop(em, None)
    for tok, data in list(_TOKEN_TO_EMAIL.items()):
        if data["expires"] < now:
            _TOKEN_TO_EMAIL.pop(tok, None)

    logger.info("Saved OTP & reset token in memory for %s", email_clean)
    return otp_code, reset_token


def verify_otp_code(email: str, entered_otp: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Verify the 6-digit OTP code for an email.
    Returns (is_valid, reset_token, error_message).
    """
    email_clean = email.strip().lower()
    entered_otp = str(entered_otp).strip()

    if not entered_otp or len(entered_otp) != 6:
        return False, None, "Please enter a valid 6-digit verification code."

    # 1. Try Redis
    r = _get_redis_client()
    if r:
        try:
            stored_otp = r.get(f"otp:{email_clean}")
            if not stored_otp:
                return False, None, "Verification code has expired or was never requested."
            if stored_otp != entered_otp:
                return False, None, "Invalid verification code. Please check and try again."

            # Mark verified
            r.setex(f"otp_verified:{email_clean}", OTP_EXPIRY_SECONDS, "1")
            # Generate or return existing reset token for this verified session
            verified_token = secrets.token_urlsafe(32)
            r.setex(f"reset_token:{verified_token}", OTP_EXPIRY_SECONDS, email_clean)
            return True, verified_token, None
        except Exception as exc:
            logger.warning("Redis read failed during OTP verification: %s", exc)

    # 2. In-memory
    now = time.time()
    record = _IN_MEMORY_RESETS.get(email_clean)
    if not record or record["expires"] < now:
        return False, None, "Verification code has expired or was never requested."

    if record["otp"] != entered_otp:
        return False, None, "Invalid verification code. Please check and try again."

    record["verified"] = True
    return True, record["token"], None


def validate_reset_token(token: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a reset token is valid.
    Returns (is_valid, email).
    """
    token_clean = token.strip()
    if not token_clean:
        return False, None

    # 1. Try Redis
    r = _get_redis_client()
    if r:
        try:
            email = r.get(f"reset_token:{token_clean}")
            if email:
                return True, email
        except Exception as exc:
            logger.warning("Redis check failed: %s", exc)

    # 2. In-memory
    now = time.time()
    record = _TOKEN_TO_EMAIL.get(token_clean)
    if record and record["expires"] >= now:
        return True, record["email"]

    return False, None


def consume_reset_token(token: str, email: str) -> None:
    """Invalidate token and OTP after password has been successfully updated."""
    email_clean = email.strip().lower()
    token_clean = token.strip()

    r = _get_redis_client()
    if r:
        try:
            r.delete(f"otp:{email_clean}")
            r.delete(f"reset_token:{token_clean}")
            r.delete(f"otp_verified:{email_clean}")
        except Exception:
            pass

    _IN_MEMORY_RESETS.pop(email_clean, None)
    _TOKEN_TO_EMAIL.pop(token_clean, None)
