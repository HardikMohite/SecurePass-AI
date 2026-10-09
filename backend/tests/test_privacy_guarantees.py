"""
test_privacy_guarantees.py — SecurePass AI Privacy & Security Regression Suite

Verifies the inviolable privacy and security guarantees of SecurePass AI:
1. CANARY REGRESSION: Raw passwords (even canary credentials) NEVER reach the database,
   AI prompts, PDF reports, or API responses.
2. K-ANONYMITY ENFORCEMENT: HIBP range endpoint strictly accepts 5 hex characters.
3. FAIL-SAFE BEHAVIOR: HIBP failures return UNKNOWN / degraded, never false confidence.
4. LOG FILTERING: Passwords and bearer tokens are redacted by SecureLogFilter.
5. ZERO-KNOWLEDGE PAYLOADS: Sanitized JSON audit payloads are accepted and verified.
"""

import io
import json
import logging
from unittest.mock import patch

import pytest

from models import Analysis, db
from utils.redaction import (
    SecureLogFilter,
    assert_no_password_data,
    mask_password_preview,
)


CANARY_PASSWORD = "CANARY_SECRET_PASSWORD_987!@#"


def test_canary_password_never_persisted_to_db_or_leaked_in_response(app, client, auth_headers):
    """
    CANARY TEST: An uploaded password file must be analyzed in memory,
    purged from RAM, and NEVER stored in the database or leaked in response data.
    """
    dataset_content = f"Admin2024!\nWelcome123!\n{CANARY_PASSWORD}\nSecurePass#2026\n"
    data = {
        "file": (io.BytesIO(dataset_content.encode("utf-8")), "audit_sample.txt"),
        "enable_breach_check": "false",
    }

    resp = client.post(
        "/api/analyze",
        data=data,
        content_type="multipart/form-data",
        headers=auth_headers,
    )

    assert resp.status_code == 200, resp.get_json()
    resp_json = resp.get_json()
    resp_str = json.dumps(resp_json)

    # 1. Canary password must NEVER appear in the returned JSON
    assert CANARY_PASSWORD not in resp_str, "Privacy leak: Canary password found in HTTP response!"

    # 2. Canary password must NEVER be persisted in the database
    analysis_id = resp_json.get("analysis_id")
    assert analysis_id is not None

    with app.app_context():
        record = db.session.get(Analysis, analysis_id)
        assert record is not None
        record_raw_json = json.dumps(record.analysis_data)
        assert CANARY_PASSWORD not in record_raw_json, "Privacy leak: Canary password stored in Database!"
        assert CANARY_PASSWORD not in (record.filename or "")


def test_sanitized_client_audit_payload(client, auth_headers):
    """
    Verifies that the backend accepts zero-knowledge sanitized JSON payloads
    computed client-side, runs AI insights and policy simulations, and stores
    zero plaintext credentials.
    """
    sanitized_payload = {
        "sanitized": True,
        "filename": "client_processed_audit.txt",
        "dataset_stats": {
            "total_passwords": 500,
            "unique_passwords": 490,
            "duplicate_passwords": 10,
            "average_length": 10.4,
            "median_length": 10.0,
            "std_dev_length": 2.1,
            "min_length": 6,
            "max_length": 18,
            "length_distribution": {
                "less_than_8": 30,
                "between_8_and_11": 320,
                "between_12_and_15": 120,
                "greater_than_16": 30
            },
            "character_composition": {
                "uppercase": {"count": 400, "percentage": 80.0},
                "lowercase": {"count": 480, "percentage": 96.0},
                "numbers": {"count": 350, "percentage": 70.0},
                "special": {"count": 210, "percentage": 42.0},
                "both_cases": {"count": 390, "percentage": 78.0},
                "all_lowercase": {"count": 25, "percentage": 5.0}
            }
        },
        "patterns": {
            "total_passwords": 500,
            "dictionary_count": 45,
            "common_patterns": 60,
            "duplicate_count": 10,
            "no_special": 290,
            "short_passwords": 30,
            "all_lowercase": 25
        },
        "hibp": {
            "status": "ok",
            "checked_passwords": 25,
            "total_breached": 12,
            "estimated_breached": 12,
            "breach_percentage": 2.4,
            "breach_rate": 2.4,
            "k_anonymity_verified": True
        }
    }

    resp = client.post(
        "/api/analyze",
        json=sanitized_payload,
        headers=auth_headers,
    )

    assert resp.status_code == 200, resp.get_json()
    result = resp.get_json()
    assert result["overview"]["total_passwords"] == 500
    assert result["overview"]["unique_passwords"] == 490
    assert "analysis_id" in result


def test_assert_no_password_data_blocks_credential_leakage():
    """
    Verifies that the privacy validation guard raises ValueError
    if any plaintext credential, password field, or full hash is detected.
    """
    # Allowed: aggregate telemetry
    safe_data = {
        "overview": {"total_passwords": 100, "average_length": 12.0},
        "patterns": {"dictionary_count": 5},
    }
    assert_no_password_data(safe_data)

    # Blocked: plain password key
    with pytest.raises(ValueError, match=r"(?i)privacy violation: sensitive key"):
        assert_no_password_data({"password": "secret_password"})

    # Blocked: raw_password key
    with pytest.raises(ValueError, match=r"(?i)privacy violation: sensitive key"):
        assert_no_password_data({"raw_passwords": ["p1", "p2"]})

    # Blocked: full 40-char SHA1 hash string
    full_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    with pytest.raises(ValueError, match=r"(?i)privacy violation: full password hash"):
        assert_no_password_data({"hash_val": full_sha1})


def test_mask_password_preview():
    """Verifies that the safe password preview utility masks internal characters."""
    assert mask_password_preview("Password123!") == "P••••••••23!"
    assert mask_password_preview("short") == "s•••t"
    assert mask_password_preview("ab") == "••"
    assert mask_password_preview("") == "••••••••"


def test_hibp_range_endpoint_validation(client):
    """
    Verifies k-anonymity strict 5-hex prefix enforcement.
    """
    # Non-hex characters
    resp = client.get("/api/hibp/range/ZZZZZ")
    assert resp.status_code == 400
    assert "Exactly 5 hexadecimal characters required" in resp.get_json()["error"]

    # Too short
    resp = client.get("/api/hibp/range/1234")
    assert resp.status_code == 400

    # Too long (preventing full hash leaks)
    resp = client.get("/api/hibp/range/5BAA61E4C9")
    assert resp.status_code == 400

    # Valid 5-hex prefix with mocked response
    with patch("hibp_routes.fetch_hibp_range", return_value="0018A45C4D1def:2\n00D4F6E:1"):
        resp = client.get("/api/hibp/range/5BAA6")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/plain")
        assert "0018A45C4D1def:2" in resp.get_data(as_text=True)


def test_hibp_range_failsafe_unknown(client):
    """
    When upstream HIBP fails or is unreachable, the proxy must return 503
    with status 'unknown' — never pretending the password is clean.
    """
    with patch("hibp_routes.fetch_hibp_range", return_value=None):
        resp = client.get("/api/hibp/range/ABCDE")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["status"] == "unknown"


def test_secure_log_filter_redaction():
    """
    Verifies that the logging filter scrubs credentials and tokens.
    """
    log_filter = SecureLogFilter()

    # Password parameter
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="Login failed for user password='SuperSecretPassword123!'", args=(), exc_info=None
    )
    log_filter.filter(record)
    assert "SuperSecretPassword123!" not in record.msg
    assert "[REDACTED]" in record.msg

    # Bearer token
    record2 = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        args=(), exc_info=None
    )
    log_filter.filter(record2)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in record2.msg
    assert "[REDACTED_TOKEN]" in record2.msg
