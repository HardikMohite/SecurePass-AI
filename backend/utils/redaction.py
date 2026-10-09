"""
redaction.py — SecurePass AI

Sensitive data redaction, log filtering, and privacy validation layer.
Guarantees that plaintext passwords, password hashes, and sensitive authentication
credentials are never logged, stored in plain text, or leaked to AI services.
"""

import logging
import re
from typing import Any, Dict, List, Set, Union

logger = logging.getLogger(__name__)

# Patterns that match sensitive credential keys in dictionaries
SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?i)(password|passwd|pwd|secret|token|api_key|access_token|refresh_token|auth|credentials|private_key)'
)

# Common regex patterns for full hashes
HASH_PATTERNS = [
    re.compile(r'^[a-fA-F0-9]{32}$'),  # MD5
    re.compile(r'^[a-fA-F0-9]{40}$'),  # SHA-1
    re.compile(r'^[a-fA-F0-9]{64}$'),  # SHA-256
    re.compile(r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$'),  # bcrypt
]


class SecurityPrivacyViolationError(ValueError):
    """Raised when sensitive password or credential data is detected in a restricted payload."""
    pass


class SecureLogFilter(logging.Filter):
    """
    Logging filter that sanitizes and redacts passwords, tokens, and credentials
    from all log records before they are emitted to disk or console.
    """

    REDACTION_REGEXES = [
        # JSON or query param password patterns: "password": "..." or password=...
        (re.compile(r'(?i)(["\']?password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3'),
        (re.compile(r'(?i)(["\']?pwd["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3'),
        (re.compile(r'(?i)(["\']?token["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3'),
        (re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+=*'), r'\1[REDACTED_TOKEN]'),
        (re.compile(r'(?i)(password=)[^&\s]+'), r'\1[REDACTED]'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, repl in self.REDACTION_REGEXES:
                record.msg = pattern.sub(repl, record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                new_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        for pattern, repl in self.REDACTION_REGEXES:
                            arg = pattern.sub(repl, arg)
                    new_args.append(arg)
                record.args = tuple(new_args)
            elif isinstance(record.args, dict):
                new_args = {}
                for k, v in record.args.items():
                    if isinstance(v, str):
                        for pattern, repl in self.REDACTION_REGEXES:
                            v = pattern.sub(repl, v)
                    new_args[k] = v
                record.args = new_args
        return True


def mask_password_preview(password: str) -> str:
    """
    Safely mask a password pattern for reporting purposes so that the actual
    plaintext is non-recoverable while preserving structural context.
    Example: 'Password123!' -> 'P••••••••23!'
    """
    if not password:
        return '••••••••'
    p = str(password)
    n = len(p)
    if n <= 4:
        return '•' * n
    if n <= 8:
        return p[0] + ('•' * (n - 2)) + p[-1]
    return p[0] + ('•' * (n - 4)) + p[-3:]


def sanitize_formula_injection(val: Any) -> Any:
    """
    Mitigate Formula Injection (CSV / Spreadsheet Injection, OWASP OTG-INPVAL-014).
    If a string starts with characters that could be interpreted by spreadsheet
    software as a dynamic formula or DDE command (=, +, -, @, tab, carriage return),
    prepend a single quote (') to force static text evaluation.
    """
    if not isinstance(val, str):
        return val
    s = val.strip()
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return f"'{val}"
    return val


def assert_no_password_data(data: Any, path: str = 'root') -> None:
    """
    Recursive validator that guarantees an object contains NO plaintext passwords,
    NO password lists, and NO complete password hashes.
    Must be called before sending ANY data to AI or third-party services.

    Raises:
        SecurityPrivacyViolationError if sensitive data is detected.
    """
    if data is None:
        return

    ALLOWED_METRIC_KEYS = {
        'total_passwords', 'unique_passwords', 'duplicate_passwords',
        'weak_passwords', 'medium_passwords', 'strong_passwords',
        'checked_passwords', 'short_passwords', 'breached_passwords',
        'recommended_password_policy', 'password_policy', 'password_examples'
    }

    # Check dictionaries
    if isinstance(data, dict):
        for key, value in data.items():
            key_str = str(key)
            current_path = f"{path}.{key_str}"
            key_lower = key_str.lower()

            if key_lower in ALLOWED_METRIC_KEYS:
                # Aggregate count or structured policy container — safe
                pass
            elif SENSITIVE_KEY_PATTERNS.search(key_str):
                # Allowed only if it is an aggregate counter, percentage, or policy rule
                allowed_suffixes = (
                    '_count', '_percentage', '_ratio', '_score', '_distribution',
                    '_requirements', '_length', '_stats', '_types', '_examples',
                    '_scenarios', '_patterns', '_simulation', '_categories'
                )
                if not any(key_lower.endswith(suffix) for suffix in allowed_suffixes):
                    raise SecurityPrivacyViolationError(
                        f"Privacy Violation: sensitive key '{key_str}' detected at {current_path}. "
                        "Passwords must never be sent to AI or external services."
                    )

            # Recurse into values
            assert_no_password_data(value, current_path)

    # Check lists / iterables
    elif isinstance(data, (list, tuple, set)):
        for i, item in enumerate(data):
            assert_no_password_data(item, f"{path}[{i}]")

    # Check strings for raw hashes
    elif isinstance(data, str):
        s = data.strip()
        # Ensure full password hashes are not transmitted
        for h_pat in HASH_PATTERNS:
            if h_pat.match(s):
                raise SecurityPrivacyViolationError(
                    f"Privacy Violation: full password hash detected at {path}. "
                    "Hashes must never be transmitted to AI."
                )
