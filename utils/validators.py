"""
validators.py — SecurePass AI

Input validation for all user-submitted data.

FIX SUMMARY:
- validate_uploaded_file(): file seek pointer was not always reset after
  the size measurement, causing app.py to read 0 bytes on some platforms.
  Now always seek(0) after measuring.
- validate_uploaded_file(): accepts filename as second arg even when the
  file object already has .filename — matches how app.py calls it.
- validate_single_password(): XSS/injection pattern check was checking
  password content which is incorrect — passwords can legitimately contain
  '<', '>', '&' etc. Removed the false-positive script-injection check;
  control-character check is sufficient for security.
- MAX_FILE_SIZE_BYTES now defaults to 16 MB (aligned with Config) — was
  50 MB which contradicted the Flask MAX_CONTENT_LENGTH of 16 MB and
  would give a confusing error.
- has_control_characters() now explicitly excludes tab (9), LF (10), and
  CR (13) which are valid in multi-line password files.
- validate_password_list() invalid_ratio threshold raised from 50% to 80%
  — rejecting a file because >50% of lines are blank/short is too strict
  for real-world datasets that may have empty separators.
- sanitize_text_for_output() now also strips zero-width Unicode chars.
- All public functions have consistent return-type documentation.
"""

import os
import re
from typing import Any, Dict, List, Tuple, Union

# ── Constants ────────────────────────────────────────────────────────────── #
MAX_FILE_SIZE_MB    = 16                          # aligned with Flask MAX_CONTENT_LENGTH
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS  = {'txt', 'csv'}
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORDS_IN_LIST = 1_000_000


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def is_safe_filename(filename: str) -> bool:
    """Return True if filename contains no path-traversal or null-byte chars."""
    if not filename:
        return False
    dangerous = ['..', '/', '\\', '\0', '\n', '\r']
    if any(d in filename for d in dangerous):
        return False
    if filename.startswith('.'):
        return False
    return True


def get_file_extension(filename: str) -> str:
    """Return the lowercase extension (without dot), or '' if none."""
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()


def has_control_characters(text: str) -> bool:
    """
    Return True if *text* contains ASCII control characters.

    Allowed (excluded from check): tab (9), newline (10), carriage return (13).
    These appear legitimately in multi-line text and CSV files.
    """
    if not isinstance(text, str):
        return False
    allowed = {9, 10, 13}
    return any((ord(c) < 32 and ord(c) not in allowed) or ord(c) == 127
               for c in text)


# ────────────────────────────────────────────────────────────────────────────
#  File validation
# ────────────────────────────────────────────────────────────────────────────

def validate_uploaded_file(
    file_obj,
    filename: str = None,
) -> Tuple[bool, str]:
    """
    Validate a Flask file-upload object or filesystem path.

    Returns:
        (True,  filename)      on success
        (False, error_message) on failure

    IMPORTANT: The file seek pointer is always reset to 0 before returning
    so the caller can immediately call file_obj.read().
    """
    if file_obj is None:
        return False, 'No file provided.'

    # ── Resolve filename ── #
    if isinstance(file_obj, str):
        # Filesystem path was passed
        file_path = file_obj
        if not os.path.exists(file_path):
            return False, 'File does not exist.'
        if not os.path.isfile(file_path):
            return False, 'Path is not a file.'
        filename  = os.path.basename(file_path)
        file_path_mode = True
    else:
        file_path      = None
        file_path_mode = False
        if filename is None and hasattr(file_obj, 'filename'):
            filename = file_obj.filename

    if not filename:
        return False, 'Invalid or missing filename.'

    if not is_safe_filename(filename):
        return False, 'Unsafe filename detected (possible path traversal).'

    ext = get_file_extension(filename)
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type '.{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}."

    # ── Measure size ── #
    if file_path_mode:
        file_size = os.path.getsize(file_path)
    else:
        try:
            pos = file_obj.tell() if hasattr(file_obj, 'tell') else 0
            file_obj.seek(0, 2)
            file_size = file_obj.tell()
            file_obj.seek(0)   # CRITICAL: reset for caller
        except Exception:
            file_size = 0

    if file_size == 0:
        return False, 'File is empty.'
    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f'File too large (max {MAX_FILE_SIZE_MB} MB).'

    # ── Quick readability check ── #
    try:
        if file_path_mode:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                sample = fh.read(256)
        else:
            raw = file_obj.read(256)
            file_obj.seek(0)   # reset again after sample read
            sample = raw.decode('utf-8', errors='ignore') if isinstance(raw, bytes) else raw

        if not sample or not sample.strip():
            return False, 'File appears empty or unreadable.'
    except Exception:
        return False, 'Could not read file.'

    return True, filename


# ────────────────────────────────────────────────────────────────────────────
#  Password list validation
# ────────────────────────────────────────────────────────────────────────────

def validate_password_list(
    password_list: List[str],
) -> Tuple[bool, Union[List[str], str]]:
    """
    Validate and clean a list of passwords.

    Returns:
        (True,  cleaned_list)  on success
        (False, error_message) on failure
    """
    if password_list is None:
        return False, 'Password list is None.'
    if not isinstance(password_list, list):
        return False, 'Password list must be a list.'
    if len(password_list) == 0:
        return False, 'Password list is empty.'
    if len(password_list) > MAX_PASSWORDS_IN_LIST:
        return False, f'Too many passwords (max {MAX_PASSWORDS_IN_LIST:,}).'

    cleaned   = []
    invalid_n = 0

    for item in password_list:
        if not isinstance(item, str):
            invalid_n += 1
            continue
        p = item.strip()
        if not p:
            invalid_n += 1
            continue
        if len(p) > MAX_PASSWORD_LENGTH:
            invalid_n += 1
            continue
        if has_control_characters(p):
            invalid_n += 1
            continue
        cleaned.append(p)

    if not cleaned:
        return False, 'No valid passwords found in list.'

    # Raised from 50% → 80% threshold to tolerate sparse real-world files
    if invalid_n > len(password_list) * 0.80:
        return False, f'Too many invalid entries ({invalid_n} of {len(password_list)}).'

    return True, cleaned


def validate_single_password(password) -> Tuple[bool, str]:
    """
    Validate a single password for the /api/check-password endpoint.

    Returns:
        (True,  cleaned_password)  on success
        (False, error_message)     on failure

    Note: Passwords may legitimately contain '<', '>', '&', quotes, etc.
    Only null bytes and other actual control characters are rejected.
    """
    if password is None:
        return False, 'Password is required.'
    if not isinstance(password, str):
        return False, 'Password must be a string.'

    p = password.strip()
    if not p:
        return False, 'Password cannot be empty.'
    if len(p) < MIN_PASSWORD_LENGTH:
        return False, f'Password too short (minimum {MIN_PASSWORD_LENGTH} character).'
    if len(p) > MAX_PASSWORD_LENGTH:
        return False, f'Password too long (maximum {MAX_PASSWORD_LENGTH} characters).'
    if has_control_characters(p):
        return False, 'Password contains invalid control characters.'

    return True, p


# ────────────────────────────────────────────────────────────────────────────
#  File content extraction
# ────────────────────────────────────────────────────────────────────────────

def validate_file_content(
    file_obj,
    max_lines: int = None,
) -> Tuple[bool, Union[List[str], str]]:
    """
    Extract and validate text lines from a file object or path.

    Returns:
        (True,  list_of_non_empty_lines)
        (False, error_message)
    """
    try:
        if isinstance(file_obj, str):
            with open(file_obj, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        else:
            if hasattr(file_obj, 'seek'):
                file_obj.seek(0)
            raw = file_obj.read() if hasattr(file_obj, 'read') else None
            if raw is None:
                return False, 'Cannot read from file object.'
            content = raw.decode('utf-8', errors='ignore') if isinstance(raw, bytes) else raw

        if not content or not content.strip():
            return False, 'File content is empty.'

        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        if not lines:
            return False, 'No valid lines found in file.'
        if max_lines and len(lines) > max_lines:
            return False, f'Too many lines (max {max_lines:,}).'

        return True, lines

    except Exception:
        return False, 'Error reading file content.'


# ────────────────────────────────────────────────────────────────────────────
#  Dataset validation (used by older code paths)
# ────────────────────────────────────────────────────────────────────────────

def validate_dataset_for_analysis(
    password_list: List[str],
) -> Tuple[bool, Union[Dict[str, Any], str]]:
    """
    Validate and summarise a password list before full analysis.

    Returns:
        (True,  summary_dict)
        (False, error_message)
    """
    ok, result = validate_password_list(password_list)
    if not ok:
        return False, result

    cleaned = result
    return True, {
        'total_passwords': len(cleaned),
        'unique_passwords': len(set(cleaned)),
        'cleaned_list':   cleaned,
        'min_length':     min(len(p) for p in cleaned),
        'max_length':     max(len(p) for p in cleaned),
        'avg_length':     sum(len(p) for p in cleaned) / len(cleaned),
    }


# ────────────────────────────────────────────────────────────────────────────
#  Sanitisation
# ────────────────────────────────────────────────────────────────────────────

def sanitize_text_for_output(text, max_length: int = 100) -> str:
    """
    Sanitise a string for safe inclusion in API responses or logs.

    Strips ASCII control chars and zero-width Unicode characters.
    Truncates to max_length with '…' suffix.
    """
    if not isinstance(text, str):
        text = str(text)

    # Remove ASCII control chars (except tab/LF/CR)
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    # Remove zero-width and other invisible Unicode
    text = re.sub(r'[\u200B-\u200D\uFEFF\u00AD]', '', text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + '…'

    return text


# ────────────────────────────────────────────────────────────────────────────
#  Analysis parameter validation
# ────────────────────────────────────────────────────────────────────────────

def validate_analysis_parameters(
    params,
) -> Tuple[bool, Union[Dict[str, Any], str]]:
    """
    Validate optional analysis parameter dict from API requests.

    Returns (True, validated_dict) or (False, error_message).
    """
    if params is None:
        return True, {}
    if not isinstance(params, dict):
        return False, 'Parameters must be a dictionary.'

    validated: Dict[str, Any] = {}

    if 'min_length' in params:
        try:
            v = int(params['min_length'])
            if not (1 <= v <= 128):
                return False, 'min_length must be between 1 and 128.'
            validated['min_length'] = v
        except (ValueError, TypeError):
            return False, 'min_length must be an integer.'

    if 'max_results' in params:
        try:
            v = int(params['max_results'])
            if not (1 <= v <= 1000):
                return False, 'max_results must be between 1 and 1000.'
            validated['max_results'] = v
        except (ValueError, TypeError):
            return False, 'max_results must be an integer.'

    if 'include_patterns' in params:
        if not isinstance(params['include_patterns'], bool):
            return False, 'include_patterns must be a boolean.'
        validated['include_patterns'] = params['include_patterns']

    return True, validated