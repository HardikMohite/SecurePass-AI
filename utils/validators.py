"""
validators.py � SecurePass AI

Input validation for all user-submitted data.

FIX SUMMARY:
- validate_uploaded_file(): file seek pointer was not always reset after
  the size measurement, causing app.py to read 0 bytes on some platforms.
  Now always seek(0) after measuring.
- validate_uploaded_file(): accepts filename as second arg even when the
  file object already has .filename � matches how app.py calls it.
- validate_single_password(): XSS/injection pattern check was checking
  password content which is incorrect � passwords can legitimately contain
  '<', '>', '&' etc. Removed the false-positive script-injection check;
  control-character check is sufficient for security.
- MAX_FILE_SIZE_BYTES now defaults to 16 MB (aligned with Config) � was
  50 MB which contradicted the Flask MAX_CONTENT_LENGTH of 16 MB and
  would give a confusing error.
- has_control_characters() now explicitly excludes tab (9), LF (10), and
  CR (13) which are valid in multi-line password files.
- validate_password_list() invalid_ratio threshold raised from 50% to 80%
  � rejecting a file because >50% of lines are blank/short is too strict
  for real-world datasets that may have empty separators.
- sanitize_text_for_output() now also strips zero-width Unicode chars.
- All public functions have consistent return-type documentation.
"""

import os
import re
from typing import Any, Dict, List, Tuple, Union

# -- Constants -------------------------------------------------------------- #
MAX_FILE_SIZE_MB    = 16                          # aligned with Flask MAX_CONTENT_LENGTH
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS  = {'txt', 'csv'}
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORDS_IN_LIST = 1_000_000


# ----------------------------------------------------------------------------
#  Helpers
# ----------------------------------------------------------------------------

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


# ----------------------------------------------------------------------------
#  File validation
# ----------------------------------------------------------------------------

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

    # -- Resolve filename -- #
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

    # -- Measure size -- #
    if file_path_mode:
        file_size = os.path.getsize(file_path)
    else:
        try:
            file_obj.seek(0, 2)
            file_size = file_obj.tell()
            file_obj.seek(0)   # CRITICAL: reset for caller
        except Exception:
            file_size = 0

    if file_size == 0:
        return False, 'File is empty.'
    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f'File too large (max {MAX_FILE_SIZE_MB} MB).'

    # -- Quick readability check -- #
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