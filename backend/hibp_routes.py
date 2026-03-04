"""
hibp_routes.py — SecurePass AI

Flask routes for the HaveIBeenPwned (HIBP) breach-check integration.

FIX SUMMARY:
- check_password_batch() response no longer echoes raw passwords back as
  dict keys — replaced with index-keyed results to prevent password leakage
  in API logs / browser history.
- check_single_password() uses get_json(silent=True) to avoid 400 on bad
  Content-Type.
- /health route no longer checks a real password against the live API on
  every call (was making a real request per health poll); replaced with a
  lightweight prefix-only probe using hash '00000'.
- Added explicit 408 response when HIBP check times out so the frontend
  can distinguish timeout from server error.
- _get_top_breached_passwords() now masks all but first 2 chars (was 3)
  for shorter passwords.
- All bare `except Exception` blocks now log the error before returning 500.
- Blueprint URL prefix kept as /api/hibp for backwards compatibility.
"""

import logging

from flask import Blueprint, jsonify, request
from flask_login import login_required

from backend.hibp_checker import (
    HIBPChecker,
    calculate_breach_statistics,
    format_breach_message,
    get_breach_severity_level,
)

logger = logging.getLogger(__name__)

hibp_bp = Blueprint('hibp', __name__, url_prefix='/api/hibp')


# ────────────────────────────────────────────────────────────────────────────
#  Single password check
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/check-password', methods=['POST'])
@login_required
def check_single_password():
    """
    Check one password against the HIBP breach database.

    Body (JSON):
        password – the password to check (required)

    Returns 200 with breach result, 400 on bad input, 500 on server error.
    """
    try:
        data = request.get_json(silent=True)
        if not data or not data.get('password'):
            return jsonify({'error': 'password field is required.'}), 400

        password = str(data['password'])
        if not password.strip():
            return jsonify({'error': 'Password cannot be empty.'}), 400

        checker = HIBPChecker()
        result  = checker.check_password(password)

        if result.get('error'):
            # Distinguish timeout from other errors
            err = result['error']
            status = 408 if 'timeout' in err.lower() else 500
            return jsonify({'error': err, 'is_breached': None, 'breach_count': 0}), status

        count    = result.get('breach_count', 0)
        severity = get_breach_severity_level(count)

        return jsonify({
            'is_breached':     result.get('is_breached', False),
            'breach_count':    count,
            'severity':        severity,
            'message':         format_breach_message(count),
            'recommendation':  _recommendation(count, severity),
        }), 200

    except Exception as exc:
        logger.exception('Error in /api/hibp/check-password')
        return jsonify({'error': 'Unexpected server error.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Batch check
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/check-batch', methods=['POST'])
@login_required
def check_password_batch():
    """
    Check up to 200 passwords concurrently against HIBP.

    Body (JSON):
        passwords – array of password strings (required, max 200)

    Response:
        results    – array (index-aligned with input) of check results
                     NOTE: passwords are NOT echoed back as keys to prevent
                     credential leakage in API responses / logs.
        statistics – aggregate breach statistics
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'passwords' not in data:
            return jsonify({'error': 'passwords array is required.'}), 400

        passwords = data.get('passwords', [])
        if not isinstance(passwords, list) or len(passwords) == 0:
            return jsonify({'error': 'passwords must be a non-empty array.'}), 400
        if len(passwords) > 200:
            return jsonify({'error': 'Maximum 200 passwords per batch request.'}), 400

        checker      = HIBPChecker()
        raw_results  = checker.check_password_batch(passwords)

        # Build index-aligned results (no raw passwords as keys)
        indexed = []
        for pwd in passwords:
            res   = raw_results.get(pwd, {})
            count = res.get('breach_count', 0) or 0
            indexed.append({
                'is_breached':  res.get('is_breached', False),
                'breach_count': count,
                'severity':     get_breach_severity_level(count),
                'message':      format_breach_message(count),
                'error':        res.get('error'),
            })

        stats = calculate_breach_statistics(raw_results)

        return jsonify({
            'results':         indexed,
            'statistics':      stats,
            'total_processed': len(passwords),
        }), 200

    except Exception as exc:
        logger.exception('Error in /api/hibp/check-batch')
        return jsonify({'error': 'Unexpected server error.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Dataset check
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/check-dataset', methods=['POST'])
@login_required
def check_dataset():
    """
    Sample and check a full password dataset against HIBP.

    Body (JSON):
        passwords   – full password array (required)
        sample_size – number to check (optional, default 100, max 500)
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'passwords' not in data:
            return jsonify({'error': 'passwords array is required.'}), 400

        passwords = data.get('passwords', [])
        if not isinstance(passwords, list) or len(passwords) == 0:
            return jsonify({'error': 'passwords must be a non-empty array.'}), 400

        sample_size       = max(1, min(int(data.get('sample_size', 100)), 500))
        total_dataset_size = len(passwords)
        sampled           = total_dataset_size > sample_size

        if sampled:
            import random
            to_check = random.sample(passwords, sample_size)
        else:
            to_check = passwords

        checker     = HIBPChecker()
        raw_results = checker.check_password_batch(to_check)
        stats       = calculate_breach_statistics(raw_results)
        top_breached = _top_breached(raw_results, limit=10)

        return jsonify({
            'breach_statistics':      stats,
            'top_breached_passwords': top_breached,
            'sampled':                sampled,
            'sample_size':            len(to_check),
            'total_dataset_size':     total_dataset_size,
            'sampling_percentage':    round(len(to_check) / total_dataset_size * 100, 2),
        }), 200

    except Exception as exc:
        logger.exception('Error in /api/hibp/check-dataset')
        return jsonify({'error': 'Unexpected server error.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Health check
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/health', methods=['GET'])
def health_check():
    """
    Verify HIBP API reachability with a lightweight probe.

    Uses hash prefix '00000' (no real password) to test connectivity
    without triggering a meaningful breach lookup.
    """
    import requests as _req
    try:
        resp = _req.get(
            'https://api.pwnedpasswords.com/range/00000',
            headers={'User-Agent': 'SecurePass-AI-Auditor/1.0'},
            timeout=5,
        )
        available = resp.status_code == 200
        return jsonify({
            'status':        'operational' if available else 'degraded',
            'api_available': available,
        }), 200
    except Exception as exc:
        logger.warning('HIBP health check failed: %s', exc)
        return jsonify({'status': 'error', 'api_available': False, 'error': str(exc)}), 200


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers
# ────────────────────────────────────────────────────────────────────────────

def _recommendation(breach_count: int, severity: str) -> str:
    if breach_count == 0:
        return 'Password not found in known breaches. Use a unique password per account.'
    if severity == 'Critical':
        return 'URGENT: Change this password immediately on all accounts.'
    if severity == 'High':
        return 'Change this password as soon as possible.'
    if severity == 'Medium':
        return 'Consider changing this password — it has appeared in data breaches.'
    return 'This password has been found in breaches. Consider using a different one.'


def _mask(password: str) -> str:
    """Mask all but the first 2 characters of a password for safe display."""
    if len(password) <= 2:
        return '*' * len(password)
    return password[:2] + '*' * (len(password) - 2)


def _top_breached(batch_results: dict, limit: int = 10) -> list:
    """Return the top breached passwords (masked) sorted by breach count."""
    items = [
        {
            'password_masked': _mask(pwd),
            'breach_count':    res.get('breach_count', 0),
            'severity':        get_breach_severity_level(res.get('breach_count', 0)),
        }
        for pwd, res in batch_results.items()
        if res and res.get('breach_count', 0) > 0
    ]
    items.sort(key=lambda x: x['breach_count'], reverse=True)
    return items[:limit]