"""
hibp_routes.py — SecurePass AI

Flask routes for the HaveIBeenPwned (HIBP) breach-check integration.

This file is updated to use the new, high-performance `hibp_engine`.
"""

import logging

import re
from flask import Blueprint, jsonify, request, Response
from flask_jwt_extended import jwt_required

# Import high-performance HIBP engine functions
from hibp_engine import check_password_hibp, fetch_hibp_range

logger = logging.getLogger(__name__)

hibp_bp = Blueprint('hibp', __name__, url_prefix='/api/hibp')


# ────────────────────────────────────────────────────────────────────────────
#  Privacy-Preserving k-Anonymity Range Proxy (Client never sends password)
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/range/<prefix>', methods=['GET'])
def get_range(prefix: str):
    """
    Privacy-first HIBP k-Anonymity range proxy.
    Accepts ONLY a 5-character hexadecimal SHA-1 hash prefix.
    Clients compute the hash locally and match suffixes locally.
    Neither plaintext passwords nor full hashes ever reach our server or HIBP.
    """
    clean_prefix = (prefix or '').strip().upper()
    if not re.match(r'^[0-9A-F]{5}$', clean_prefix):
        return jsonify({
            'success': False,
            'error': 'Invalid prefix. Exactly 5 hexadecimal characters required.'
        }), 400

    raw = fetch_hibp_range(clean_prefix)
    if raw is None:
        return jsonify({
            'success': False,
            'status': 'unknown',
            'error': 'HIBP service unavailable or rate limited.'
        }), 503

    return Response(raw, mimetype='text/plain', headers={
        'Cache-Control': 'public, max-age=86400',
        'X-Privacy-Mode': 'k-anonymity-prefix-only'
    })


# ────────────────────────────────────────────────────────────────────────────
#  Single password check (Task 8)
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/check-password', methods=['POST'])
@jwt_required(optional=True)
def check_single_password_route():
    """
    Check one password against the HIBP breach database using the new engine.
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'password' not in data:
            return jsonify({'success': False, 'error': 'password field is required.'}), 400

        password = data['password']
        result = check_password_hibp(password)

        if result['status'] != 'ok':
            return jsonify({
                'success': False,
                'error': f"HIBP check failed with status: {result['status']}"
            }), 503 # 503 Service Unavailable is appropriate for API issues

        return jsonify({
            'success': True,
            'breached': result['breached'],
            'count': result['count']
        }), 200

    except Exception:
        logger.exception('Error in /api/hibp/check-password route')
        return jsonify({'success': False, 'error': 'An unexpected server error occurred.'}), 500


# ────────────────────────────────────────────────────────────────────────────
#  Health check
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/health', methods=['GET'])
def health_check():
    """
    Verify HIBP API reachability with a lightweight probe using the new engine.
    """
    # We can test reachability by checking a known non-password
    result = check_password_hibp("000000000000000000000")
    api_available = result['status'] == 'ok'

    return jsonify({
        'status': 'operational' if api_available else 'degraded',
        'api_available': api_available,
        'details': result
    }), 200