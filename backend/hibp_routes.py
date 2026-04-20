"""
hibp_routes.py — SecurePass AI

Flask routes for the HaveIBeenPwned (HIBP) breach-check integration.

This file is updated to use the new, high-performance `hibp_engine`.
"""

import logging

from flask import Blueprint, jsonify, request
from flask_login import login_required

# Import the new high-performance HIBP engine
from backend.hibp_engine import check_password_hibp, check_bulk_passwords

logger = logging.getLogger(__name__)

hibp_bp = Blueprint('hibp', __name__, url_prefix='/api/hibp')


# ────────────────────────────────────────────────────────────────────────────
#  Single password check (Task 8)
# ────────────────────────────────────────────────────────────────────────────

@hibp_bp.route('/check-password', methods=['POST'])
@login_required
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

    except Exception as e:
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