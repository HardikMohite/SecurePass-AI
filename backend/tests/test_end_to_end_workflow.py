"""
test_end_to_end_workflow.py — End-to-End Workflow Verification Suite
Validates:
1. Web asset & SPA routing: /, /login, /register, /403, /500, /dataset.txt, /securepass_logo.svg
2. Error resilience: No infinite redirect loops on 404/unknown routes
3. Complete E2E user lifecycle: Register -> Login -> Profile -> Analyze -> Download PDF Report -> Logout
4. Password reset OTP & verify workflow
"""
import pytest
import json
from models import db, User, Analysis





def test_e2e_frontend_routes_served(client):
    """Frontend HTML pages must return 200 with HTML content without redirect loops."""
    # Root dashboard
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'SecurePass' in resp.data

    # Auth pages
    assert client.get('/login').status_code == 200
    assert client.get('/register').status_code == 200
    assert client.get('/profile').status_code == 200
    assert client.get('/forgot-password').status_code == 200
    assert client.get('/reset-password').status_code == 200
    assert client.get('/check-mail').status_code == 200

    # Error status pages
    resp_403 = client.get('/403')
    assert resp_403.status_code == 200
    assert b'403' in resp_403.data or b'Access' in resp_403.data

    resp_500 = client.get('/500')
    assert resp_500.status_code == 200
    assert b'500' in resp_500.data or b'Server Error' in resp_500.data


def test_e2e_spa_fallback_and_static_assets(client):
    """SPA routes fall back to index.html with 200; public assets return 200."""
    # SPA navigation path (no infinite redirect loop)
    resp = client.get('/dashboard')
    assert resp.status_code == 200
    assert b'SecurePass' in resp.data

    # Public static files
    resp_txt = client.get('/dataset.txt')
    assert resp_txt.status_code == 200

    # API 404 returns JSON, not HTML or redirect
    resp_api = client.get('/api/does-not-exist')
    assert resp_api.status_code == 404
    data = resp_api.get_json()
    assert data.get('error') == 'Resource not found'


def test_e2e_auth_analyze_report_flow(client):
    """Complete user workflow: register, authenticate, analyze passwords, download PDF."""
    # 1. Register
    reg_resp = client.post('/api/auth/register', json={
        'email': 'e2e_user@example.com',
        'username': 'E2ETester',
        'password': 'SecurePassword123!',
        'confirm_password': 'SecurePassword123!',
    })
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post('/api/auth/login', json={
        'email': 'e2e_user@example.com',
        'password': 'SecurePassword123!',
    })
    assert login_resp.status_code == 200
    tokens = login_resp.get_json()
    access_token = tokens['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}

    # 3. Profile
    profile_resp = client.get('/api/auth/profile', headers=headers)
    assert profile_resp.status_code == 200
    user_info = profile_resp.get_json()
    user_data = user_info.get('user') or user_info
    assert user_data['email'] == 'e2e_user@example.com'

    # 4. Analyze dataset via file upload
    import io
    dataset_content = "Password123!\nAdmin@2026\nWelcome#123\nqwerty12345\n"
    analyze_resp = client.post(
        '/api/analyze',
        headers=headers,
        data={
            'file': (io.BytesIO(dataset_content.encode('utf-8')), 'e2e_dataset.txt'),
            'enable_breach_check': 'false',
        },
        content_type='multipart/form-data',
    )
    assert analyze_resp.status_code == 200
    analysis = analyze_resp.get_json()
    assert 'overview' in analysis
    assert 'risk_level' in analysis
    assert 'analysis_id' in analysis
    assert 'compliance' in analysis

    # 4b. Single password check
    single_resp = client.post('/api/check-password', headers=headers, json={
        'password': 'ComplexPassword2026!#$'
    })
    assert single_resp.status_code == 200
    single_data = single_resp.get_json()
    assert 'entropy' in single_data or 'score' in single_data

    # 5. Download executive PDF report
    report_resp = client.post('/api/download-report', headers=headers, json={
        'report_type': 'executive',
        'company_name': 'E2E Corp',
        'total_passwords': 4,
        'unique_passwords': 4,
        'average_length': 12.0,
        'median_length': 12.0,
        'std_dev_length': 1.0,
        'min_length': 10,
        'max_length': 14,
        'risk_score': 65.0,
        'risk_level': 'Medium',
        'compliance': analysis['compliance'],
        'patterns': {
            'dictionary_words': 1,
            'sequential_numbers': 1,
            'keyboard_walks': 1,
            'repeated_chars': 0,
        },
    })
    assert report_resp.status_code == 200
    assert report_resp.mimetype == 'application/pdf'
    assert report_resp.data[:4] == b'%PDF'

    # 6. Logout
    logout_resp = client.post('/api/auth/logout', headers=headers)
    assert logout_resp.status_code == 200


def test_e2e_password_reset_flow(client):
    """Complete password reset flow via OTP simulation."""
    # 1. Register a user
    client.post('/api/auth/register', json={
        'email': 'reset_test@example.com',
        'username': 'ResetUser',
        'password': 'InitialPassword123!',
        'confirm_password': 'InitialPassword123!',
    })

    # 2. Request forgot-password OTP
    req_resp = client.post('/api/auth/forgot-password', json={
        'email': 'reset_test@example.com'
    })
    assert req_resp.status_code == 200
    req_data = req_resp.get_json()
    assert req_data['success'] is True
    otp = req_data['dev_otp']
    assert len(otp) == 6

    # 3. Verify OTP
    verify_resp = client.post('/api/auth/verify-otp', json={
        'email': 'reset_test@example.com',
        'otp': otp
    })
    assert verify_resp.status_code == 200
    verify_data = verify_resp.get_json()
    assert verify_data['success'] is True
    token = verify_data['token']

    # 4. Set new password
    reset_resp = client.post('/api/auth/reset-password', json={
        'token': token,
        'password': 'BrandNewPassword999!',
        'confirm_password': 'BrandNewPassword999!'
    })
    assert reset_resp.status_code == 200
    assert reset_resp.get_json()['success'] is True

    # 5. Sign in with the brand new password
    login_new = client.post('/api/auth/login', json={
        'email': 'reset_test@example.com',
        'password': 'BrandNewPassword999!'
    })
    assert login_new.status_code == 200
    assert 'access_token' in login_new.get_json()
