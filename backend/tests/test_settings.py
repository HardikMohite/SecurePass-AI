import pytest


def test_settings_get_and_update(client, auth_headers):
    # 1. Get initial settings
    resp = client.get("/api/settings", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "settings" in data

    # 2. Update notification and retention settings
    update_payload = {
        "weekly_report": False,
        "breach_alerts": True,
        "score_alerts": True,
        "email_notifications": True,
        "digest_frequency": "weekly",
        "retention_days": 30
    }
    put_resp = client.put("/api/settings", json=update_payload, headers=auth_headers)
    assert put_resp.status_code == 200
    updated = put_resp.get_json()["settings"]
    assert updated["weekly_report"] is False
    assert updated["score_alerts"] is True
    assert updated["digest_frequency"] == "weekly"
    assert updated["retention_days"] == 30


def test_profile_update(client, auth_headers):
    # Update display name
    resp = client.put("/api/settings/profile", json={"username": "Alice Security"}, headers=auth_headers)
    assert resp.status_code == 200
    user_data = resp.get_json()["user"]
    assert user_data["username"] == "Alice Security"

    # Verify /api/auth/me returns updated name
    me_resp = client.get("/api/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    assert me_resp.get_json()["user"]["username"] == "Alice Security"


def test_change_password_flow(client, register_user):
    # Register user with initial password
    initial_pass = "Str0ng!Pass1"
    user_info = register_user(email="pwchange@example.com", password=initial_pass, username="pwtester")
    auth_headers = {"Authorization": f"Bearer {user_info['access_token']}"}

    # 1. Attempt with incorrect current password
    fail_resp = client.post(
        "/api/settings/change-password",
        json={"current_password": "WrongPassword!", "new_password": "NewStr0ng!Pass2"},
        headers=auth_headers
    )
    assert fail_resp.status_code == 400
    assert "Current password is incorrect" in fail_resp.get_json()["error"]

    # 2. Attempt with too short new password
    short_resp = client.post(
        "/api/settings/change-password",
        json={"current_password": initial_pass, "new_password": "short"},
        headers=auth_headers
    )
    assert short_resp.status_code == 400
    assert "at least 8 characters" in short_resp.get_json()["error"]

    # 3. Successful password change
    new_pass = "NewStr0ng!Pass2"
    success_resp = client.post(
        "/api/settings/change-password",
        json={"current_password": initial_pass, "new_password": new_pass},
        headers=auth_headers
    )
    assert success_resp.status_code == 200
    assert "Password updated successfully" in success_resp.get_json()["message"]

    # 4. Old password should now fail login
    login_fail = client.post(
        "/api/auth/login",
        json={"email": "pwchange@example.com", "password": initial_pass}
    )
    assert login_fail.status_code == 401

    # 5. New password should succeed login
    login_ok = client.post(
        "/api/auth/login",
        json={"email": "pwchange@example.com", "password": new_pass}
    )
    assert login_ok.status_code == 200
    assert "access_token" in login_ok.get_json()


def test_storage_and_session_endpoints(client, auth_headers):
    # Storage endpoint
    st_resp = client.get("/api/settings/storage", headers=auth_headers)
    assert st_resp.status_code == 200
    st_data = st_resp.get_json()
    assert "used_mb" in st_data
    assert "analysis_count" in st_data
    assert "limit_mb" in st_data

    # Session endpoint
    sess_resp = client.get("/api/settings/session", headers=auth_headers)
    assert sess_resp.status_code == 200
    sess_data = sess_resp.get_json()
    assert "browser" in sess_data or "os" in sess_data or "created_at" in sess_data
