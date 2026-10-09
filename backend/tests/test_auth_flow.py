"""Register + login flow — issues valid JWT access/refresh tokens."""


def test_register_returns_access_and_refresh_tokens(client):
    resp = client.post(
        "/api/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "Str0ng!Pass",
            "username": "newuser",
        },
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["email"] == "newuser@example.com"


def test_register_rejects_duplicate_email(client, register_user):
    register_user(email="dupe@example.com")
    resp = client.post(
        "/api/auth/register",
        json={"email": "dupe@example.com", "password": "Str0ng!Pass"},
    )
    assert resp.status_code == 409


def test_register_rejects_weak_password(client):
    resp = client.post(
        "/api/auth/register",
        json={"email": "weak@example.com", "password": "weak"},
    )
    assert resp.status_code == 400


def test_login_with_correct_credentials_returns_valid_jwt(client, register_user):
    register_user(email="login-test@example.com", password="Str0ng!Pass")

    resp = client.post(
        "/api/auth/login",
        json={"email": "login-test@example.com", "password": "Str0ng!Pass"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    access_token = body["access_token"]
    assert access_token

    # The token must actually be usable against a protected endpoint,
    # not just present in the response body.
    me = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me.status_code == 200
    assert me.get_json()["user"]["email"] == "login-test@example.com"


def test_login_with_wrong_password_returns_401(client, register_user):
    register_user(email="wrongpw@example.com", password="Str0ng!Pass")

    resp = client.post(
        "/api/auth/login",
        json={"email": "wrongpw@example.com", "password": "TotallyWrong1!"},
    )
    assert resp.status_code == 401


def test_login_with_unknown_email_returns_401(client):
    resp = client.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "Str0ng!Pass"},
    )
    assert resp.status_code == 401


def test_login_with_username_success(client, register_user):
    register_user(email="usernametest@example.com", password="Str0ng!Pass", username="SentinelUser")

    # Login with username field
    resp1 = client.post(
        "/api/auth/login",
        json={"username": "SentinelUser", "password": "Str0ng!Pass"},
    )
    assert resp1.status_code == 200
    assert resp1.get_json()["user"]["username"] == "SentinelUser"

    # Login with email field containing username (case-insensitive)
    resp2 = client.post(
        "/api/auth/login",
        json={"email": "sentineluser", "password": "Str0ng!Pass"},
    )
    assert resp2.status_code == 200
    assert resp2.get_json()["user"]["email"] == "usernametest@example.com"


def test_login_session_duration_remember_me(client, register_user):
    register_user(email="sessiontest@example.com", password="Str0ng!Pass", username="SessionUser")

    # When remember=True: 30 days
    resp_remember = client.post(
        "/api/auth/login",
        json={"email": "sessiontest@example.com", "password": "Str0ng!Pass", "remember": True},
    )
    assert resp_remember.status_code == 200
    assert resp_remember.get_json()["session_expiry"] == "30 days"

    # When remember=False: 15 minutes
    resp_normal = client.post(
        "/api/auth/login",
        json={"email": "sessiontest@example.com", "password": "Str0ng!Pass", "remember": False},
    )
    assert resp_normal.status_code == 200
    assert resp_normal.get_json()["session_expiry"] in ("15 minutes", "24 hours")

