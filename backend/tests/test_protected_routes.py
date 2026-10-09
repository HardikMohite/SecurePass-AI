"""
A protected route (@jwt_required()) rejects requests with no/invalid
token and accepts requests with a valid one.

/api/auth/stats is used as the representative protected route — it's a
plain `@jwt_required()` endpoint (unlike /api/auth/me and /api/auth/check,
which deliberately use jwt_required(optional=True) so they can respond
200 to anonymous callers too).
"""


def test_protected_route_rejects_missing_token(client):
    resp = client.get("/api/auth/stats")
    assert resp.status_code == 401


def test_protected_route_rejects_garbage_token(client):
    resp = client.get(
        "/api/auth/stats",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_protected_route_accepts_valid_token(client, auth_headers):
    resp = client.get("/api/auth/stats", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "total_analyses" in body
    assert body["total_analyses"] == 0


def test_protected_route_rejects_revoked_token(client, register_user):
    """A logged-out (revoked) access token is rejected even though it
    hasn't expired yet — exercises the Redis-backed blocklist path."""
    body = register_user(email="revoke-me@example.com")
    headers = {"Authorization": f"Bearer {body['access_token']}"}

    logout_resp = client.post("/api/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    resp = client.get("/api/auth/stats", headers=headers)
    assert resp.status_code == 401
