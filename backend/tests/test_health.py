"""GET /api/health — basic liveness check."""


def test_health_returns_200(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_health_body_reports_ok_status(client):
    resp = client.get("/api/health")
    body = resp.get_json()
    assert body["status"] == "ok"
