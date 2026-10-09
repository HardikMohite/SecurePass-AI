"""
test_multi_user_isolation.py — Comprehensive Multi-User Data Isolation & IDOR Defense Test Suite

Validates all 8 acceptance criteria scenarios required for multi-tenant privacy:
- Test A: New user isolation (clean initial account, zero sample/leaked data)
- Test B: Cross-user record access & IDOR rejection (403 on foreign analysis access)
- Test C: List, search, and history isolation
- Test D: Dashboard stats and analytics scoping
- Test E: Authentication bypass and user_id parameter tampering resistance
- Test F: Account switching & token revocation (logout blocks further access)
- Test G: Reference dataset separation (1,666 dataset never copied into private tables)
- Test H: Regression validation (valid auth operations, file analysis, reports)
"""

import io
import json
import pytest
from models import Analysis, User, db


def test_scenario_a_new_user_isolation(client, register_user):
    """
    Test A: New user isolation.
    - Register User A and User B.
    - Confirm User B cannot see User A's private records.
    - Confirm User B starts with 0 analyses and empty dashboard.
    - Confirm newly registered accounts do not copy development dataset records.
    """
    user_a = register_user(email="alice@example.com", username="alice")
    user_b = register_user(email="bob@example.com", username="bob")

    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {user_b['access_token']}"}

    # User A uploads a dataset
    file_data = {"file": (io.BytesIO(b"Password123!\nSecretPass2026!\nAcmeCorp99#"), "alice_vault.txt")}
    res_a = client.post("/api/analyze", headers=headers_a, data=file_data, content_type="multipart/form-data")
    assert res_a.status_code == 200

    # User B checks their own history
    res_b_history = client.get("/api/auth/history", headers=headers_b)
    assert res_b_history.status_code == 200
    b_data = res_b_history.get_json()
    assert b_data["total"] == 0
    assert len(b_data["history"]) == 0

    # User B checks their stats
    res_b_stats = client.get("/api/auth/stats", headers=headers_b)
    assert res_b_stats.status_code == 200
    b_stats = res_b_stats.get_json()
    assert b_stats["total_analyses"] == 0
    assert len(b_stats["recent_analyses"]) == 0


def test_scenario_b_cross_user_idor_rejection(client, register_user):
    """
    Test B: Cross-user record access and IDOR defense.
    - User A creates an analysis.
    - User B attempts to access User A's analysis by ID via GET /api/report/<id>.
    - User B attempts to generate compliance evidence pack using User A's analysis_id.
    - User B attempts to generate AI policy using User A's analysis_id.
    - User B attempts to download report PDF using User A's analysis_id.
    - All unauthorized cross-user operations MUST return 403 Forbidden.
    """
    user_a = register_user(email="alice_idor@example.com", username="alice_idor")
    user_b = register_user(email="bob_idor@example.com", username="bob_idor")

    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {user_b['access_token']}"}

    # User A creates an analysis
    file_data = {"file": (io.BytesIO(b"P@ssw0rd2026\nSuperSecure99!\nAdminSecret##"), "alice_confidential.txt")}
    res_a = client.post("/api/analyze", headers=headers_a, data=file_data, content_type="multipart/form-data")
    assert res_a.status_code == 200
    analysis_id = res_a.get_json()["analysis_id"]
    assert analysis_id is not None

    # 1. User B attempts GET /api/report/<id>
    res_b_report = client.get(f"/api/report/{analysis_id}", headers=headers_b)
    assert res_b_report.status_code == 403, "User B must not read User A's report"
    assert "Access denied" in res_b_report.get_json().get("error", "")

    # 2. User B attempts /api/compliance/evidence-pack with analysis_id
    res_b_pack = client.post(
        "/api/compliance/evidence-pack",
        headers=headers_b,
        json={"analysis_id": analysis_id}
    )
    assert res_b_pack.status_code == 403, "User B must not attest evidence pack for User A's analysis"

    # 3. User B attempts /api/ai-policy with analysis_id
    res_b_policy = client.post(
        "/api/ai-policy",
        headers=headers_b,
        json={
            "analysis_id": analysis_id,
            "company_name": "Bob Evil Corp",
            "company_domain": "evilcorp.com"
        }
    )
    assert res_b_policy.status_code == 403, "User B must not generate policy using User A's analysis"

    # 4. User B attempts /api/download-report with analysis_id
    res_b_download = client.post(
        "/api/download-report",
        headers=headers_b,
        json={
            "analysis_id": analysis_id,
            "report_type": "technical",
            "total_passwords": 3,
            "risk_score": 45
        }
    )
    assert res_b_download.status_code == 403, "User B must not export report for User A's analysis"


def test_scenario_c_list_and_history_isolation(client, register_user):
    """
    Test C: List and history isolation.
    - User A creates 2 records.
    - User B creates 1 record.
    - /api/auth/history returns exactly User A's 2 records for User A.
    - /api/auth/history returns exactly User B's 1 record for User B.
    - User B deletes history -> only User B's record is deleted, User A's 2 records remain intact.
    """
    user_a = register_user(email="alice_hist@example.com", username="alice_hist")
    user_b = register_user(email="bob_hist@example.com", username="bob_hist")

    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {user_b['access_token']}"}

    # User A records
    client.post("/api/analyze", headers=headers_a, data={"file": (io.BytesIO(b"Pass1!\nPass2!"), "a1.txt")}, content_type="multipart/form-data")
    client.post("/api/analyze", headers=headers_a, data={"file": (io.BytesIO(b"Pass3!\nPass4!"), "a2.txt")}, content_type="multipart/form-data")

    # User B record
    client.post("/api/analyze", headers=headers_b, data={"file": (io.BytesIO(b"SecretB1!\nSecretB2!"), "b1.txt")}, content_type="multipart/form-data")

    # Verify A history
    res_a_hist = client.get("/api/auth/history", headers=headers_a).get_json()
    assert res_a_hist["total"] == 2
    filenames_a = [item["filename"] for item in res_a_hist["history"]]
    assert "a1.txt" in filenames_a and "a2.txt" in filenames_a
    assert "b1.txt" not in filenames_a

    # Verify B history
    res_b_hist = client.get("/api/auth/history", headers=headers_b).get_json()
    assert res_b_hist["total"] == 1
    filenames_b = [item["filename"] for item in res_b_hist["history"]]
    assert filenames_b == ["b1.txt"]

    # User B deletes their history
    del_res = client.delete("/api/auth/history", headers=headers_b)
    assert del_res.status_code == 200
    assert del_res.get_json()["deleted"] == 1

    # Verify B has 0, A still has 2
    assert client.get("/api/auth/history", headers=headers_b).get_json()["total"] == 0
    assert client.get("/api/auth/history", headers=headers_a).get_json()["total"] == 2


def test_scenario_d_dashboard_and_snapshot_scoping(client, register_user):
    """
    Test D: Dashboard and reports statistics scoping.
    - User A has an active analysis. User B has none.
    - GET /api/ai-policy/snapshot for User A returns has_data: True.
    - GET /api/ai-policy/snapshot for User B returns has_data: False.
    """
    user_a = register_user(email="alice_dash@example.com", username="alice_dash")
    user_b = register_user(email="bob_dash@example.com", username="bob_dash")

    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {user_b['access_token']}"}

    client.post("/api/analyze", headers=headers_a, data={"file": (io.BytesIO(b"PassA123!\nPassA456!"), "alice_dash.txt")}, content_type="multipart/form-data")

    snap_a = client.get("/api/ai-policy/snapshot", headers=headers_a).get_json()
    assert snap_a["has_data"] is True
    assert snap_a["filename"] == "alice_dash.txt"

    snap_b = client.get("/api/ai-policy/snapshot", headers=headers_b).get_json()
    assert snap_b["has_data"] is False


def test_scenario_e_auth_bypass_and_parameter_tampering(app, client, register_user):
    """
    Test E: Authentication bypass and client-supplied user_id tampering resistance.
    - Access without authentication returns 401.
    - Client injecting user_id=1 in request payload cannot spoof ownership.
    """
    # 1. Use unauthenticated client to verify protected endpoints reject requests without token
    unauth_client = app.test_client()
    res_no_auth = unauth_client.get("/api/auth/history")
    assert res_no_auth.status_code == 401

    res_rep_no_auth = unauth_client.get("/api/report/1")
    assert res_rep_no_auth.status_code == 401

    # 2. Register users and test parameter tampering
    user_a = register_user(email="victim@example.com", username="victim")
    user_b = register_user(email="attacker@example.com", username="attacker")

    # Attacker tries to inject user_id in settings
    headers_b = {"Authorization": f"Bearer {user_b['access_token']}"}
    tamper_res = client.put("/api/settings", headers=headers_b, json={"user_id": user_a["user"]["id"], "min_length": 16})
    assert tamper_res.status_code == 200

    # Verify Victim's settings were NOT modified
    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}
    victim_settings = client.get("/api/settings", headers=headers_a).get_json()
    assert victim_settings.get("min_length") != 16, "Tampering with user_id payload must never affect another user"


def test_scenario_f_account_switching_and_logout_isolation(client, register_user):
    """
    Test F: Account switching & logout revocation.
    - User logs in, gets access token.
    - User logs out via POST /api/auth/logout.
    - The old access token is revoked and cannot access private endpoints anymore.
    """
    user_a = register_user(email="alice_switch@example.com", username="alice_switch")
    headers_a = {"Authorization": f"Bearer {user_a['access_token']}"}

    # Verify active access
    check_res = client.get("/api/auth/stats", headers=headers_a)
    assert check_res.status_code == 200

    # Logout
    logout_res = client.post("/api/auth/logout", headers=headers_a)
    assert logout_res.status_code == 200

    # Old token must be rejected
    after_res = client.get("/api/auth/stats", headers=headers_a)
    assert after_res.status_code == 401


def test_scenario_g_dataset_handling_isolation(app, client, register_user):
    """
    Test G: Dataset handling.
    - Verify that registering accounts does NOT insert the 1,666 reference passwords into the Analysis database.
    - Confirm database Analysis table only contains user-submitted analyses.
    """
    user = register_user(email="newbie@example.com", username="newbie")
    user_id = user["user"]["id"]

    with app.app_context():
        count = Analysis.query.filter_by(user_id=user_id).count()
        assert count == 0, "New user account must have 0 analyses in database; sample dataset must never be auto-seeded into user accounts"


def test_scenario_h_regression_normal_workflow(client, register_user):
    """
    Test H: Regression testing of core workflows.
    - Single password checking works for both authenticated and guest users.
    - File upload audit correctly calculates risk scores and associates with user.
    - User can retrieve their own report by ID.
    - Health check returns 200 OK.
    """
    # Health
    assert client.get("/api/health").status_code == 200

    # Guest check password
    pw_res = client.post("/api/check-password", json={"password": "TestingPassword123!"})
    assert pw_res.status_code == 200
    assert "strength_score" in pw_res.get_json()

    # User workflow
    user = register_user(email="workflow_user@example.com", username="workflow_user")
    headers = {"Authorization": f"Bearer {user['access_token']}"}

    # Upload analysis
    file_data = {"file": (io.BytesIO(b"ValidPass123!\nCorrectHorseBatteryStaple"), "workflow.txt")}
    an_res = client.post("/api/analyze", headers=headers, data=file_data, content_type="multipart/form-data")
    assert an_res.status_code == 200
    an_id = an_res.get_json()["analysis_id"]

    # Retrieve own report
    rep_res = client.get(f"/api/report/{an_id}", headers=headers)
    assert rep_res.status_code == 200
    assert rep_res.get_json()["id"] == an_id
    assert rep_res.get_json()["filename"] == "workflow.txt"
