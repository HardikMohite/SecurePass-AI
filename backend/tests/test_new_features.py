"""
backend/tests/test_new_features.py — End-to-end tests for all new and updated features:
  - POST /api/ai-policy/generate-passwords (enterprise compliant passphrases)
  - GET & POST /api/compliance/evidence-pack (cryptographic compliance dossier)
  - POST /api/compliance-ai (compliance narrative with deterministic synthesis fallback)
  - Extended map_to_standards (NIST, OWASP, ISO 27001, PCI-DSS v4.0, HIPAA)
  - POST /api/download-report (report_type customization)
"""

import io
from compliance_mapper import map_to_standards


def test_ai_policy_generate_passwords(client, auth_headers):
    """POST /api/ai-policy/generate-passwords returns proper enterprise compliant passphrases."""
    payload = {"count": 6, "org_name": "SecureCorp", "domain": "fintech"}
    resp = client.post(
        "/api/ai-policy/generate-passwords",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert len(data["passwords"]) == 6

    for item in data["passwords"]:
        pw = item["password"]
        assert len(pw) >= 14, f"Password {pw} is too short"
        assert any(c.isupper() for c in pw), f"Password {pw} missing uppercase"
        assert any(c.islower() for c in pw), f"Password {pw} missing lowercase"
        assert any(c.isdigit() for c in pw), f"Password {pw} missing number"
        assert any(not c.isalnum() for c in pw), f"Password {pw} missing special char"
        assert item["is_proper"] is True
        assert item["score"] == 100
        assert "Compliant" in item["compliance"]


def test_compliance_evidence_pack_get(client, auth_headers):
    """GET /api/compliance/evidence-pack streams a text attestation dossier."""
    resp = client.get("/api/compliance/evidence-pack", headers=auth_headers)
    assert resp.status_code == 200
    content = resp.data.decode("utf-8")
    assert "SECUREPASS AI" in content
    assert "NIST SP 800-63B" in content
    assert "PCI-DSS v4.0" in content
    assert "ISO/IEC 27001" in content
    assert "HIPAA" in content
    assert "SHA-256 Digest" in content


def test_compliance_ai_deterministic_fallback(client, auth_headers):
    """POST /api/compliance-ai returns a professional compliance narrative."""
    payload = {
        "nist_status": "Partial Compliance",
        "owasp_risk": "Medium",
        "iso_status": "Partial Compliance",
        "nist_score": 68,
        "owasp_score": 72,
        "iso_score": 65,
        "violations": [
            {"rule": "Dictionary word restriction", "severity": "High"},
            {"rule": "Sequential numeric passwords", "severity": "High"},
        ],
    }
    resp = client.post(
        "/api/compliance-ai",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert isinstance(data["text"], str)
    assert len(data["text"]) > 40
    assert "NIST" in data["text"] or "compliance" in data["text"].lower()


def test_map_to_standards_five_frameworks():
    """map_to_standards must evaluate all 5 major frameworks including PCI-DSS and HIPAA."""
    sample_patterns = {
        "patterns": {
            "dictionary_based": {"count": 15, "percentage": 15.0},
            "name_based": {"count": 5, "percentage": 5.0},
            "keyboard_walk": {"count": 12, "percentage": 12.0},
            "sequential_numbers": {"count": 8, "percentage": 8.0},
            "capitalization_misuse": {"count": 10, "percentage": 10.0},
            "leetspeak": {"count": 4, "percentage": 4.0},
        }
    }
    res = map_to_standards(sample_patterns, 65.0)
    assert "nist_compliance_status" in res
    assert "owasp_risk_level" in res
    assert "iso_compliance_status" in res
    assert "pci_compliance_status" in res
    assert "hipaa_compliance_status" in res

    scores = res["compliance_scores"]
    assert "NIST SP 800-63B" in scores
    assert "OWASP" in scores
    assert "ISO 27001" in scores
    assert "PCI-DSS v4.0" in scores
    assert "HIPAA" in scores


def test_download_report_compliance_pack(client, auth_headers):
    """POST /api/download-report with report_type=compliance generates a PDF."""
    payload = {
        "report_type": "compliance",
        "overview": {
            "total_passwords": 50,
            "weak_passwords": 10,
            "medium_passwords": 15,
            "strong_passwords": 25,
            "average_length": 11.4,
            "risk_score": 62.0,
        },
        "compliance_scores": {
            "NIST SP 800-63B": 75.0,
            "PCI-DSS v4.0": 80.0,
            "HIPAA": 78.0,
            "ISO 27001": 82.0,
            "OWASP": 70.0,
        },
    }
    resp = client.post(
        "/api/download-report",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data[:4] == b"%PDF"


def test_download_report_pdf_with_nested_character_composition(client, auth_headers):
    """POST /api/download-report handles nested dict character composition cleanly."""
    payload = {
        "report_type": "executive",
        "company_name": "TestCorp",
        "total_passwords": 100,
        "unique_passwords": 95,
        "average_length": 12.2,
        "median_length": 12.0,
        "std_dev_length": 2.5,
        "min_length": 8,
        "max_length": 20,
        "risk_score": 70.0,
        "risk_level": "Low",
        "character_composition": {
            "uppercase": {"count": 90, "percentage": 90.0},
            "lowercase": {"count": 95, "percentage": 95.0},
            "numbers": {"count": 80, "percentage": 80.0},
            "special": {"count": 60, "percentage": 60.0},
        },
        "patterns": {
            "dictionary_words": 10,
            "sequential_numbers": 5,
            "keyboard_walks": 3,
            "repeated_chars": 2,
            "date_patterns": 4,
            "l33tspeak": 6,
        },
        "hibp": {
            "total_breached": 2,
            "breach_rate": 2.0,
        },
    }
    resp = client.post(
        "/api/download-report",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data[:4] == b"%PDF"



def test_single_password_check(client):
    """POST /api/check-password returns comprehensive entropy, crack time, and compliance."""
    # Strong enterprise password
    strong_resp = client.post("/api/check-password", json={"password": "Enterprise@Shield2026!"})
    assert strong_resp.status_code == 200
    res = strong_resp.get_json()
    assert "Low" in res["risk_level"]
    assert res["strength_score"] >= 80
    assert res["length"] == len("Enterprise@Shield2026!")
    assert res["entropy"] > 60.0
    assert "Centuries" in res["crack_time"] or "years" in res["crack_time"]
    assert "100% Compliant" in res["compliance_status"]

    # Weak password
    weak_resp = client.post("/api/check-password", json={"password": "123456"})
    assert weak_resp.status_code == 200
    w_res = weak_resp.get_json()
    assert "High" in w_res["risk_level"]
    assert w_res["strength_score"] < 40
    assert "Instant" in w_res["crack_time"]
    assert "Non-Compliant" in w_res["compliance_status"]


def test_txt_upload_analysis(client, auth_headers):
    """POST /api/analyze with .txt file containing passwords."""
    content = b"Password123!\nAdmin#2026\nqwerty\nSecureEnterpriseVault99!"
    data = {"file": (io.BytesIO(content), "passwords.txt")}
    resp = client.post(
        "/api/analyze",
        data=data,
        content_type="multipart/form-data",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    res = resp.get_json()
    assert "overview" in res
    assert res["overview"]["total_passwords"] == 4
    assert "compliance" in res
    assert "compliance_scores" in res["compliance"]


def test_csv_upload_analysis(client, auth_headers):
    """POST /api/analyze with .csv file containing password columns."""
    content = b"username,password,department\njohn_doe,SecretP@ss99,Finance\nalice,123456,Engineering\nbob,VaultMaster#2026,Security\n"
    data = {"file": (io.BytesIO(content), "users.csv")}
    resp = client.post(
        "/api/analyze",
        data=data,
        content_type="multipart/form-data",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    res = resp.get_json()
    assert "overview" in res
    assert res["overview"]["total_passwords"] == 3
    assert "compliance" in res
    assert "compliance_scores" in res["compliance"]


def test_excel_upload_analysis(client, auth_headers):
    """POST /api/analyze with .xlsx file parsed using openpyxl."""
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Credentials"
    ws.append(["User ID", "Email", "Password", "Status"])
    ws.append(["USR-1", "user1@corp.com", "Summer2026!Safe", "Active"])
    ws.append(["USR-2", "user2@corp.com", "welcome123", "Active"])
    ws.append(["USR-3", "user3@corp.com", "UltraSecure#Key2026$", "Active"])
    ws.append(["USR-4", "user4@corp.com", "password", "Disabled"])

    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)

    data = {"file": (bio, "enterprise_audit.xlsx")}
    resp = client.post(
        "/api/analyze",
        data=data,
        content_type="multipart/form-data",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    res = resp.get_json()
    assert "overview" in res
    assert res["overview"]["total_passwords"] == 4
    assert "compliance" in res
    assert "compliance_scores" in res["compliance"]
    assert "risk_score" in res["overview"]



