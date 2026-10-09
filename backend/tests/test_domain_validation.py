"""
backend/tests/test_domain_validation.py — Unit & Integration tests for Domain Validation
and Fake Domain Detection in SecurePass AI.
"""

from ai_engine import validate_domain_name, verify_domain_dns, lookup_company_domain


def test_validate_domain_name_syntax():
    """Verify syntactic domain checks against RFC standards and dummy TLDs."""
    # Valid domains
    ok, clean = validate_domain_name("google.com")
    assert ok is True and clean == "google.com"

    ok, clean = validate_domain_name("https://portal.acme.co.uk/")
    assert ok is True and clean == "portal.acme.co.uk"

    ok, clean = validate_domain_name("sub-domain.enterprise.org")
    assert ok is True and clean == "sub-domain.enterprise.org"

    # Missing TLD
    ok, err = validate_domain_name("nodomain")
    assert ok is False and "missing a top-level domain" in err

    # Reserved fake TLDs
    ok, err = validate_domain_name("corporate.fake")
    assert ok is False and "reserved or non-routable" in err

    ok, err = validate_domain_name("testsite.invalid")
    assert ok is False and "reserved or non-routable" in err

    ok, err = validate_domain_name("dummy.internal")
    assert ok is False and "reserved or non-routable" in err

    # Empty domain
    ok, err = validate_domain_name("")
    assert ok is False and "cannot be empty" in err


def test_fake_domain_rejected_in_lookup():
    """Verify that fake or non-existent domains are flagged and rejected with found=False."""
    result = lookup_company_domain("FakeCompany", "fakedomain999xyz123.com")
    assert result["found"] is False
    assert result["is_fake"] is True
    assert result["dns_resolved"] is False
    assert result["requires_domain"] is True
    assert "could not be resolved" in result["message"]
    assert result["company_info"]["is_fake"] is True


def test_reserved_tld_rejected_in_lookup():
    """Verify that reserved dummy TLDs are rejected immediately."""
    result = lookup_company_domain("FakeCompany", "mycorp.fake")
    assert result["found"] is False
    assert result["is_fake"] is True
    assert result["dns_resolved"] is False
    assert "Invalid or fake domain" in result["message"]


def test_real_domain_accepted_in_lookup():
    """Verify that active, registered domains resolve and synthesize intelligence."""
    result = lookup_company_domain("Acme Corp", "acme.com")
    assert result["found"] is True
    assert result["is_fake"] is False
    assert result["dns_resolved"] is True
    assert result["company_info"]["dns_resolved"] is True
    assert result["company_info"]["resolved_ip"] is not None


def test_company_lookup_api_endpoint(client):
    """POST /api/company-lookup detects fake domains and responds with structured rejection."""
    # Test fake domain
    resp_fake = client.post("/api/company-lookup", json={
        "company_name": "GhostCorp",
        "domain": "ghostfake999nonexistent.xyz"
    })
    assert resp_fake.status_code == 200
    data_fake = resp_fake.get_json()
    assert data_fake["found"] is False
    assert data_fake["is_fake"] is True
    assert data_fake["dns_resolved"] is False

    # Test real domain
    resp_real = client.post("/api/company-lookup", json={
        "company_name": "Google LLC",
        "domain": "google.com"
    })
    assert resp_real.status_code == 200
    data_real = resp_real.get_json()
    assert data_real["found"] is True
    assert data_real["is_fake"] is False
    assert data_real["dns_resolved"] is True
