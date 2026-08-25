"""API-level tests for the endpoints that exist at Step 2.

Error handling gets the most attention here: the prototype must never answer a
malformed request with a stack trace.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


class TestHealth:
    def test_health_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["risk_config_version"]

    def test_health_reports_component_status_honestly(self, client):
        components = client.get("/api/health").json()["components"]
        assert components["lexical_scorer"]["status"] == "ok"
        assert components["threat_intelligence"]["status"] == "ok"
        assert components["dga_detector"]["status"] == "ok"
        assert components["dga_detector"]["accuracy_claimed"] is None
        assert components["threat_intelligence"]["indicators_total"] > 0
        assert components["risk_engine"]["status"] == "ok"
        assert components["event_store"]["status"] == "ok"

    def test_health_reports_every_component(self, client):
        components = client.get("/api/health").json()["components"]
        for name in ["normalizer", "feature_extractor", "lexical_scorer",
                     "threat_intelligence", "dga_detector", "risk_engine",
                     "event_store"]:
            assert name in components, name
            assert components[name]["status"] == "ok", name


class TestConfigEndpoint:
    def test_exposes_active_policy(self, client):
        body = client.get("/api/config").json()
        assert body["weights"]["threat_intel"] == 0.40
        assert body["weights"]["dga"] == 0.35
        assert body["weights"]["lexical"] == 0.25
        assert len(body["bands"]) == 3

    def test_unknown_is_not_treated_as_safe(self, client):
        policy = client.get("/api/config").json()["unknown_domain_policy"]
        assert policy["treat_unknown_as_safe"] is False
        assert policy["unknown_confidence"] == 0.0

    def test_internal_comment_keys_are_stripped(self, client):
        body = client.get("/api/config").json()
        assert not any(key.startswith("_") for key in body["weights"])


class TestFeatureInspection:
    def test_analyses_a_normal_domain(self, client):
        response = client.post("/api/debug/features", json={"domain": "github.com"})
        assert response.status_code == 200
        body = response.json()
        assert body["domain"] == "github.com"
        assert body["registrable_domain"] == "github.com"
        assert body["lexical_score"] < 30
        assert body["extraction_time_ms"] >= 0

    def test_extracts_host_from_url(self, client):
        body = client.post(
            "/api/debug/features", json={"domain": "https://mail.google.com/x"}
        ).json()
        assert body["domain"] == "mail.google.com"
        assert body["was_url"] is True

    def test_dga_like_domain_scores_higher(self, client):
        low = client.post("/api/debug/features", json={"domain": "amazon.com"}).json()
        high = client.post(
            "/api/debug/features", json={"domain": "kq3v9z7jx1p8w.info"}
        ).json()
        assert high["lexical_score"] > low["lexical_score"]

    def test_factors_are_returned_with_explanations(self, client):
        body = client.post(
            "/api/debug/features", json={"domain": "paypal-secure-verify.top"}
        ).json()
        assert body["lexical_factors"]
        for factor in body["lexical_factors"]:
            assert factor["code"] and factor["label"] and factor["detail"]


class TestErrorHandling:
    """A judge entering something strange must get a clear message, not a 500."""

    @pytest.mark.parametrize(
        "domain,expected_code",
        [
            ("", "EMPTY_INPUT"),
            ("   ", "EMPTY_INPUT"),
            ("example..com", "EMPTY_LABEL"),
            ("exa mple.com", "INVALID_LABEL_FORMAT"),
            ("-bad.com", "INVALID_LABEL_FORMAT"),
            ("example.123", "NUMERIC_TLD"),
            ("a" * 64 + ".com", "LABEL_TOO_LONG"),
            ("a" * 5000, "INPUT_TOO_LARGE"),
        ],
    )
    def test_bad_domains_return_400_with_a_code(self, client, domain, expected_code):
        response = client.post("/api/debug/features", json={"domain": domain})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == expected_code
        assert error["message"]

    def test_missing_field_returns_422(self, client):
        response = client.post("/api/debug/features", json={})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_REQUEST"

    def test_wrong_type_returns_422(self, client):
        response = client.post("/api/debug/features", json={"domain": 12345})
        assert response.status_code == 422

    def test_unknown_route_returns_404(self, client):
        assert client.get("/api/does-not-exist").status_code == 404

    @pytest.mark.parametrize(
        "domain",
        [
            "localhost",
            "192.168.1.1",
            "münchen.de",
            "_dmarc.example.com",
            "xn--80ak6aa92e.com",
            "a.b.c.d.e.f.g.example.com",
            "9.9.9.9",
        ],
    )
    def test_unusual_but_valid_input_does_not_crash(self, client, domain):
        assert client.post("/api/debug/features", json={"domain": domain}).status_code == 200


class TestIntelEndpoint:
    def test_known_malicious_domain(self, client):
        body = client.post(
            "/api/intel/lookup", json={"domain": "malware-c2-panel.test"}
        ).json()
        assert body["threat_intelligence"]["verdict"] == "MALICIOUS"
        assert body["signal_score"] == 95.0
        assert body["signal_confidence"] > 0.9

    def test_trusted_domain(self, client):
        body = client.post("/api/intel/lookup", json={"domain": "github.com"}).json()
        assert body["threat_intelligence"]["verdict"] == "TRUSTED"

    def test_unknown_domain_returns_zero_confidence(self, client):
        body = client.post(
            "/api/intel/lookup", json={"domain": "kq3v9z7jx1p8w.info"}
        ).json()
        assert body["threat_intelligence"]["verdict"] == "UNKNOWN"
        assert body["signal_confidence"] == 0.0

    def test_subdomain_of_malicious_domain_matches_parent(self, client):
        body = client.post(
            "/api/intel/lookup", json={"domain": "login.malware-c2-panel.test"}
        ).json()
        assert body["threat_intelligence"]["match_type"] == "parent_domain"

    def test_invalid_domain_still_returns_400(self, client):
        response = client.post("/api/intel/lookup", json={"domain": "bad..domain"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "EMPTY_LABEL"


class TestDGAEndpoint:
    def test_dga_like_domain_scores_high(self, client):
        body = client.post(
            "/api/debug/dga", json={"domain": "xkzqmwvbtrn.xyz"}
        ).json()
        assert body["dga_analysis"]["score"] > 0.8
        assert body["signal_score"] > 80

    def test_legitimate_domain_scores_low(self, client):
        body = client.post("/api/debug/dga", json={"domain": "github.com"}).json()
        assert body["dga_analysis"]["score"] < 0.5

    def test_response_declares_model_type_honestly(self, client):
        body = client.post("/api/debug/dga", json={"domain": "github.com"}).json()
        assert body["dga_analysis"]["model_type"] == "PROTOTYPE_STATISTICAL"

    def test_components_are_exposed_for_explainability(self, client):
        body = client.post("/api/debug/dga", json={"domain": "xkzqmwvbtrn.xyz"}).json()
        components = body["dga_analysis"]["components"]
        assert "bigram_llr" in components
        assert "z_score" in components
        assert "length_factor" in components

    def test_analyses_the_registrable_label(self, client):
        body = client.post(
            "/api/debug/dga", json={"domain": "www.xkzqmwvbtrn.xyz"}
        ).json()
        assert body["analysed_label"] == "xkzqmwvbtrn"

    def test_invalid_domain_returns_400(self, client):
        response = client.post("/api/debug/dga", json={"domain": "bad..domain"})
        assert response.status_code == 400
