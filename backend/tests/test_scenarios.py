"""The three demonstration scenarios, as executable assertions.

If these pass, the prototype does what it claims on stage. Scenario 3 is the
important one: it proves the system is more than a blacklist.

Persistence is exercised against a temporary database so the suite never
touches the real event log.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.storage.events import EventRepository, set_event_repository


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    database = tmp_path_factory.mktemp("scenarios") / "test.db"
    set_event_repository(EventRepository(path=database))
    yield TestClient(create_app(), raise_server_exceptions=False)
    set_event_repository(None)


def analyse(client, domain):
    response = client.post("/api/analyze", json={"domain": domain})
    assert response.status_code == 200, response.text
    return response.json()


class TestScenario1LegitimateDomain:
    """github.com -> low risk, ALLOW, event recorded."""

    def test_allowed_with_low_risk(self, client):
        result = analyse(client, "github.com")
        assert result["risk_score"] < 30
        assert result["classification"] == "SAFE"
        assert result["decision"] == "ALLOW"

    def test_recognised_by_threat_intelligence(self, client):
        result = analyse(client, "github.com")
        assert result["threat_intelligence"]["verdict"] == "TRUSTED"

    def test_event_is_persisted(self, client):
        result = analyse(client, "wikipedia.org")
        assert result["event_id"] is not None
        events = client.get("/api/events", params={"q": "wikipedia"}).json()
        assert events["total"] >= 1
        assert events["events"][0]["domain"] == "wikipedia.org"


class TestScenario2KnownMaliciousDomain:
    """A controlled indicator from the local dataset -> BLOCK."""

    def test_blocked_with_high_risk(self, client):
        result = analyse(client, "malware-c2-panel.test")
        assert result["risk_score"] >= 70
        assert result["classification"] == "MALICIOUS"
        assert result["decision"] == "BLOCK"

    def test_threat_intelligence_matched(self, client):
        result = analyse(client, "malware-c2-panel.test")
        ti = result["threat_intelligence"]
        assert ti["verdict"] == "MALICIOUS"
        assert ti["matched_indicator"] == "malware-c2-panel.test"
        assert "c2" in ti["categories"]

    def test_floor_override_was_applied(self, client):
        result = analyse(client, "ransom-payment-portal.test")
        assert "ti_malicious_floor" in result["overrides_applied"]

    def test_subdomain_of_indicator_also_blocked(self, client):
        result = analyse(client, "login.ransom-payment-portal.test")
        assert result["decision"] == "BLOCK"
        assert result["threat_intelligence"]["match_type"] == "parent_domain"

    def test_dashboard_records_the_threat(self, client):
        analyse(client, "botnet-controller.test")
        stats = client.get("/api/stats").json()
        assert stats["blocked"] >= 1
        assert stats["threats_detected"] >= 1


class TestScenario3UnknownDGADomain:
    """The scenario that proves this is not a blacklist.

    A synthetic random-looking domain that appears in NO dataset must still be
    caught, on its own characteristics alone.
    """

    DOMAIN = "kq3v9z7jx1p8w.info"

    def test_not_present_in_threat_intelligence(self, client):
        result = analyse(client, self.DOMAIN)
        assert result["threat_intelligence"]["verdict"] == "UNKNOWN"
        assert result["threat_intelligence"]["matched_indicator"] is None

    def test_threat_intel_signal_is_excluded_not_counted_as_safe(self, client):
        result = analyse(client, self.DOMAIN)
        ti = [s for s in result["signals"] if s["name"] == "threat_intel"][0]
        assert ti["confidence"] == 0.0
        assert ti["used_in_fusion"] is False
        assert ti["weighted_contribution"] == 0.0

    def test_still_reaches_a_blocking_score(self, client):
        result = analyse(client, self.DOMAIN)
        assert result["risk_score"] >= 70
        assert result["decision"] == "BLOCK"

    def test_dga_analysis_identified_it(self, client):
        result = analyse(client, self.DOMAIN)
        assert result["dga_analysis"]["score"] > 0.8

    def test_lexical_analysis_identified_it(self, client):
        result = analyse(client, self.DOMAIN)
        lexical = [s for s in result["signals"] if s["name"] == "lexical"][0]
        assert lexical["score"] > 45

    def test_explanation_names_the_real_reasons(self, client):
        result = analyse(client, self.DOMAIN)
        codes = {f["code"] for f in result["risk_factors"]}
        assert "DGA_HIGH" in codes
        assert "TI_NO_MATCH" in codes

    def test_recommendation_flags_it_as_a_new_indicator(self, client):
        result = analyse(client, self.DOMAIN)
        assert "no threat-intelligence match" in result["recommended_action"].lower()

    @pytest.mark.parametrize("domain", [
        "xkzqmwvbtrn.xyz", "vhwnxkzptqrjmb.top", "zxqvbnmkljhgfd.tk",
    ])
    def test_other_unlisted_dga_domains_also_caught(self, client, domain):
        result = analyse(client, domain)
        assert result["threat_intelligence"]["verdict"] == "UNKNOWN"
        assert result["decision"] == "BLOCK"


class TestEndToEndContract:
    """The success criteria from the brief, checked as one flow."""

    def test_full_pipeline_shape(self, client):
        result = analyse(client, "hdfcbank-netbanking-verify.xyz")
        for field in [
            "domain", "risk_score", "classification", "decision",
            "threat_intelligence", "dga_analysis", "domain_features",
            "risk_factors", "signals", "recommended_action",
            "analysis_time_ms", "stage_timings_ms", "event_id", "timestamp",
        ]:
            assert field in result, field

    def test_timings_are_measured_per_stage(self, client):
        result = analyse(client, "github.com")
        stages = result["stage_timings_ms"]
        for stage in ["normalize", "features", "threat_intel", "dga", "risk_engine"]:
            assert stage in stages
            assert stages[stage] >= 0
        assert result["analysis_time_ms"] > 0

    def test_contributions_sum_to_the_reported_score(self, client):
        for domain in ["github.com", "malware-c2-panel.test", "kq3v9z7jx1p8w.info"]:
            result = analyse(client, domain)
            total = sum(f["contribution"] for f in result["risk_factors"])
            assert abs(total - result["risk_score"]) < 1.0, domain

    def test_dashboard_statistics_come_from_stored_events(self, client):
        before = client.get("/api/stats").json()["total_analyzed"]
        analyse(client, "some-new-unseen-domain.com")
        after = client.get("/api/stats").json()["total_analyzed"]
        assert after == before + 1


class TestAsymmetricSignalsEndToEnd:
    """Every signal abstains on a null finding; none votes for safety.

    These run through the real API against the real pipeline, so they pin the
    behaviour users and the dashboard actually see - not just the unit-level
    contract of one detector.
    """

    def test_no_signal_votes_for_safety(self, client):
        """A clean, unknown domain leaves every null signal out of fusion."""
        result = analyse(client, "waterline.com")
        by_name = {s["name"]: s for s in result["signals"]}
        for name in ("threat_intel", "dga", "lexical", "tunnel", "behavioral"):
            signal = by_name[name]
            if signal["score"] == 0.0 or (name == "dga" and signal["score"] < 50):
                assert signal["confidence"] == 0.0, name
                assert signal["used_in_fusion"] is False, name
                assert signal["weighted_contribution"] == 0.0, name

    def test_behavioural_evidence_is_not_diluted_by_a_null_dga(self, client):
        """The fan-out case, end to end.

        An ordinary-looking name whose *behaviour* is anomalous. Lexical and
        DGA both find nothing; if either voted its zero, the behavioural
        finding would be averaged into ALLOW. Both must abstain and leave the
        behavioural signal to decide.
        """
        for index in range(14):
            analyse(client, "n%d.quietbrook.com" % index)

        result = analyse(client, "n99.quietbrook.com")
        by_name = {s["name"]: s for s in result["signals"]}

        behavioural = by_name["behavioral"]
        assert behavioural["used_in_fusion"], "no behavioural evidence to test"
        assert behavioural["score"] >= 30

        assert by_name["lexical"]["confidence"] == 0.0
        assert by_name["dga"]["confidence"] == 0.0
        # With the null signals abstaining, behaviour is what is left and the
        # fused score must reflect it rather than being averaged away.
        assert result["risk_score"] >= behavioural["score"] - 1

    def test_known_malicious_detection_is_intact(self, client):
        for domain in (
            "malware-c2-panel.test",
            "login.ransom-payment-portal.test",
            "compromised-host.example.com",
        ):
            result = analyse(client, domain)
            assert result["decision"] == "BLOCK", domain
            assert result["risk_score"] >= 70, domain

    def test_dga_detection_is_intact(self, client):
        for domain in ("xjqzwvbnmk4d8f2.top", "zzzxqwvbnmlkjh.info", "kqxvbnmwrtplzd.com"):
            result = analyse(client, domain)
            assert result["decision"] == "BLOCK", domain
            dga = next(s for s in result["signals"] if s["name"] == "dga")
            assert dga["used_in_fusion"], domain

    def test_impersonation_detection_is_intact(self, client):
        for domain in ("paypa1.com", "secure-login-microsoft-verify.tk"):
            result = analyse(client, domain)
            assert result["decision"] in ("MONITOR", "BLOCK"), domain
            assert result["risk_score"] >= 60, domain

    def test_tunnelling_detection_is_intact(self, client):
        result = analyse(
            client, "aGVsbG93b3JsZGRhdGFleGZpbA.dGhpc2lzZGF0YQ.tunnel.test"
        )
        tunnel = next(s for s in result["signals"] if s["name"] == "tunnel")
        assert tunnel["used_in_fusion"]
        assert result["decision"] in ("MONITOR", "BLOCK")

    def test_legitimate_domains_stay_allowed(self, client):
        for domain in (
            "google.com", "github.com", "wikipedia.org", "cloudflare.com",
            "sbi.co.in", "irctc.co.in", "drdo.gov.in", "nptel.ac.in",
            "stackoverflow.com", "flipkart.com", "hdfcbank.com", "zee5.com",
            "ndtv.com", "npci.com", "mcdonalds.com",
        ):
            result = analyse(client, domain)
            assert result["decision"] == "ALLOW", "%s -> %s (%d)" % (
                domain, result["decision"], result["risk_score"])
