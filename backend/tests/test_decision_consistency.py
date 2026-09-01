"""Phase 5C: two ways the engine reached a wrong answer, and the fences.

ISSUE 1 - LEGITIMATE INFRASTRUCTURE SCORED AS GENERATED

jsdelivr.net reached 51/MONITOR, and the whole 51 came from one signal: the
DGA model, with every other signal abstaining. The model's dictionary term
asks "is this label built from real words?", and the answer for ``jsdelivr``
was no - because ``deliver`` is in the lexicon and ``delivr`` is not. Dropping
a vowel is one of the most productive naming conventions on the web, and it
made a real word invisible to an exact-match lookup.

The same term failed a second way. ``cdn`` was missing from a lexicon that
already carried cloud, edge, cache, host, net, api and npm - so the token that
names the delivery tier itself read as nonsense, and cdn77, bunnycdn and
netdna-cdn scored as generated names.

Neither fix is a domain list. One teaches the matcher a morphological rule,
the other fills a gap in a vocabulary of morphemes. Both generalise to
domains nobody has ever seen, which is what the last test in the first class
demonstrates.

ISSUE 2 - REPETITION MANUFACTURED BEHAVIOURAL EVIDENCE

``query_burst`` counted stored rows. Analysing one unknown domain 25 times
through the API therefore tripped it - and because the burst scores 26 while
the domain scored 75, joining the confidence-weighted average pulled the
verdict DOWN from BLOCK to MONITOR. Anyone able to get a domain re-analysed
could make it look progressively safer, which inverts the point of the system.

The distinction now drawn is between repeated observation and new evidence,
not between event types. Every DNS event counts, because repetition is the
shape of beaconing and is itself the evidence. An analysis event counts once
per distinct name, because re-reading a row you have already read tells you
nothing. Fourteen different subdomains submitted through the API are still
fourteen observations and still fire subdomain fan-out.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.core.features import (
    dictionary_coverage,
    extract_features,
    _is_vowel_elision,
)
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline
from backend.app.dns_gateway.models import DNSContext
from backend.app.main import create_app
from backend.app.storage.events import EventRepository, set_event_repository


@pytest.fixture(scope="module")
def pipeline():
    return get_pipeline()


@pytest.fixture
def clean_store(tmp_path):
    import backend.app.storage.events as events_module

    previous = events_module._repository
    repository = EventRepository(path=tmp_path / "consistency.db")
    set_event_repository(repository)
    try:
        yield repository
    finally:
        set_event_repository(previous)


@pytest.fixture
def client(clean_store):
    return TestClient(create_app(), raise_server_exceptions=False)


def verdict(pipeline, domain):
    a = pipeline.analyse(domain).assessment
    return a.score, a.decision


def seed_dns(repository, domain, times=1, client_address="10.0.0.7",
             response_code="NOERROR", blocked=False):
    """Real analyses stored as observed gateway traffic."""
    pipe = get_pipeline()
    for _ in range(times):
        repository.log(
            pipe.analyse(domain),
            source="dns",
            dns=DNSContext(
                query_type="A",
                client_address=client_address,
                response_code=response_code,
                blocked=blocked,
            ),
        )


# ===========================================================================
# ISSUE 1
# ===========================================================================


class TestLegitimateInfrastructureIsNotGenerated:
    def test_the_reported_domain_is_allowed(self, pipeline):
        score, decision = verdict(pipeline, "jsdelivr.net")
        assert decision == "ALLOW", "jsdelivr.net scored {}".format(score)

    @pytest.mark.parametrize("domain", [
        "cloudfront.net", "fastly.net", "akamai.net", "gstatic.com",
        "keycdn.com", "stackpath.com", "cachefly.net", "edgecast.com",
        "netdnacdn.com",
    ])
    def test_cdn_and_service_infrastructure_is_allowed(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} scored {}".format(domain, score)

    @pytest.mark.parametrize("domain", [
        "google.de", "amazon.ca", "apple.com.cn", "irctc.co.in",
        "bankofbaroda.in", "google.co.uk", "nic.in",
    ])
    def test_country_code_domains_are_allowed(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} scored {}".format(domain, score)

    @pytest.mark.parametrize("domain", [
        "mail.google.com", "docs.python.org", "api.stripe.com",
        "s3.eu-west-1.amazonaws.com", "cdn.jsdelivr.net",
        "assets.githubassets.com", "static.cloudflareinsights.com",
    ])
    def test_multi_label_domains_are_allowed(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} scored {}".format(domain, score)

    @pytest.mark.parametrize("domain,score", [
        ("raw.githubusercontent.com", 36),
    ])
    def test_known_limitation_long_multilabel_names_still_monitor(
            self, pipeline, domain, score):
        """A THIRD false-positive mechanism, recorded rather than hidden.

        Phase 5D fixed the other one of these two: static.cloudflareinsights.com
        went 38/MONITOR -> 26/ALLOW once consonant runs stopped crossing label
        boundaries, and it now lives in the ALLOW list above.

        This one is legitimate and still reaches MONITOR. Its dictionary
        coverage is 1.000 and the DGA signal abstains outright; the points come
        from the LEXICAL scorer reading the whole FQDN - ENTROPY_HIGH +18,
        ENTROPY_NORMALIZED_HIGH +10, LENGTH_LONG +8 for 25 characters - so a
        legitimate name is charged for being long and for having subdomains.

        Phase 5D implemented that scope fix and MEASURED the cost: judging the
        worst label instead of the concatenation takes this domain to 10/ALLOW,
        but it also moves two pinned reference values - malware-c2-panel.invalid
        18 -> 10 and TUNNEL_NAME 96 -> 97, decisions unchanged in both cases.
        Legitimate and pinned domains share the mechanism exactly (coverage
        0.615 and 1.000 respectively), so no discriminator separates them. The
        pins were held and the fix reverted, pending a decision.
        """
        assert verdict(pipeline, domain) == (score, "MONITOR")

    @pytest.mark.parametrize("domain", [
        "windows.net", "youtube-nocookie.com", "instagram-brand.com",
        "googleapis.com", "amazontrust.com", "paypalobjects.com",
    ])
    def test_service_domains_carrying_a_brand_token_are_allowed(
            self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} scored {}".format(domain, score)

    def test_the_fix_is_a_rule_not_a_memorised_list(self):
        """Names nobody has registered must benefit from the same rule.

        This is the test that separates a general fix from a whitelist: none
        of these strings appears in any data file, and the engine has never
        seen them. They are recognised because of how they are BUILT.
        """
        # vowel elision - the delivr/deliver morphology, on invented words
        for coined in ("managr", "servr", "netwrk", "platfrm", "monitr",
                       "clustr", "filtr"):
            assert _is_vowel_elision(coined), coined
            assert dictionary_coverage(coined) > 0.0, coined

        # infrastructure morphemes, in combinations that exist nowhere
        for invented in ("fastcdn", "edgeproxy", "staticmirror", "dnsrelay"):
            assert dictionary_coverage(invented) > 0.5, invented

    def test_random_labels_gain_nothing_from_either_rule(self):
        """The counterweight: neither rule may launder a generated name.

        ``trn`` reaches ``turn`` by inserting one vowel, which is why the
        elision rule carries a length floor - without it a three-letter
        consonant cluster inside a random string scored as a real word.
        """
        for generated in ("xkzqmwvbtrn", "kq3v9z7jx1p8w", "zxqvbnmkljhgfd",
                          "vhwnxkzptqrjmb", "p9x2m7k4q1w8z3"):
            assert dictionary_coverage(generated) == 0.0, generated

    def test_generated_names_still_score_as_generated(self, pipeline):
        for domain in ("kq3v9z7jx1p8w.info", "zxqvbnmkljhgfd.tk",
                       "xjqzwvbnmk4d8f2.top", "vhwnxkzptqrjmb.top"):
            score, decision = verdict(pipeline, domain)
            assert decision == "BLOCK", "{} scored {}".format(domain, score)


class TestSuspiciousMatrixUnchanged:
    """Every category the engine is meant to catch, with its evidence."""

    @pytest.mark.parametrize("domain,expect_impersonation", [
        ("paypal-secure-verify.top", True),
        ("secure-login-microsoft-verify.tk", True),
        ("hdfcbank-netbanking-verify.xyz", True),
        ("apple-id-verify.xyz", True),
        ("paypa1.com", True),
        ("gooogle.com", True),
        ("githhub.com", True),
        ("paypal.tk", True),
    ])
    def test_impersonation_categories_still_escalate(
            self, pipeline, domain, expect_impersonation):
        features = extract_features(normalize(domain))
        assert features.brand_impersonation is expect_impersonation, domain
        score, decision = verdict(pipeline, domain)
        assert decision in ("MONITOR", "BLOCK"), "{} -> {}".format(domain, score)
        assert score >= 60, domain

    def test_known_malicious_indicator_still_blocks(self, pipeline):
        assert verdict(pipeline, "malware-c2-panel.test") == (85, "BLOCK")


# ===========================================================================
# ISSUE 2
# ===========================================================================


class TestRepetitionCannotLowerRisk:
    """The security property: repetition must never buy a safer verdict."""

    @pytest.mark.parametrize("domain", [
        "kq3v9z7jx1p8w.info", "zxqvbnmkljhgfd.tk", "malware-c2-panel.test",
    ])
    def test_repeated_analysis_never_downgrades_a_block(self, client, domain):
        first = client.post("/api/analyze", json={"domain": domain}).json()
        assert first["decision"] == "BLOCK", domain

        outcomes = set()
        for _ in range(30):
            body = client.post("/api/analyze", json={"domain": domain}).json()
            outcomes.add((body["risk_score"], body["decision"]))

        assert outcomes == {(first["risk_score"], first["decision"])}, (
            "{} drifted across 30 identical analyses: {}".format(domain, outcomes)
        )

    def test_repeated_analysis_of_a_suspicious_unknown_is_stable(self, client):
        """The exact case that was observed drifting 75/BLOCK -> 68/MONITOR."""
        domain = "some-unknown-site-xyzq.test"
        first = client.post("/api/analyze", json={"domain": domain}).json()
        for _ in range(30):
            body = client.post("/api/analyze", json={"domain": domain}).json()
            assert body["risk_score"] == first["risk_score"], domain
            assert body["decision"] == first["decision"], domain

    def test_repeated_analysis_of_a_safe_domain_invents_no_risk(self, client):
        for _ in range(30):
            body = client.post("/api/analyze", json={"domain": "github.com"}).json()
        assert body["risk_score"] == 0
        assert body["decision"] == "ALLOW"
        behavioural = next(
            s for s in body["signals"] if s["name"] == "behavioral")
        assert not behavioural["used_in_fusion"], (
            "repetition alone must not produce behavioural evidence"
        )


class TestGenuinelyNewEvidenceStillCounts:
    def test_distinct_subdomains_still_fire_fanout(self, client):
        for index in range(14):
            client.post("/api/analyze", json={"domain": "n%d.fanout-demo.test" % index})
        body = client.post(
            "/api/analyze", json={"domain": "n99.fanout-demo.test"}).json()
        behavioural = next(
            s for s in body["signals"] if s["name"] == "behavioral")
        assert behavioural["used_in_fusion"]
        assert "subdomain_fanout" in body["behavioral_analysis"]["indicators"]

    def test_repeated_dns_traffic_still_fires_a_burst(self, clean_store):
        """Beaconing is repetition, and must keep counting as evidence."""
        seed_dns(clean_store, "beacon-c2.test", times=25)
        history = clean_store.domain_history("beacon-c2.test")
        assert history["total_queries"] == 25

        from backend.app.detection import HistoryBehavioralAnalyzer

        result = HistoryBehavioralAnalyzer(
            repository=clean_store).analyse_client("beacon-c2.test", "10.0.0.7")
        assert "query_burst" in result.indicators

    def test_nxdomain_ratio_indicator_still_works(self, clean_store):
        seed_dns(clean_store, "nx-demo.test", times=8, response_code="NXDOMAIN")
        history = clean_store.domain_history("nx-demo.test")
        assert history["nxdomain_count"] == 8

    def test_analysis_of_a_new_name_is_new_evidence(self, clean_store):
        """One observation per distinct name - not zero, and not per row."""
        pipe = get_pipeline()
        for name in ("a.newname-demo.test", "b.newname-demo.test",
                     "c.newname-demo.test"):
            for _ in range(5):
                clean_store.log(pipe.analyse(name), source="api")
        history = clean_store.domain_history("newname-demo.test")
        assert history["total_queries"] == 3, (
            "three names seen five times each is three observations"
        )


class TestPhase3ReferenceValues:
    @pytest.mark.parametrize("domain,score,decision", [
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
    ])
    def test_reference_value_unchanged(self, pipeline, domain, score, decision):
        assert verdict(pipeline, domain) == (score, decision)
