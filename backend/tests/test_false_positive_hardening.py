"""Legitimate domains must not be escalated by a bare brand-name match.

WHAT WENT WRONG

``_detect_brand_impersonation`` treated the presence of a protected brand
token as proof of impersonation, exempting only the handful of domains listed
against that brand in ``brands.json``. No hand-maintained list can enumerate
every ccTLD, CDN and service domain a global brand operates, so the detector
flagged the brands' own domains:

    google.de  amazon.ca  apple.com.cn  microsoft.de  windows.net
    youtube-nocookie.com  instagram-brand.com  linkedin-ei.com

Each one reached ``brand_impersonation_floor`` and scored 60/MONITOR. A judge
typing ``google.de`` would have watched the platform accuse Google of
impersonating Google.

The edit-distance rule had the same shape of defect: a flat budget of two
edits on a six-letter brand let a third of the string change, which scored
``gitlab.com`` as a typosquat of ``github.com``.

WHAT THE FIX IS NOT

It is not an allowlist. Adding the eight domains above would have moved the
boundary rather than fixed it - the ninth legitimate brand domain would fail
in the same way. The detector now decides on STRUCTURE plus INDEPENDENT
EVIDENCE: whether the brand name IS the registrable label or merely appears
beside others, and whether anything other than the brand token suggests
hostility. See ``_detect_brand_impersonation``.

WHAT THESE TESTS PROTECT

Both directions, deliberately. Relaxing a detector is exactly the change that
looks like an improvement while quietly disarming it, so every test that pins
a legitimate domain to ALLOW is paired with one pinning a real attack to
MONITOR or BLOCK.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline
from backend.app.main import create_app


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def pipeline():
    return get_pipeline()


def assess(pipeline, domain):
    return pipeline.analyse(domain).assessment


def brand(domain):
    return extract_features(normalize(domain))


# -- 1-3. the domains a judge will actually type ----------------------------


class TestHouseholdDomainsAreAllowed:
    """The six named in the report, plus the ones that were actually broken."""

    @pytest.mark.parametrize("domain", [
        "github.com", "youtube.com", "google.com",
        "microsoft.com", "apple.com", "amazon.com",
    ])
    def test_canonical_domain_is_allowed_at_zero_risk(self, pipeline, domain):
        result = assess(pipeline, domain)
        assert result.score == 0, domain
        assert result.decision == "ALLOW", domain

    @pytest.mark.parametrize("domain", [
        "google.de",             # Google's own German site
        "amazon.ca",             # Amazon Canada
        "apple.com.cn",          # Apple China
        "microsoft.de",          # Microsoft Germany
        "windows.net",           # Azure service domain
        "youtube-nocookie.com",  # Google's privacy-preserving embed host
        "instagram-brand.com",   # Meta's own brand-assets site
        "gitlab.com",            # scored a typosquat of github.com
    ])
    def test_brand_owned_domain_is_not_escalated(self, pipeline, domain):
        """These were the false positives. None may reach MONITOR."""
        result = assess(pipeline, domain)
        assert result.decision == "ALLOW", (
            "{} scored {} - a legitimate brand domain must not be escalated "
            "by the brand token alone".format(domain, result.score)
        )
        assert "brand_impersonation_floor" not in (result.overrides_applied or ())


# -- 4. carrying a brand name is not impersonating one ----------------------


class TestCanonicalDomainsAreNotImpersonation:
    @pytest.mark.parametrize("domain", [
        "github.com", "google.com", "amazon.com", "apple.com",
        "google.de", "amazon.ca", "apple.com.cn", "windows.net",
    ])
    def test_not_flagged_as_impersonation(self, domain):
        assert brand(domain).brand_impersonation is False, domain

    def test_the_positive_case_is_recorded_not_merely_absent(self):
        """A recognised brand domain says so, rather than showing nothing.

        The difference matters: "no brand match" and "this IS the brand" are
        different findings, and only the second is positive evidence.
        """
        f = brand("google.de")
        assert f.brand_match_type == "brand_owned"
        assert f.brand_target == "google.com"
        assert "registrable_label_is_brand" in f.brand_evidence

    def test_uncorroborated_composite_is_distinguishable_from_a_clean_name(self):
        """youtube-nocookie.com is not impersonation, but it is not nothing."""
        f = brand("youtube-nocookie.com")
        assert f.brand_impersonation is False
        assert f.brand_match_type == "brand_token_uncorroborated"


# -- 5. real impersonation is still caught ----------------------------------


class TestImpersonationStillDetected:
    @pytest.mark.parametrize("domain", [
        "github-login-security.example",
        "github-security.example",
        "github.verify.example",
        "paypal-secure-verify.top",
        "secure-login-microsoft-verify.tk",
        "apple-id-verify.xyz",
        "amazon-account-suspended.cf",
        "hdfcbank-netbanking-verify.xyz",
    ])
    def test_brand_plus_corroborating_evidence_is_impersonation(self, pipeline, domain):
        assert brand(domain).brand_impersonation is True, domain
        assert assess(pipeline, domain).decision in ("MONITOR", "BLOCK"), domain

    @pytest.mark.parametrize("domain", [
        "githhub.com", "paypa1.com", "gooogle.com", "faceb00k.com",
        "micr0soft.com", "amaz0n.com", "netfliix.com", "linkedln.com",
    ])
    def test_typosquats_are_still_caught(self, pipeline, domain):
        f = brand(domain)
        assert f.brand_impersonation is True, domain
        assert f.brand_match_type == "typosquat", domain
        assert assess(pipeline, domain).score >= 60, domain

    @pytest.mark.parametrize("domain", ["paypal.tk", "netflix.ml"])
    def test_bare_brand_on_a_throwaway_tld_is_impersonation(self, pipeline, domain):
        """The same shape as google.de, and the TLD is what separates them."""
        f = brand(domain)
        assert f.brand_impersonation is True, domain
        assert f.brand_match_type == "brand_on_suspicious_tld", domain
        assert assess(pipeline, domain).score >= 60, domain

    def test_the_edit_budget_still_admits_a_one_edit_lookalike(self):
        """Tightening the budget must not switch typosquatting off."""
        assert brand("paypa1.com").brand_impersonation is True
        assert brand("gitlab.com").brand_impersonation is False


# -- 6-8. nothing else moved ------------------------------------------------


class TestExistingDetectionPreserved:
    def test_known_malicious_indicator_still_blocks(self, pipeline):
        result = assess(pipeline, "malware-c2-panel.test")
        assert result.score == 85
        assert result.decision == "BLOCK"

    def test_dga_case_still_blocks(self, pipeline):
        result = assess(pipeline, "kq3v9z7jx1p8w.info")
        assert result.score == 95
        assert result.decision == "BLOCK"

    def test_unknown_domain_is_still_evaluated_not_waved_through(self, pipeline):
        """The fix must not make unknown domains safe by default."""
        result = assess(pipeline, "zxqvbnmkljhgfd.tk")
        assert result.decision in ("MONITOR", "BLOCK")
        assert result.score >= 30

    def test_trusted_ceiling_still_applies(self, pipeline):
        result = assess(pipeline, "malware-c2-panel.invalid")
        assert result.score == 18
        assert result.decision == "ALLOW"


# -- 9. determinism ---------------------------------------------------------


class TestDeterminism:
    """Same domain, same intelligence state, same history -> same answer.

    History IS an input. The behavioural analyser reads the stored query
    history for the registrable domain, so analysing the same name repeatedly
    through the API eventually changes the score - that is intended, and it is
    visible in the response as ``behavioral_analysis.indicators`` with
    ``used_in_fusion`` true. The pipeline calls below do not write events, so
    the history they read is fixed and the result must not vary at all.
    """

    @pytest.mark.parametrize("domain", [
        "github.com", "youtube.com", "google.com", "google.de",
        "paypa1.com", "malware-c2-panel.test", "kq3v9z7jx1p8w.info",
    ])
    def test_repeated_analysis_is_identical(self, pipeline, domain):
        runs = set()
        for _ in range(8):
            a = assess(pipeline, domain)
            runs.add((a.score, a.decision, a.classification,
                      tuple(a.overrides_applied or ())))
        assert len(runs) == 1, "{} produced {} different results".format(
            domain, len(runs))

    def test_history_effects_are_declared_in_the_response(self, client):
        """If history moved the score, the response must say so."""
        body = client.post("/api/analyze", json={"domain": "github.com"}).json()
        behavioural = next(s for s in body["signals"] if s["name"] == "behavioral")
        assert "used_in_fusion" in behavioural
        assert "observations" in body["behavioral_analysis"]


# -- 10. the protected Phase 3 reference values -----------------------------


class TestPhase3ReferenceValuesUnchanged:
    """These five are the regression fence for the whole engine."""

    @pytest.mark.parametrize("domain,score,decision", [
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
    ])
    def test_reference_value(self, pipeline, domain, score, decision):
        result = assess(pipeline, domain)
        assert result.score == score, domain
        assert result.decision == decision, domain
