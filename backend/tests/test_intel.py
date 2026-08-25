"""Threat-intelligence tests.

The most important assertions here are the ones proving that an UNKNOWN
verdict is treated as *absence of evidence* rather than evidence of safety,
and that a more specific malicious indicator beats a broader allowlist entry.
"""

import pytest

from backend.app.config import get_risk_config
from backend.app.core.normalizer import normalize
from backend.app.intel import (
    IntelVerdict,
    LocalFileThreatIntelProvider,
    intel_to_signal,
)
from backend.app.intel.base import MatchType


@pytest.fixture(scope="module")
def provider():
    return LocalFileThreatIntelProvider()


def look(provider, domain: str):
    nd = normalize(domain)
    return provider.lookup(nd.domain, nd.registrable_domain)


class TestMaliciousMatching:
    def test_exact_match(self, provider):
        result = look(provider, "malware-c2-panel.test")
        assert result.verdict is IntelVerdict.MALICIOUS
        assert result.match_type is MatchType.EXACT
        assert "c2" in result.categories
        assert result.confidence > 0.9

    def test_parent_domain_match(self, provider):
        result = look(provider, "login.malware-c2-panel.test")
        assert result.verdict is IntelVerdict.MALICIOUS
        assert result.match_type is MatchType.PARENT_DOMAIN
        assert result.matched_indicator == "malware-c2-panel.test"

    def test_parent_match_is_slightly_less_confident(self, provider):
        exact = look(provider, "malware-c2-panel.test")
        parent = look(provider, "deep.sub.malware-c2-panel.test")
        assert parent.confidence < exact.confidence

    def test_suspicious_verdict_is_distinct_from_malicious(self, provider):
        result = look(provider, "spam-redirect.test")
        assert result.verdict is IntelVerdict.SUSPICIOUS
        assert result.confidence < 0.9

    def test_result_carries_provenance(self, provider):
        result = look(provider, "ransom-payment-portal.test")
        assert result.source
        assert result.first_seen
        assert result.description


class TestTrustedMatching:
    def test_trusted_exact(self, provider):
        assert look(provider, "github.com").verdict is IntelVerdict.TRUSTED

    def test_trusted_parent(self, provider):
        result = look(provider, "mail.google.com")
        assert result.verdict is IntelVerdict.TRUSTED
        assert result.match_type is MatchType.PARENT_DOMAIN

    def test_specific_malicious_beats_broader_trusted(self, provider):
        """A compromised host on a reputable domain must still be caught."""
        assert look(provider, "example.com").verdict is IntelVerdict.TRUSTED
        result = look(provider, "compromised-host.example.com")
        assert result.verdict is IntelVerdict.MALICIOUS
        assert result.matched_indicator == "compromised-host.example.com"


class TestUnknownIsNotSafe:
    """The core of adaptive detection."""

    @pytest.mark.parametrize(
        "domain",
        ["kq3v9z7jx1p8w.info", "some-random-domain-nobody-listed.com", "xyzabc.top"],
    )
    def test_unlisted_domain_is_unknown(self, provider, domain):
        assert look(provider, domain).verdict is IntelVerdict.UNKNOWN

    def test_unknown_reports_zero_confidence(self, provider):
        signal = intel_to_signal(look(provider, "unlisted-xyz.com"), get_risk_config())
        assert signal.confidence == 0.0
        assert signal.is_informative is False

    def test_unknown_never_claims_safety(self, provider):
        """An empty lookup must not produce a low-risk *informative* signal."""
        signal = intel_to_signal(look(provider, "unlisted-xyz.com"), get_risk_config())
        assert signal.score == 0.0
        # Score 0 with confidence 0 is excluded from fusion entirely, so it
        # cannot drag a genuinely suspicious domain toward SAFE.
        assert signal.confidence == 0.0

    def test_unknown_explains_itself(self, provider):
        signal = intel_to_signal(look(provider, "unlisted-xyz.com"), get_risk_config())
        assert signal.factors[0].code == "TI_NO_MATCH"
        assert "not evidence of safety" in signal.factors[0].detail


class TestPublicSuffixSafety:
    def test_never_matches_on_a_public_suffix_alone(self, provider):
        """A '.com' or '.co.in' query must not match a trusted '.com' entry."""
        candidates = provider._candidates("anything.new.com", "new.com")
        assert "com" not in candidates
        assert candidates[-1] == "new.com"

    def test_candidates_ordered_most_specific_first(self, provider):
        candidates = provider._candidates("a.b.example.com", "example.com")
        assert candidates == ["a.b.example.com", "b.example.com", "example.com"]


class TestSignalConversion:
    def test_malicious_maps_to_configured_score(self, provider):
        signal = intel_to_signal(look(provider, "botnet-controller.test"), get_risk_config())
        assert signal.score == 95.0
        assert signal.confidence > 0.9
        assert signal.factors[0].code == "TI_MALICIOUS"

    def test_trusted_maps_to_zero_with_high_confidence(self, provider):
        signal = intel_to_signal(look(provider, "wikipedia.org"), get_risk_config())
        assert signal.score == 0.0
        assert signal.confidence >= 0.85

    def test_signal_metadata_is_json_serialisable(self, provider):
        signal = intel_to_signal(look(provider, "malware-c2-panel.test"), get_risk_config())
        assert signal.metadata["verdict"] == "MALICIOUS"
        assert isinstance(signal.metadata["categories"], list)


class TestProviderContract:
    def test_stats_reports_dataset_size(self, provider):
        stats = provider.stats()
        assert stats["indicators_total"] > 0
        assert stats["trusted_domains"] > 0
        assert stats["malicious"] > 0
        assert "categories" in stats

    def test_provider_is_swappable(self):
        """The seam a live feed or STIX/TAXII collection plugs into."""
        custom = LocalFileThreatIntelProvider(
            indicators={
                "source": "unit_test_feed",
                "indicators": [
                    {
                        "indicator": "injected.test",
                        "verdict": "MALICIOUS",
                        "categories": ["test"],
                        "confidence": 0.99,
                    }
                ],
            },
            trusted={"source": "unit_test_feed", "trusted_domains": []},
        )
        result = look(custom, "injected.test")
        assert result.verdict is IntelVerdict.MALICIOUS
        assert result.source == "unit_test_feed"
        # And the bundled indicators are genuinely absent from this instance.
        assert look(custom, "malware-c2-panel.test").verdict is IntelVerdict.UNKNOWN


class TestDatasetSafety:
    def test_all_malicious_indicators_use_reserved_namespaces(self, provider):
        """No real infrastructure may appear in the malicious dataset."""
        reserved = (".test", ".invalid", ".example")
        reserved_domains = ("example.com", "example.org", "example.net")
        for indicator, entry in provider._indicators.items():
            if entry.get("verdict") not in ("MALICIOUS", "SUSPICIOUS"):
                continue
            ok = indicator.endswith(reserved) or any(
                indicator == d or indicator.endswith("." + d) for d in reserved_domains
            )
            assert ok, "{} is not in a reserved namespace".format(indicator)
