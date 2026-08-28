"""DNS tunnelling detector tests.

The two properties that matter:
  1. real infrastructure with long encoded-looking subdomains is NOT flagged
  2. when the detector finds nothing it abstains, so it can never dilute
     another signal's evidence
"""

import pytest

from backend.app.config import get_risk_config
from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.detection import HeuristicTunnelDetector, tunnel_to_signal

# Real-world shapes that look encoded but are perfectly ordinary.
LEGITIMATE = [
    "mail.google.com",
    "api.github.com",
    "d111111abcdef8.cloudfront.net",
    "s3.dualstack.us-east-1.amazonaws.com",
    "_acme-challenge.example.com",
    "selector1._domainkey.example.com",
    "v1.api.stripe.com",
    "static.cdn.example.com",
    "20240815-report.analytics.example.com",
]

TUNNELLING = [
    "a7f3b2e91c4d8a6f0b5e2d9c1a8b7f4e.tunnel.example.com",
    "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHBheWxvYWQ.x.example.com",
    "f0e1d2c3.b4a5968778695a4b.3c2d1e0f9a8b.7c6d5e4f.data.example.com",
    "4a6f686e446f65313233343536373839304142434445.exfil.example.com",
]


@pytest.fixture(scope="module")
def detector():
    return HeuristicTunnelDetector()


def analyse(detector, domain, query_type=None):
    context = {"query_type": query_type} if query_type else None
    return detector.analyse(extract_features(normalize(domain)), context)


class TestAbstention:
    """The detector must stay silent unless it has something to say."""

    def test_no_subdomain_means_no_opinion(self, detector):
        result = analyse(detector, "github.com")
        assert result.confidence == 0.0
        assert result.score == 0.0
        assert result.indicators == []

    @pytest.mark.parametrize("domain", LEGITIMATE)
    def test_legitimate_infrastructure_is_not_flagged(self, detector, domain):
        result = analyse(detector, domain)
        # It may notice a single weak trait, but must never reach the
        # multi-indicator confidence that drives a decision.
        assert result.confidence < 0.6, domain
        assert len(result.indicators) < 3, domain

    def test_abstaining_signal_is_excluded_from_fusion(self, detector):
        signal = tunnel_to_signal(analyse(detector, "github.com"), get_risk_config())
        assert signal.is_informative is False
        assert signal.factors[0].code == "DNS_TUNNEL_NONE"
        assert "not evidence the domain is safe" in signal.factors[0].detail


class TestDetection:
    @pytest.mark.parametrize("domain", TUNNELLING)
    def test_tunnelling_shapes_are_detected(self, detector, domain):
        result = analyse(detector, domain, "TXT")
        assert result.score >= 60, domain
        assert result.confidence >= 0.6, domain
        assert len(result.indicators) >= 2, domain

    def test_encoded_payload_is_identified(self, detector):
        result = analyse(detector, "a7f3b2e91c4d8a6f0b5e2d9c1a8b7f4e.t.example.com")
        assert "encoded_payload" in result.indicators
        assert result.measurements["encoding_alphabet"] in ("hex", "base32", "base64ish")

    def test_many_labels_indicator(self, detector):
        result = analyse(detector, "a.b.c.d.e.f.example.com")
        assert "many_labels" in result.indicators

    def test_confidence_scales_with_evidence(self, detector):
        weak = analyse(detector, "a.b.c.d.e.f.example.com")
        strong = analyse(
            detector, "f0e1d2c3.b4a5968778695a4b.3c2d1e0f9a8b.7c6d5e4f.d.example.com", "TXT"
        )
        assert strong.confidence > weak.confidence


class TestRecordTypeContext:
    def test_high_capacity_type_only_counts_alongside_other_evidence(self, detector):
        """A TXT lookup on its own is completely ordinary."""
        plain = analyse(detector, "mail.google.com", "TXT")
        assert "high_capacity_record" not in plain.indicators

    def test_high_capacity_type_adds_to_existing_evidence(self, detector):
        domain = "a7f3b2e91c4d8a6f0b5e2d9c1a8b7f4e.tunnel.example.com"
        with_txt = analyse(detector, domain, "TXT")
        without = analyse(detector, domain, "A")
        assert "high_capacity_record" in with_txt.indicators
        assert "high_capacity_record" not in without.indicators
        assert with_txt.score > without.score

    def test_missing_context_is_handled(self, detector):
        assert analyse(detector, "mail.google.com", None).score >= 0


class TestHonestLabelling:
    def test_declared_as_heuristic(self, detector):
        assert detector.info()["model_type"] == "PROTOTYPE_HEURISTIC"

    def test_no_accuracy_claimed(self, detector):
        assert detector.info()["accuracy_claimed"] is None

    def test_factor_explains_the_measurement(self, detector):
        signal = tunnel_to_signal(
            analyse(detector, TUNNELLING[0], "TXT"), get_risk_config()
        )
        factor = signal.factors[0]
        assert factor.code == "DNS_TUNNEL_INDICATORS"
        assert "entropy" in factor.detail
        assert factor.label and factor.detail


class TestAllowlistInteraction:
    """Tunnelling through an allowlisted domain must remain visible."""

    def test_strong_tunnelling_sets_the_allowlist_aside(self):
        from backend.app.core.pipeline import get_pipeline

        result = get_pipeline().analyse(
            "f0e1d2c3.b4a5968778695a4b.3c2d1e0f9a8b.7c6d5e4f.data.example.com",
            {"query_type": "TXT"},
        )
        # example.com is on the trusted allowlist.
        assert result.intel_metadata["verdict"] == "TRUSTED"
        assert "allowlist_set_aside" in result.assessment.overrides_applied
        assert result.assessment.score > 25, "the allowlist cap must not apply"

    def test_ordinary_allowlisted_domain_still_capped(self):
        from backend.app.core.pipeline import get_pipeline

        result = get_pipeline().analyse("mail.google.com")
        assert "allowlist_set_aside" not in result.assessment.overrides_applied
        assert result.assessment.score <= 25


class TestPayloadEquivalenceAcrossSuffixes:
    """Identical payload bytes must be read identically, whatever the suffix.

    pages.dev is a two-label public suffix. The registrable domain under it is
    therefore payload-label-plus-suffix, so DELEGATED_SPAN - everything below
    the registrable domain - silently dropped the payload's last label. One
    attacker's bytes read 41 characters over two labels under tunnel.test and
    26 over one under pages.dev, scoring 76 against 26, decided entirely by
    where a suffix boundary happened to fall.

    Nobody registers a brand inside a provider namespace, so that label is not
    a registrant's name; it is another label the attacker filled.
    """

    PAYLOAD = "aGVsbG93b3JsZGRhdGFleGZpbA.dGhpc2lzZGF0YQ"

    REGISTRY_SUFFIXES = ["tunnel.test", "example.com"]
    PROVIDER_SUFFIXES = ["pages.dev", "cloudfront.net", "github.io",
                         "herokuapp.com"]

    def _analysis(self, detector, suffix):
        return detector.analyse(
            extract_features(normalize(self.PAYLOAD + "." + suffix)))

    def test_same_bytes_score_the_same_under_every_suffix(self, detector):
        scores = {suffix: self._analysis(detector, suffix).score
                  for suffix in self.REGISTRY_SUFFIXES + self.PROVIDER_SUFFIXES}
        assert len(set(scores.values())) == 1, (
            "identical payload bytes scored differently by suffix: " + str(scores))
        assert set(scores.values()) != {0.0}, "the payload must still be detected"

    def test_the_whole_payload_is_measured_under_a_provider_suffix(self, detector):
        """Not just the measurements that happen to add up to the same score."""
        reference = self._analysis(detector, "tunnel.test").measurements
        for suffix in self.PROVIDER_SUFFIXES:
            found = self._analysis(detector, suffix).measurements
            for key in ("subdomain_length", "subdomain_label_count",
                        "longest_label", "subdomain_entropy"):
                assert found[key] == reference[key], (suffix, key)

    def test_the_signal_declares_the_span_it_actually_read(self, detector):
        """Evidence independence compares these; a wrong one corrupts it."""
        from backend.app.core.classification import (
            CONTROLLED_SPAN, DELEGATED_SPAN,
        )

        registry = tunnel_to_signal(
            self._analysis(detector, "tunnel.test"), get_risk_config())
        provider = tunnel_to_signal(
            self._analysis(detector, "pages.dev"), get_risk_config())
        assert registry.scope_key == DELEGATED_SPAN
        assert provider.scope_key == CONTROLLED_SPAN

    @pytest.mark.parametrize("domain", [
        "d111111abcdef8.cloudfront.net",   # pure hex - trips encoded_payload
        "d1a2b3c4e5f6g7.cloudfront.net",
        "myproject.github.io",
        "myapp.herokuapp.com",
        "assets.myproject.github.io",
        "s3.dualstack.us-east-1.amazonaws.com",
    ])
    def test_legitimate_provider_hosts_are_still_not_flagged(self, detector, domain):
        """A static hostname is not a channel, however it is spelled.

        A provider host with nothing below it varies nothing from one query to
        the next. Folding its allocated label into the payload span would read
        d111111abcdef8 - a real CloudFront distribution id, and pure hex - as
        an encoded payload, which measures how a CDN spells an id rather than
        anything an attacker did.
        """
        result = detector.analyse(extract_features(normalize(domain)))
        assert result.score == 0.0, (domain, result.indicators)
        assert result.confidence == 0.0
        assert not result.indicators
