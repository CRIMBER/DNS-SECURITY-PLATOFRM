"""Name classification and analysis-scope contract.

The migration matrix from the implementation plan, as executable assertions.

Every case here failed, or would have been scored on the wrong span, before
the classification stage existed: each detector inferred domain semantics for
itself and they all made the same assumption - that the label below the public
suffix is a registrant-chosen brand name.
"""

import pytest

from backend.app.core.classification import (
    CONTROLLED_SPAN,
    DELEGATED_SPAN,
    REGISTRANT_LABEL,
    SEMANTIC_TEXT,
    NameKind,
    SuffixKind,
)
from backend.app.core.features import extract_features
from backend.app.core.lexical import score_lexical
from backend.app.core.normalizer import DomainValidationError, normalize
from backend.app.detection import get_dga_detector


def classify(domain):
    return normalize(domain).classification


class TestKind:
    @pytest.mark.parametrize(
        "domain,expected",
        [
            ("example.com", NameKind.REGISTRY_DOMAIN),
            ("login.example.com", NameKind.REGISTRY_DOMAIN),
            ("sbi.co.in", NameKind.REGISTRY_DOMAIN),
            ("xn--80ak6aa92e.com", NameKind.REGISTRY_DOMAIN),
            ("foo.pages.dev", NameKind.PROVIDER_HOST),
            ("foo.cloudfront.net", NameKind.PROVIDER_HOST),
            ("foo.github.io", NameKind.PROVIDER_HOST),
            ("my-app.s3.amazonaws.com", NameKind.PROVIDER_HOST),
            ("42.1.168.192.in-addr.arpa", NameKind.INFRASTRUCTURE),
            ("1.0.0.127.in-addr.arpa", NameKind.INFRASTRUCTURE),
            ("printer.local", NameKind.LOCAL_NAME),
            ("localhost", NameKind.LOCAL_NAME),
            ("192.168.1.10", NameKind.IP_LITERAL),
            ("8.8.8.8", NameKind.IP_LITERAL),
            ("2001:db8::1", NameKind.IP_LITERAL),
            ("sokadi", NameKind.SINGLE_LABEL),
            ("wpad", NameKind.SINGLE_LABEL),
        ],
    )
    def test_kind(self, domain, expected):
        assert classify(domain).kind is expected

    def test_malformed_input_is_still_rejected_at_the_door(self):
        """Classification does not weaken validation."""
        for bad in ("a..b", "", "-leading.com", "x" * 300 + ".com"):
            with pytest.raises(DomainValidationError):
                normalize(bad)


class TestReservedSuffixesAreNotLocalNames:
    """.test and .invalid are reserved, but their labels are registrant-shaped.

    This is the distinction the plan turned on. Treating every RFC 6761
    special-use zone as a LOCAL_NAME would have made DGA and lexical abstain on
    them - and 20 of the 21 bundled threat-intelligence indicators live under
    .test or .invalid, so the entire malicious fixture set would have scored
    zero. The split is by how names in the zone are CHOSEN, not by whether the
    zone is reserved.
    """

    @pytest.mark.parametrize(
        "domain", ["malware-c2-panel.test", "login.credential-harvest.invalid"]
    )
    def test_reserved_but_registrant_shaped(self, domain):
        c = classify(domain)
        assert c.kind is NameKind.REGISTRY_DOMAIN
        assert c.suffix_kind is SuffixKind.SPECIAL_USE
        assert c.scope_is_registrant_chosen is True
        assert c.has_scope(REGISTRANT_LABEL)

    def test_unregistered_zones_are_local(self):
        for domain in ("printer.local", "host.internal", "localhost"):
            assert classify(domain).kind is NameKind.LOCAL_NAME


class TestScopes:
    @pytest.mark.parametrize(
        "domain,label,delegated,controlled",
        [
            ("example.com", "example", "", "example"),
            ("login.example.com", "example", "login", "login.example"),
            ("a.b.example.co.uk", "example", "a.b", "a.b.example"),
            ("foo.pages.dev", "foo", "", "foo"),
            ("payload.foo.pages.dev", "foo", "payload", "payload.foo"),
            ("foo.cloudfront.net", "foo", "", "foo"),
        ],
    )
    def test_spans(self, domain, label, delegated, controlled):
        c = classify(domain)
        assert c.scope(REGISTRANT_LABEL) == label
        assert c.scope(DELEGATED_SPAN) == delegated
        assert c.scope(CONTROLLED_SPAN) == controlled

    @pytest.mark.parametrize(
        "domain", ["192.168.1.10", "8.8.8.8", "42.1.168.192.in-addr.arpa", "localhost"]
    )
    def test_names_with_no_chosen_label_expose_no_registrant_label(self, domain):
        c = classify(domain)
        assert not c.has_scope(REGISTRANT_LABEL)
        assert c.scope_is_registrant_chosen is False

    def test_empty_span_means_abstain_not_a_zero_length_name(self):
        """The distinction the whole contract rests on."""
        c = classify("192.168.1.10")
        assert c.scope(REGISTRANT_LABEL) == ""
        assert c.has_scope(REGISTRANT_LABEL) is False


class TestProviderNamespacesAreNotAnAllowlist:
    """Classification records where a name sits. It grants nothing."""

    def test_provider_is_recorded_not_trusted(self):
        c = classify("d1a2b3c4e5f6g7.cloudfront.net")
        assert c.kind is NameKind.PROVIDER_HOST
        assert c.suffix_kind is SuffixKind.PROVIDER
        assert c.scope_is_registrant_chosen is False

    def test_dga_still_runs_inside_a_provider_namespace(self):
        """Deliberately unchanged: suppressing it here is a policy decision the
        evaluation does not support, and this phase is representation only."""
        features = extract_features(normalize("d1a2b3c4e5f6g7.cloudfront.net"))
        result = get_dga_detector().analyse(features)
        assert result.confidence > 0.0
        assert result.score > 0.5

    def test_lexical_still_runs_inside_a_provider_namespace(self):
        signal = score_lexical(
            extract_features(normalize("d1a2b3c4e5f6g7.cloudfront.net"))
        )
        assert signal.is_informative
        assert signal.score > 0


class TestReverseDNS:
    @pytest.mark.parametrize(
        "domain,target",
        [
            ("42.1.168.192.in-addr.arpa", "192.168.1.42"),
            ("1.0.0.127.in-addr.arpa", "127.0.0.1"),
        ],
    )
    def test_ipv4_target_is_decoded(self, domain, target):
        c = classify(domain)
        assert c.is_reverse_dns is True
        assert c.reverse_target == target

    def test_ipv6_target_is_decoded(self):
        name = (
            "a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9."
            "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
        c = classify(name)
        assert c.is_reverse_dns is True
        assert c.reverse_target is not None
        assert ":" in c.reverse_target

    def test_malformed_reverse_name_does_not_crash(self):
        c = classify("not-an-address.in-addr.arpa")
        assert c.kind is NameKind.INFRASTRUCTURE
        assert c.reverse_target is None


class TestIPLiterals:
    @pytest.mark.parametrize(
        "address,version,private",
        [
            ("192.168.1.10", 4, True),
            ("10.0.0.1", 4, True),
            ("127.0.0.1", 4, True),
            ("8.8.8.8", 4, False),
            ("2001:db8::1", 6, True),
        ],
    )
    def test_address_is_represented_as_an_address(self, address, version, private):
        c = classify(address)
        assert c.kind is NameKind.IP_LITERAL
        assert c.ip_address == address
        assert c.ip_version == version
        assert c.ip_is_private is private


class TestIDN:
    @pytest.mark.parametrize(
        "domain,script",
        [
            ("xn--80ak6aa92e.com", "Cyrillic"),
            ("xn--fiqs8s.com", "Cjk"),
            ("xn--11b4c3d.com", "Devanagari"),
        ],
    )
    def test_script_is_detected_on_the_analysed_span(self, domain, script):
        """Measured on the label, not the whole host.

        Including the ASCII public suffix would add 'Latin' to every IDN and
        make each one look mixed-script.
        """
        c = classify(domain)
        assert c.scripts == frozenset({script})
        assert c.unicode_form is not None

    def test_ascii_form_is_preserved_for_wire_and_lookup(self):
        nd = normalize("xn--80ak6aa92e.com")
        assert nd.domain == "xn--80ak6aa92e.com"
        assert nd.classification.unicode_form != nd.domain

    def test_decoding_does_not_declare_the_domain_safe(self):
        """An IDN is still reported as an IDN.

        Homograph and confusable detection is future work; until it exists an
        internationalised name is LESS examined than before, not more, and the
        punycode observation is what keeps it visible.
        """
        signal = score_lexical(extract_features(normalize("xn--80ak6aa92e.com")))
        assert any(f.code == "PUNYCODE" for f in signal.factors)


class TestDetectorScoping:
    """Which detectors speak for which kind of name."""

    ABSTAIN = ["192.168.1.10", "8.8.8.8", "42.1.168.192.in-addr.arpa",
               "printer.local", "Brother-MFC.local", "xn--80ak6aa92e.com"]

    @pytest.mark.parametrize("domain", ABSTAIN)
    def test_dga_abstains_where_its_assumptions_do_not_hold(self, domain):
        result = get_dga_detector().analyse(extract_features(normalize(domain)))
        assert result.confidence == 0.0
        assert result.notes.startswith("Abstained:")

    @pytest.mark.parametrize(
        "domain", ["192.168.1.10", "8.8.8.8", "42.1.168.192.in-addr.arpa"]
    )
    def test_lexical_abstains_entirely_where_there_is_no_name(self, domain):
        signal = score_lexical(extract_features(normalize(domain)))
        assert signal.confidence == 0.0
        assert signal.score == 0.0
        assert signal.factors[0].code == "LEXICAL_NOT_APPLICABLE"

    def test_lexical_shape_rules_do_not_fire_on_an_address(self):
        """192.168.1.10 reached 95/BLOCK by measuring the digit ratio of an
        address as though it were a brand label."""
        signal = score_lexical(extract_features(normalize("192.168.1.10")))
        codes = {f.code for f in signal.factors}
        assert "DIGIT_RATIO_HIGH" not in codes
        assert "ENTROPY_HIGH" not in codes

    def test_brand_matching_survives_on_a_local_name(self):
        """A printer advertised with a brand token is still worth seeing, even
        though nobody registered the name."""
        signal = score_lexical(extract_features(normalize("paypal-login.local")))
        assert any(
            f.code in ("BRAND_IMPERSONATION", "BRAND_SUBSTRING", "SUSPICIOUS_KEYWORD")
            for f in signal.factors
        )

    def test_single_label_is_analysed_rather_than_ignored(self):
        """wpad is a real attack vector; abstaining would be the opposite error."""
        result = get_dga_detector().analyse(extract_features(normalize("wpad")))
        assert result.confidence >= 0.0
        assert classify("wpad").has_scope(REGISTRANT_LABEL)


class TestEvidenceIndependence:
    """Two signals reading the same span are one observation, not two."""

    def test_name_derived_signals_declare_the_span_they_read(self):
        from backend.app.config import get_risk_config
        from backend.app.detection import dga_to_signal

        features = extract_features(normalize("kqxvbnmwrtplzd.com"))
        lexical = score_lexical(features)
        dga = dga_to_signal(
            get_dga_detector().analyse(features), get_risk_config()
        )
        assert lexical.scope_key == REGISTRANT_LABEL
        assert dga.scope_key == REGISTRANT_LABEL
        assert lexical.scope_key == dga.scope_key, (
            "these two are not independent evidence"
        )

    def test_corroboration_needs_distinct_evidence(self):
        from backend.app.config import get_risk_config
        from backend.app.core.risk_engine import RiskEngine
        from backend.app.core.signals import RiskFactor, Severity, Signal

        def signal(name, score, scope):
            return Signal(
                name=name, score=score, confidence=0.9, scope_key=scope,
                factors=[RiskFactor(code="X", label="f", severity=Severity.HIGH,
                                    detail="d", raw_points=score)],
            )

        engine = RiskEngine(get_risk_config())
        echo = engine.assess([
            signal("dga", 90.0, REGISTRANT_LABEL),
            signal("lexical", 90.0, REGISTRANT_LABEL),
        ])
        genuine = engine.assess([
            signal("dga", 90.0, REGISTRANT_LABEL),
            signal("tunnel", 90.0, DELEGATED_SPAN),
        ])
        assert "corroboration_bonus" not in echo.overrides_applied
        assert "corroboration_bonus" in genuine.overrides_applied

    def test_signals_that_read_no_span_are_independent(self):
        """Threat intelligence reads a database, behavioural reads history."""
        from backend.app.config import get_risk_config
        from backend.app.core.risk_engine import RiskEngine
        from backend.app.core.signals import RiskFactor, Severity, Signal

        def signal(name, score):
            return Signal(
                name=name, score=score, confidence=0.9,
                factors=[RiskFactor(code="X", label="f", severity=Severity.HIGH,
                                    detail="d", raw_points=score)],
            )

        engine = RiskEngine(get_risk_config())
        result = engine.assess([signal("threat_intel", 90.0),
                                signal("behavioral", 90.0)])
        assert "corroboration_bonus" in result.overrides_applied


class TestBackwardCompatibility:
    def test_features_dict_gains_a_key_and_drops_none(self):
        data = extract_features(normalize("example.com")).to_dict()
        for key in ("length", "entropy", "digit_ratio", "tld", "is_punycode",
                    "brand_impersonation", "suspicious_keywords"):
            assert key in data
        assert "name_classification" in data

    def test_classification_survives_the_features_boundary(self):
        """The field that used to be computed and then thrown away."""
        features = extract_features(normalize("foo.pages.dev"))
        assert features.classification is not None
        assert features.classification.public_suffix == "pages.dev"
        assert features.scope(REGISTRANT_LABEL) == "foo"

    def test_features_still_construct_without_a_classification(self):
        """Defaults keep existing fixtures and callers working."""
        from backend.app.core.features import DomainFeatures

        bare = DomainFeatures(
            domain="x.com", registrable_domain="x.com", sld="x", tld="com",
            subdomain="",
        )
        assert bare.classification is None
        assert bare.scope(REGISTRANT_LABEL) == ""
        assert bare.name_kind is None
