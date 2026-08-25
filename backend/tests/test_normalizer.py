"""Normalisation and input-validation tests.

The normalizer is the only stage that rejects input, so its error behaviour is
what stands between a judge typing something odd and a stack trace.
"""

import pytest

from backend.app.core.normalizer import (
    MAX_DOMAIN_LENGTH,
    DomainValidationError,
    normalize,
)


class TestCanonicalisation:
    def test_lowercases_and_strips_trailing_dot(self):
        assert normalize("GitHub.COM.").domain == "github.com"

    def test_strips_surrounding_whitespace_and_quotes(self):
        assert normalize('  "example.com"  ').domain == "example.com"

    @pytest.mark.parametrize(
        "raw",
        [
            "https://mail.google.com/inbox?tab=1",
            "http://mail.google.com",
            "mail.google.com/inbox",
            "mail.google.com:8443",
            "user:pw@mail.google.com",
        ],
    )
    def test_extracts_host_from_pasted_input(self, raw):
        assert normalize(raw).domain == "mail.google.com"

    def test_marks_url_input(self):
        assert normalize("https://example.com/a").was_url is True
        assert normalize("example.com").was_url is False


class TestStructure:
    def test_splits_simple_domain(self):
        nd = normalize("www.example.com")
        assert nd.registrable_domain == "example.com"
        assert nd.sld == "example"
        assert nd.tld == "com"
        assert nd.subdomain == "www"

    def test_handles_multi_label_public_suffix(self):
        nd = normalize("secure.hdfcbank.co.in")
        assert nd.public_suffix == "co.in"
        assert nd.registrable_domain == "hdfcbank.co.in"
        assert nd.sld == "hdfcbank"
        assert nd.subdomain == "secure"

    def test_deep_subdomains_preserved(self):
        nd = normalize("a.b.c.d.example.com")
        assert nd.registrable_domain == "example.com"
        assert nd.subdomain == "a.b.c.d"

    def test_single_label_is_accepted_not_rejected(self):
        # Single-label queries genuinely occur in DNS telemetry.
        nd = normalize("localhost")
        assert nd.is_single_label is True
        assert nd.domain == "localhost"

    def test_underscore_label_accepted(self):
        # _dmarc.example.com is a legitimate DNS name.
        nd = normalize("_dmarc.example.com")
        assert nd.has_underscore is True
        assert nd.registrable_domain == "example.com"


class TestSpecialForms:
    def test_ipv4_literal(self):
        nd = normalize("192.168.1.10")
        assert nd.is_ip_literal is True

    def test_ipv6_literal_in_brackets(self):
        assert normalize("[2001:db8::1]").is_ip_literal is True

    def test_internationalised_domain_becomes_punycode(self):
        nd = normalize("münchen.de")
        assert nd.domain.startswith("xn--")
        assert nd.is_punycode is True

    def test_existing_punycode_is_flagged(self):
        assert normalize("xn--80ak6aa92e.com").is_punycode is True


class TestRejection:
    @pytest.mark.parametrize("raw", ["", "   ", None])
    def test_empty_input(self, raw):
        with pytest.raises(DomainValidationError) as exc:
            normalize(raw)
        assert exc.value.code == "EMPTY_INPUT"

    def test_domain_too_long(self):
        too_long = ".".join(["a" * 60] * 5) + ".com"
        assert len(too_long) > MAX_DOMAIN_LENGTH
        with pytest.raises(DomainValidationError) as exc:
            normalize(too_long)
        assert exc.value.code == "DOMAIN_TOO_LONG"

    def test_label_too_long(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("a" * 64 + ".com")
        assert exc.value.code == "LABEL_TOO_LONG"

    def test_input_far_too_large(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("a" * 5000)
        assert exc.value.code == "INPUT_TOO_LARGE"

    def test_consecutive_dots(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("example..com")
        assert exc.value.code == "EMPTY_LABEL"

    @pytest.mark.parametrize("raw", ["exa mple.com", "exa$mple.com", "ex!ample.com"])
    def test_illegal_characters(self, raw):
        with pytest.raises(DomainValidationError) as exc:
            normalize(raw)
        assert exc.value.code == "INVALID_LABEL_FORMAT"

    def test_leading_hyphen_label(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("-bad.com")
        assert exc.value.code == "INVALID_LABEL_FORMAT"

    def test_all_numeric_tld(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("example.123")
        assert exc.value.code == "NUMERIC_TLD"

    def test_errors_carry_a_human_readable_message(self):
        with pytest.raises(DomainValidationError) as exc:
            normalize("example..com")
        assert exc.value.message
        assert not exc.value.message.startswith("Traceback")
