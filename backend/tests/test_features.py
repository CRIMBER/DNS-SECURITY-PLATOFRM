"""Feature-extraction and lexical-scoring tests.

These assert *relative* behaviour (a random string scores higher than a real
brand) rather than exact point values, so retuning the config file does not
break the suite.
"""

import pytest

from backend.app.core.features import (
    dictionary_coverage,
    extract_features,
    levenshtein,
    max_repeat_run,
    shannon_entropy,
)
from backend.app.core.lexical import score_lexical
from backend.app.core.normalizer import normalize

LEGITIMATE = [
    "github.com",
    "google.com",
    "amazon.com",
    "wikipedia.org",
    "cloudflare.com",
    "bbc.co.uk",
    "irctc.co.in",
    "uidai.gov.in",
    "sbi.co.in",
    "openai.com",
]

DGA_LIKE = [
    "kq3v9z7jx1p8w.info",
    "xkzqmwvbtrn.xyz",
    "vhwnxkzptqrjmb.top",
    "zxqvbnmkljhgfd.tk",
    "p9x2m7k4q1w8z3.buzz",
]


def lex(domain: str) -> float:
    return score_lexical(extract_features(normalize(domain))).score


class TestPrimitives:
    def test_entropy_zero_for_uniform_string(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_entropy_increases_with_variety(self):
        assert shannon_entropy("abcdefgh") > shannon_entropy("aabbccdd")

    def test_entropy_of_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_max_repeat_run(self):
        assert max_repeat_run("aabbbbcc") == 4
        assert max_repeat_run("abc") == 1

    def test_levenshtein_basic(self):
        assert levenshtein("paypal", "paypa1") == 1
        assert levenshtein("google", "gooogle") == 1

    def test_levenshtein_early_exit(self):
        assert levenshtein("abc", "zzzzzzzzzz", max_distance=2) == 3

    def test_dictionary_coverage_recognises_words(self):
        assert dictionary_coverage("onlinebanking") > 0.8

    def test_dictionary_coverage_zero_for_random(self):
        assert dictionary_coverage("kqvzxjw") == 0.0


class TestFeatureExtraction:
    def test_basic_counts(self):
        f = extract_features(normalize("secure-login-99.example.com"))
        assert f.hyphen_count == 2
        assert f.digit_count == 2
        assert f.subdomain_count == 1
        assert f.registrable_domain == "example.com"

    def test_suspicious_tld_detected(self):
        assert extract_features(normalize("anything.tk")).tld_is_suspicious is True

    def test_ordinary_tld_not_suspicious(self):
        assert extract_features(normalize("anything.com")).tld_is_suspicious is False

    def test_public_suffix_never_triggers_keywords(self):
        # 'gov' must not be read as a phishing keyword inside 'gov.in'.
        f = extract_features(normalize("uidai.gov.in"))
        assert f.suspicious_keywords == []

    def test_keyword_weighting_distinguishes_strength(self):
        weak = extract_features(normalize("mail.example.com"))
        strong = extract_features(normalize("verify-suspended.example.com"))
        assert strong.keyword_max_weight > weak.keyword_max_weight

    def test_features_serialise_to_json_safe_dict(self):
        data = extract_features(normalize("example.com")).to_dict()
        assert isinstance(data["entropy"], float)
        assert "char_class_distribution" in data


class TestBrandImpersonation:
    def test_token_match_flagged(self):
        f = extract_features(normalize("paypal-secure-verify.top"))
        assert f.brand_impersonation is True
        assert f.brand_target == "paypal.com"

    def test_typosquat_flagged(self):
        assert extract_features(normalize("paypa1.com")).brand_impersonation is True

    @pytest.mark.parametrize(
        "domain",
        ["paypal.com", "www.paypal.com", "google.co.in", "github.io", "amazon.in"],
    )
    def test_genuine_brand_domains_never_flagged(self, domain):
        assert extract_features(normalize(domain)).brand_impersonation is False

    def test_unrelated_domain_not_flagged(self):
        assert extract_features(normalize("sbi.co.in")).brand_impersonation is False


class TestLexicalScoring:
    @pytest.mark.parametrize("domain", LEGITIMATE)
    def test_legitimate_domains_score_low(self, domain):
        assert lex(domain) < 30, "{} scored too high".format(domain)

    @pytest.mark.parametrize("domain", DGA_LIKE)
    def test_dga_like_domains_score_high(self, domain):
        assert lex(domain) > 45, "{} scored too low".format(domain)

    def test_random_scores_above_legitimate(self):
        assert lex("xkzqmwvbtrn.xyz") > lex("github.com")

    def test_score_is_bounded(self):
        worst = lex("secure-login-verify-account-suspended-x9k2m7q4w1z8.tk")
        assert 0.0 <= worst <= 100.0

    def test_clean_domain_still_explains_itself(self):
        signal = score_lexical(extract_features(normalize("amazon.com")))
        assert signal.factors, "every result must carry an explanation"
        assert signal.factors[0].code == "LEXICAL_CLEAN"

    def test_short_domain_lowers_confidence(self):
        # Both domains fire the same single rule (SUSPICIOUS_TLD) for the same
        # score, so the only variable left is label length. Compared against a
        # clean pair this would prove nothing: a clean domain now abstains
        # entirely, and 0.0 is not less than 0.0.
        short = score_lexical(extract_features(normalize("bb.tk")))
        normal = score_lexical(extract_features(normalize("cloudflare.tk")))
        assert short.score == normal.score, "the finding must be held constant"
        assert short.confidence < normal.confidence

    def test_clean_domain_abstains_rather_than_voting_safe(self):
        """Absence of a lexical anomaly is not evidence of safety.

        A clean name must drop out of the weighted average rather than
        contribute a confident zero, which would dilute independent evidence
        from the behavioural, tunnelling, DGA or threat-intelligence signals.
        """
        signal = score_lexical(extract_features(normalize("cloudflare.com")))
        assert signal.score == 0.0
        assert signal.confidence == 0.0
        assert not signal.is_informative

    def test_lexical_anomaly_still_reports_confidently(self):
        """The asymmetry must not mute positive findings."""
        signal = score_lexical(extract_features(normalize("secure-login-verify-account.tk")))
        assert signal.score > 0.0
        assert signal.confidence > 0.0
        assert signal.is_informative

    def test_every_factor_has_an_explanation(self):
        signal = score_lexical(extract_features(normalize("paypal-verify-login.tk")))
        for factor in signal.factors:
            assert factor.label and factor.detail
            assert factor.severity is not None
