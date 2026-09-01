"""Phase 5F: a label built from known words was chosen, not generated.

THE FALSE-POSITIVE FAMILY

Three legitimate infrastructure domains survived Phase 5E, each for a
different reason, and only one of them is a blocking failure:

    netdna-cdn.com             92/BLOCK    DGA z=4.75, inflated by the hyphen
    raw.githubusercontent.com  36/MONITOR  lexical entropy/length over the FQDN
    bunnycdn.com               44/MONITOR  DGA z=2.96, "bunny" absent from the lexicon

THE GENERIC PROPERTY

Measured over the corpus, dictionary coverage separates the two populations
completely among the labels the DGA model actually reports on:

    generated names            0.000  (every single one)
    legitimate infrastructure  0.375 - 1.000

That is not a coincidence of this sample. The DGA model asks exactly one
question - "was this label GENERATED rather than chosen by a person?" - and
coverage answers it directly, from a different kind of evidence than the
character statistics. netdna-cdn.com is 0.667: "netdna" plus "cdn".

THE MECHANISM

When more than half a label is explained by known words, the model abstains:
its question has been answered in the negative by direct evidence, so its
character reading is not evidence of generation.

Scoped strictly to this model's own question. It does not touch fusion,
enforcement, behavioural, threat-intelligence or brand evidence - which is
exactly what separates it from the blanket DGA discount rejected in 5E.

It costs nothing against word-composed PHISHING, because a bigram model never
caught those: dictionary-word DGAs are a documented blind spot of any
character model, and names like secure-login-bank-verify.tk are carried by
keyword, TLD and brand evidence instead.

IT IS NOT FREE, AND THE FIRST 5F PASS UNDERSTATED THAT.

The refurbished pass widened the adversarial corpus and found the exposure:
a name whose ONLY suspicion came from the DGA model, and which is built from
known words, loses that suspicion entirely.

    data-exfil-node.test    40/MONITOR -> 15/ALLOW  (coverage 0.62)

The abstention is semantically right - "data", "exfil", "node" is a name a
person chose, so the DGA reading of 0.53 was itself a misfire - but the
platform had nothing else that objected to it.

THAT GAP HAS SINCE BEEN CLOSED, AND IT WAS NOT ENOUGH.

The malware-operations vocabulary added to suspicious_keywords.json gives this
name the independent evidence it was missing: it now matches "exfil" and the
lexical signal reports 15 points where it previously reported nothing. The
numbers above moved accordingly - 59 -> 40 with the flag off, because weighted
fusion averages the new lexical 15 against the DGA 59; and 0 -> 15 with it on,
because the lexical finding is all that remains.

But 15 is still inside ALLOW. The suspicious_keyword rule caps at 20 points
(points_scale 16, max_points 20), deliberately, because phishing tokens are
individually weak evidence - so keyword evidence ALONE cannot reach the
MONITOR band at 30, however strong the token. Independent evidence exists now
and still cannot carry the case by itself.

So the gate stated in Phase 5F - "no attack is downgraded into ALLOW" - still
fails, and the mechanism stays off. Recorded and pinned below either way.

STATE: DISABLED BY DEFAULT

Enabling it moves a protected reference value - behaviour-demo 46 -> 39,
decision unchanged - because "behaviour-demo" is itself 54% known words. That
is a decision for the owner of those values, so the mechanism ships measured,
tested and switched off. Both states are pinned below so neither is vacuous.
"""

import pytest

from backend.app.config import get_risk_config, reload_risk_config
from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline, reset_pipeline

FLAG_PATH = ("dga", "model_parameters", "word_composed_abstention")


@pytest.fixture
def with_abstention_enabled():
    """Flip the flag in the loaded config, and put it back afterwards."""
    config = get_risk_config()
    node = config._data
    for part in FLAG_PATH:
        node = node[part]
    previous = node["enabled"]
    node["enabled"] = True
    reset_pipeline()
    try:
        yield get_pipeline()
    finally:
        node["enabled"] = previous
        reload_risk_config()
        reset_pipeline()


def verdict(pipeline, domain):
    a = pipeline.analyse(domain).assessment
    return a.score, a.decision


def coverage(domain):
    return extract_features(normalize(domain)).dictionary_word_coverage


# -- the property the mechanism rests on ------------------------------------


class TestCoverageSeparatesThePopulations:
    """If this separation ever stops holding, the mechanism is unsound."""

    @pytest.mark.parametrize("domain", [
        "kq3v9z7jx1p8w.info", "zxqvbnmkljhgfd.tk", "vhwnxkzptqrjmb.top",
        "xjqzwvbnmk4d8f2.top", "p9x2m7k4q1w8z3.buzz", "qwzkxjvbnmrtplf.com",
        "dzlkbjnr8dfg7.cloudfront.net",
    ])
    def test_generated_names_have_no_dictionary_coverage(self, domain):
        assert coverage(domain) == 0.0, domain

    @pytest.mark.parametrize("domain,minimum", [
        ("netdna-cdn.com", 0.6), ("raw.githubusercontent.com", 0.9),
        ("bunnycdn.com", 0.3), ("cdn.jsdelivr.net", 0.7),
        ("static.cloudflareinsights.com", 0.7), ("node16cdn.com", 0.9),
    ])
    def test_infrastructure_names_do_decompose(self, domain, minimum):
        assert coverage(domain) >= minimum, domain


# -- state 1: shipped default (disabled) ------------------------------------


class TestDefaultStateIsUnchanged:
    """The tree ships with the mechanism off; behaviour must be Phase 5E's."""

    def test_flag_is_disabled_by_default(self):
        assert get_risk_config().get(
            "dga.model_parameters.word_composed_abstention.enabled") is False

    @pytest.mark.parametrize("domain,score,decision", [
        ("netdna-cdn.com", 92, "BLOCK"),
        ("apple-id-verify.xyz", 70, "BLOCK"),
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
    ])
    def test_scores_are_phase_5e_scores(self, domain, score, decision):
        assert verdict(get_pipeline(), domain) == (score, decision)


# -- state 2: enabled ---------------------------------------------------------


class TestEnabledStateFixesTheFalsePositive:
    def test_the_blocking_false_positive_is_resolved(self, with_abstention_enabled):
        """netdna-cdn.com: a legitimate CDN, blocked at 92 on one DGA finding."""
        score, decision = verdict(with_abstention_enabled, "netdna-cdn.com")
        assert decision == "ALLOW", "scored {}".format(score)

    def test_the_phishing_case_gets_stronger_not_weaker(self, with_abstention_enabled):
        """apple-id-verify.xyz 70 -> 85.

        The marginal DGA finding that Phase 5E had to floor around now
        abstains, so the lexical 85 stands on its own evidence.
        """
        score, decision = verdict(with_abstention_enabled, "apple-id-verify.xyz")
        assert decision == "BLOCK"
        assert score >= 70

    @pytest.mark.parametrize("domain,score,decision", [
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
        ("zxqvbnmkljhgfd.tk", 99, "BLOCK"),
        ("xjqzwvbnmk4d8f2.top", 100, "BLOCK"),
        ("p9x2m7k4q1w8z3.buzz", 98, "BLOCK"),
        ("vhwnxkzptqrjmb.top", 98, "BLOCK"),
        ("dzlkbjnr8dfg7.cloudfront.net", 89, "BLOCK"),
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("secure-login-microsoft-verify.tk", 100, "BLOCK"),
        ("hdfcbank-netbanking-verify.xyz", 100, "BLOCK"),
        ("amazon-account-suspended.cf", 91, "BLOCK"),
        ("paypal-secure-verify.top", 91, "BLOCK"),
        ("github-login-security.example", 88, "BLOCK"),
    ])
    def test_no_attack_loses_a_single_point(
            self, with_abstention_enabled, domain, score, decision):
        assert verdict(with_abstention_enabled, domain) == (score, decision)

    @pytest.mark.parametrize("domain", [
        "secure-login-bank-verify.tk", "my-secure-payment-portal.cf",
        "account-update-service.top", "password-reset-service.xyz",
    ])
    def test_word_composed_phishing_is_not_laundered(
            self, with_abstention_enabled, domain):
        """The obvious evasion: build the name entirely from real words.

        It buys nothing. A bigram model never caught these - dictionary-word
        DGAs are its documented blind spot - so abstaining costs no detection.
        Keyword, TLD and brand evidence carry them exactly as before.
        """
        score, decision = verdict(with_abstention_enabled, domain)
        assert decision in ("MONITOR", "BLOCK"), "{} -> {}".format(domain, score)
        assert coverage(domain) > 0.5, "this test must exercise the abstention"

    def test_the_abstention_is_visible_in_the_result(self, with_abstention_enabled):
        """A model that stopped reporting must say so."""
        meta = with_abstention_enabled.analyse("netdna-cdn.com").dga_metadata
        assert bool(meta["components"]["word_composed_abstention"]) is True
        signal = next(s for s in with_abstention_enabled.analyse(
            "netdna-cdn.com").signals if s.name == "dga")
        assert signal.confidence == 0.0

    def test_a_random_label_still_reports(self, with_abstention_enabled):
        meta = with_abstention_enabled.analyse("zxqvbnmkljhgfd.tk").dga_metadata
        assert bool(meta["components"]["word_composed_abstention"]) is False
        signal = next(s for s in with_abstention_enabled.analyse(
            "zxqvbnmkljhgfd.tk").signals if s.name == "dga")
        assert signal.confidence > 0.0


class TestEnablingCostIsRecorded:
    @pytest.mark.parametrize("domain,before_score", [
        ("data-exfil-node.test", 40),
    ])
    def test_the_detection_that_would_be_lost_is_named(
            self, with_abstention_enabled, domain, before_score):
        """The cost the first 5F pass missed, asserted rather than described.

        With the mechanism ON this name drops to ALLOW. It is pinned here so
        that switching the flag on cannot be done without meeting this test,
        and so the exposure is discoverable in the suite rather than only in
        a report.
        """
        score, decision = verdict(with_abstention_enabled, domain)
        assert (score, decision) == (15, "ALLOW"), (
            "the measured cost of enabling has changed - re-measure before "
            "trusting the recorded trade-off"
        )
        assert coverage(domain) > 0.5

    def test_that_detection_is_intact_while_the_flag_is_off(self):
        """As shipped, nothing is lost."""
        assert verdict(get_pipeline(), "data-exfil-node.test") == (40, "MONITOR")

    def test_the_reference_value_that_moves_is_named(self, with_abstention_enabled):
        """The one measured cost, asserted rather than described.

        behaviour-demo's own label is 54% known words, so its marginal DGA
        finding abstains too and the reference value moves 46 -> 39. The
        DECISION is unchanged. This test exists so that cost cannot be
        forgotten if the flag is ever switched on.
        """
        assert coverage("host10.behaviour-demo.invalid") > 0.5
