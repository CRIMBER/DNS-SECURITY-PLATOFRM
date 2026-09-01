"""Phase 5D: three ways the lexical/DGA layer charged a name for its shape.

Each fix is a scope or double-count correction, not a threshold move and not a
list. All three make the measurement mean what it says it measures.

M1  CONSONANT RUNS CROSSED LABEL BOUNDARIES
    max_consonant_run was computed over the FQDN with its dots deleted, so the
    join of two labels invented runs that appear nowhere in the name:
    "cdn.jsdelivr.net" became "cdnjsdelivrnet" and was charged 6 consonants for
    "cdnjsd". A dot is a word boundary; a run cannot span one.

M2  DIGITS WERE COUNTED THREE TIMES
    The bigram chain scored digits, and digit density is ALREADY scored by the
    model's own term_digits and again by the lexical digit-ratio rule. Worse,
    the corpus is built from words, so every digit transition looks maximally
    improbable whatever it means: cdn77 reached z=7.24, as implausible as a
    real DGA. Removing digits from the chain sharpens it BOTH ways - the
    generated names it exists to catch score higher without their digits
    diluting the letters (p9x2m7k4q1w8z3: z 7.73 -> 10.28).

M3  A SHORT LABEL COULD DECIDE A VERDICT IT ADMITTED IT COULD NOT JUDGE
    Below min_confident_length the model already reports confidence_short,
    but confidence is only a RELATIVE weight - a lone reporting signal sets
    the fused score regardless. scribd.com: six letters, seven transitions, a
    moderate z of 2.79, and the resulting 0.58 became the whole 58/MONITOR
    verdict on an ordinary English-looking name. A moderate finding on a short
    label is now a null finding; a STRONG one still reports, which is why
    short random labels are unaffected.

WHAT IS NOT HERE
    Two further fixes were implemented, measured, and REVERTED because they
    move pinned reference values. Both are recorded in the limitation tests at
    the bottom rather than quietly dropped.
"""

import pytest

from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline


@pytest.fixture(scope="module")
def pipeline():
    return get_pipeline()


def verdict(pipeline, domain):
    a = pipeline.analyse(domain).assessment
    return a.score, a.decision


def codes(pipeline, domain):
    return {f.code for f in pipeline.analyse(domain).assessment.factors
            if f.contribution}


# -- 1. the reported false positives ---------------------------------------


class TestReportedFalsePositivesAreFixed:
    @pytest.mark.parametrize("domain,was", [
        ("static.cloudflareinsights.com", 38),
        ("cdn77.com", 45),
        ("scribd.com", 58),
    ])
    def test_now_allowed(self, pipeline, domain, was):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", (
            "{} was {}/MONITOR and is now {}".format(domain, was, score))

    def test_bunnycdn_is_materially_reduced(self, pipeline):
        """Not ALLOW, and reported as such rather than forced."""
        score, decision = verdict(pipeline, "bunnycdn.com")
        assert score <= 45, "regressed above the Phase 5C value"
        assert decision in ("ALLOW", "MONITOR")


# -- 2. M1: consonant runs ---------------------------------------------------


class TestConsonantRunsRespectLabelBoundaries:
    def test_a_run_cannot_span_a_dot(self):
        """cdn.jsdelivr.net has no six-consonant run; the join invented it."""
        assert extract_features(normalize("cdn.jsdelivr.net")).max_consonant_run == 3

    def test_a_genuine_run_inside_one_label_is_still_measured(self):
        assert extract_features(
            normalize("zxqvbnmkljhgfd.tk")).max_consonant_run >= 8

    def test_subdomains_do_not_manufacture_the_factor(self, pipeline):
        assert "CONSONANT_RUN_LONG" not in codes(
            pipeline, "static.cloudflareinsights.com")

    def test_the_factor_still_fires_on_a_real_random_label(self, pipeline):
        assert "CONSONANT_RUN_LONG" in codes(pipeline, "vhwnxkzptqrjmb.top")


# -- 3. M2: digits are not bigram evidence -----------------------------------


class TestDigitsAreNotCountedAsImplausibleLetters:
    def test_digit_bearing_infrastructure_is_not_generated(self, pipeline):
        assert verdict(pipeline, "cdn77.com")[1] == "ALLOW"

    def test_removing_digits_does_not_soften_generated_names(self, pipeline):
        """The point of M2: attacks get stronger, not weaker."""
        for domain in ("kq3v9z7jx1p8w.info", "p9x2m7k4q1w8z3.buzz",
                       "xjqzwvbnmk4d8f2.top"):
            score, decision = verdict(pipeline, domain)
            assert decision == "BLOCK", domain
            assert score >= 95, domain

    def test_digit_density_is_still_scored_by_its_own_rule(self, pipeline):
        """The evidence is not lost - it moves to the rule that owns it."""
        assert "DIGIT_RATIO_HIGH" in codes(pipeline, "kq3v9z7jx1p8w.info")

    def test_the_chain_itself_ignores_digits(self):
        """Unit-level: the same letters score the same, digits or not."""
        from backend.app.detection.heuristic import BigramDGADetector

        model = BigramDGADetector()
        assert model.log_likelihood_ratio("node16cdn") == pytest.approx(
            model.log_likelihood_ratio("nodecdn"))
        assert model.log_likelihood_ratio("cdn77") == pytest.approx(
            model.log_likelihood_ratio("cdn"))

    @pytest.mark.parametrize("domain", [
        "node16cdn.com", "edge01relay.com", "s3website.com",
        "web3proxy.com", "api2gateway.com", "cloudfront2.net",
    ])
    def test_numbered_infrastructure_hostnames_are_allowed(self, pipeline, domain):
        """Versioned and numbered infrastructure names are ordinary.

        These are the names M2 exists for. With digits back in the chain
        node16cdn.com scores 77/BLOCK and edge01relay.com 58/MONITOR, on
        nothing but the improbability of a digit following a letter in a
        corpus built from words.
        """
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} -> {}".format(domain, score)


# -- 4. M3: thin evidence does not decide --------------------------------------


class TestShortLabelsNeedStrongEvidence:
    def test_a_moderate_finding_on_a_short_label_abstains(self, pipeline):
        result = pipeline.analyse("scribd.com")
        dga = next(s for s in result.signals if s.name == "dga")
        assert dga.confidence == 0.0, "a 6-letter label cannot carry a verdict"
        assert verdict(pipeline, "scribd.com")[1] == "ALLOW"

    @pytest.mark.parametrize("domain", ["xkqjzv.tk", "qxzjvk.top"])
    def test_a_strong_finding_on_a_short_label_still_reports(
            self, pipeline, domain):
        """The counterweight: short does not mean trusted."""
        score, decision = verdict(pipeline, domain)
        assert decision in ("MONITOR", "BLOCK"), "{} -> {}".format(domain, score)

    def test_long_generated_labels_are_untouched_by_the_bar(self, pipeline):
        for domain in ("zxqvbnmkljhgfd.tk", "vhwnxkzptqrjmb.top"):
            assert verdict(pipeline, domain)[1] == "BLOCK", domain


# -- 5. structure is not trusted, and vocabulary is not a password -----------


class TestInfrastructureVocabularyIsNotTrust:
    @pytest.mark.parametrize("domain", [
        "cdn-login-verify.tk", "static-paypal-secure.top",
        "cloud-account-suspended.cf", "cdn.hdfcbank-netbanking-verify.xyz",
    ])
    def test_infrastructure_words_do_not_launder_a_hostile_name(
            self, pipeline, domain):
        """Containing "cdn" or "cloud" or "static" buys nothing."""
        score, decision = verdict(pipeline, domain)
        assert decision in ("MONITOR", "BLOCK"), "{} -> {}".format(domain, score)

    def test_a_random_label_under_an_infrastructure_suffix_still_blocks(
            self, pipeline):
        assert verdict(pipeline, "dzlkbjnr8dfg7.cloudfront.net")[1] == "BLOCK"


# -- 6/7. long legitimate FQDN vs long random label --------------------------


class TestLengthEvidenceStillDiscriminates:
    @pytest.mark.parametrize("domain", [
        "s3.eu-west-1.amazonaws.com", "assets.githubassets.com",
        "cdn.jsdelivr.net", "docs.python.org",
    ])
    def test_long_legitimate_fqdns_are_allowed(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision == "ALLOW", "{} -> {}".format(domain, score)

    def test_a_long_random_label_is_still_penalised(self, pipeline):
        score, decision = verdict(pipeline, "kj3h4kj2h3g4k2j3h4g.attacker-domain.xyz")
        assert decision in ("MONITOR", "BLOCK")


# -- 8/9. nothing else moved -------------------------------------------------


class TestAttackMatrixUnchanged:
    @pytest.mark.parametrize("domain,score,decision", [
        ("secure-login-microsoft-verify.tk", 100, "BLOCK"),
        ("hdfcbank-netbanking-verify.xyz", 100, "BLOCK"),
        ("paypal-secure-verify.top", 91, "BLOCK"),
        ("amazon-account-suspended.cf", 91, "BLOCK"),
        ("zxqvbnmkljhgfd.tk", 99, "BLOCK"),
        ("paypa1.com", 60, "MONITOR"),
        ("gooogle.com", 60, "MONITOR"),
        ("githhub.com", 60, "MONITOR"),
        ("paypal.tk", 60, "MONITOR"),
    ])
    def test_exact_attack_scores_are_unchanged(
            self, pipeline, domain, score, decision):
        assert verdict(pipeline, domain) == (score, decision)


class TestPhase3ReferenceValues:
    @pytest.mark.parametrize("domain,score,decision", [
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
    ])
    def test_reference_value_unchanged(self, pipeline, domain, score, decision):
        assert verdict(pipeline, domain) == (score, decision)


# -- 10. what was measured, rejected, and why --------------------------------


class TestRejectedFixesAreRecorded:
    """Two correct-looking fixes that were reverted because they move pins.

    Recorded as tests so the trade-off is discoverable in the suite rather
    than only in a report, and so the day someone decides the pins may move,
    these say exactly what changes.
    """

    def test_hyphen_split_is_rejected_not_merely_deferred(self, pipeline):
        """netdna-cdn.com: 92/BLOCK, and the hyphen fix is now REJECTED.

        Scoring hyphen-separated parts independently takes it to 0/ALLOW, and
        through 5C, 5D and the first 5F pass the only recorded cost was the
        behavioural reference value moving 46 -> 39. That record was
        incomplete: it had only ever been measured against attack names that
        do not contain hyphens.

        The refurbished 5F pass built the adversarial cases the rule invites -
        hostile names assembled from hyphen-separated fragments - and the rule
        fails them, because splitting lets a random fragment hide inside a
        short part that scores as plausible on its own:

            bank-verify-xkqjzv.ml    97/BLOCK   -> 85/BLOCK
            data-exfil-node.test     59/MONITOR -> 0/ALLOW

        A false-positive fix that hands an attacker a naming convention is not
        a fix. This is a rejection on security grounds, independent of the
        reference-value question, and it should not be revisited without new
        evidence against a hyphenated adversarial corpus.
        """
        assert verdict(pipeline, "netdna-cdn.com") == (92, "BLOCK")

    def test_long_multilabel_name_still_monitors_pending_a_decision(
            self, pipeline):
        """raw.githubusercontent.com: 36/MONITOR.

        Judging the worst LABEL instead of the concatenated FQDN takes it to
        10/ALLOW, but moves malware-c2-panel.invalid 18 -> 10 and TUNNEL_NAME
        96 -> 97 (both decisions unchanged). Legitimate and pinned domains
        share the mechanism, and dictionary coverage does not separate them
        (0.615 for the pinned name, 1.000 for the pinned tunnel), so there is
        no discriminator to exploit.
        """
        assert verdict(pipeline, "raw.githubusercontent.com") == (36, "MONITOR")
