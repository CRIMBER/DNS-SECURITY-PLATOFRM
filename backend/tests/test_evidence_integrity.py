"""Phase 5E: weak suspicion must not average away corroborated strong evidence.

THE BUG

apple-id-verify.xyz scored 65/MONITOR. Its lexical signal reported 85 - brand
impersonation of apple.com, an abuse-heavy TLD, a phishing keyword and high
entropy, four independent findings - while the DGA model reported 50.7, one
thousandth above the score below which it abstains entirely. Fusion is a
confidence-weighted average:

    (0.25*0.85*85 + 0.35*0.80*50.7) / (0.25*0.85 + 0.35*0.80) = 65.5

so a detector saying "moderately suspicious" pulled a phishing domain out of
the blocking band. The gateway would have resolved it.

That is the wrong reading of a suspicion signal. "Moderately suspicious" is
not a finding of SAFETY, and it must not buy a domain out of a band another
detector independently put it in - the same asymmetry the engine already
applies to abstention, extended from absent evidence to weak evidence.

THE RULE

A signal that independently reaches the blocking band on two or more distinct
findings sets a floor at that band. The second condition is what stops this
becoming "one signal decides": a lone heuristic cannot force a block, only
corroborated evidence can. The floor is the threshold itself, never the
signal's own score, so the fix restores the decision the evidence supports
without inventing certainty. It is applied before the allowlist ceiling, which
remains authoritative.

WHAT WAS REJECTED

The mirror rule - capping a block that rests on ONE heuristic finding - would
have fixed netdna-cdn.com (a legitimate CDN blocked at 92 on DGA_HIGH alone,
with nothing else agreeing). It was implemented, measured, and REJECTED: it
downgrades a behavioural-only detection, which is the DNS fan-out attack the
engine exists to catch, and test_risk_engine.py pins that deliberately. The
measurement is recorded in the limitation test at the bottom.
"""

import os
import tempfile

import pytest

from backend.app.core.pipeline import get_pipeline, reset_pipeline
from backend.app.dns_gateway.models import DNSContext
from backend.app.storage.events import EventRepository, set_event_repository

BLOCK_THRESHOLD = 70


@pytest.fixture(scope="module")
def pipeline():
    return get_pipeline()


def verdict(pipeline, domain):
    a = pipeline.analyse(domain).assessment
    return a.score, a.decision


def signals_of(pipeline, domain):
    return {s.name: s for s in pipeline.analyse(domain).signals if s.confidence}


# -- A. malicious-downgrade protection --------------------------------------


class TestStrongEvidenceCannotBeAveragedAway:
    def test_the_reported_downgrade_is_fixed(self, pipeline):
        """apple-id-verify.xyz: 65/MONITOR -> BLOCK."""
        score, decision = verdict(pipeline, "apple-id-verify.xyz")
        assert decision == "BLOCK", "scored {}".format(score)

    def test_the_weak_signal_is_still_present_and_still_weak(self, pipeline):
        """The fix must not work by silencing the DGA model.

        Its finding is real and stays in the response; it simply may no longer
        drag a corroborated strong result out of the blocking band.
        """
        sig = signals_of(pipeline, "apple-id-verify.xyz")
        assert "dga" in sig, "the DGA signal must still report"
        assert sig["dga"].score < BLOCK_THRESHOLD
        assert sig["lexical"].score >= BLOCK_THRESHOLD

    def test_the_override_is_explainable(self, pipeline):
        """Every override the engine applies must show up as a factor."""
        a = pipeline.analyse("apple-id-verify.xyz").assessment
        assert "corroborated_evidence_floor" in a.overrides_applied
        assert any(f.code == "OVERRIDE_CORROBORATED_FLOOR" for f in a.factors)

    def test_the_floor_is_the_threshold_not_the_signal_score(self, pipeline):
        """Restore the decision, do not invent certainty."""
        score, _ = verdict(pipeline, "apple-id-verify.xyz")
        sig = signals_of(pipeline, "apple-id-verify.xyz")
        assert score == BLOCK_THRESHOLD
        assert score < sig["lexical"].score


class TestOneLuckyHeuristicCannotForceABlock:
    """The corroboration condition, tested from the other side."""

    def test_a_single_factor_signal_does_not_trigger_the_floor(self):
        """Built directly, because no real domain reaches this shape.

        The floor only runs when fusion lands BELOW the band, so a natural
        example needs a signal at 85 on ONE finding whose fused score is under
        70 - which the corpus does not happen to contain. Constructed here so
        the corroboration guard is actually exercised rather than assumed: with
        min_distinct_factors lowered to 1 this domain would be forced to BLOCK.
        """
        from backend.app.config import get_risk_config
        from backend.app.core.risk_engine import RiskEngine
        from backend.app.core.signals import RiskFactor, Severity, Signal

        def one_factor(name, score, confidence):
            return Signal(
                name=name, score=score, confidence=confidence,
                factors=[RiskFactor(code="LONE", label="l",
                                    severity=Severity.MEDIUM, detail="d",
                                    raw_points=score)],
                metadata={})

        def two_factors(name, score, confidence):
            return Signal(
                name=name, score=score, confidence=confidence,
                factors=[RiskFactor(code="A", label="l", severity=Severity.MEDIUM,
                                    detail="d", raw_points=score / 2),
                         RiskFactor(code="B", label="l", severity=Severity.MEDIUM,
                                    detail="d", raw_points=score / 2)],
                metadata={})

        engine = RiskEngine(get_risk_config())

        lone = engine.assess([
            one_factor("lexical", 85.0, 0.85),
            one_factor("dga", 20.0, 0.80),
        ])
        assert "corroborated_evidence_floor" not in (lone.overrides_applied or ()), (
            "one finding is not corroboration and must not force a block"
        )
        assert lone.decision != "BLOCK"

        corroborated = engine.assess([
            two_factors("lexical", 85.0, 0.85),
            one_factor("dga", 20.0, 0.80),
        ])
        assert "corroborated_evidence_floor" in corroborated.overrides_applied
        assert corroborated.decision == "BLOCK"

    def test_legitimate_domains_never_trigger_the_floor(self, pipeline):
        for domain in ("github.com", "google.com", "youtube.com",
                       "microsoft.com", "apple.com", "amazon.com",
                       "paypal.com", "cdn.jsdelivr.net", "jsdelivr.net",
                       "cdn77.com", "static.cloudflareinsights.com",
                       "raw.githubusercontent.com", "bunnycdn.com"):
            a = pipeline.analyse(domain).assessment
            assert "corroborated_evidence_floor" not in (a.overrides_applied or ()), domain


# -- B. legitimate-domain protection ----------------------------------------


class TestLegitimateDomainsAreNotBlocked:
    @pytest.mark.parametrize("domain", [
        "github.com", "youtube.com", "google.com", "microsoft.com",
        "apple.com", "amazon.com", "paypal.com",
        "cdn.jsdelivr.net", "static.cloudflareinsights.com", "cdn77.com",
        "jsdelivr.net", "cloudfront.net", "fastly.net", "akamai.net",
        "gstatic.com", "keycdn.com", "node16cdn.com", "edge01relay.com",
        "google.de", "amazon.ca", "apple.com.cn", "windows.net",
        "gitlab.com", "s3.eu-west-1.amazonaws.com", "assets.githubassets.com",
        "mail.google.com", "docs.python.org", "scribd.com",
    ])
    def test_not_blocked(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision != "BLOCK", "{} -> {}".format(domain, score)


# -- C. brand impersonation still needs evidence ----------------------------


class TestBrandTokenAloneIsNotImpersonation:
    @pytest.mark.parametrize("domain", [
        "google.de", "amazon.ca", "apple.com.cn", "windows.net",
        "youtube-nocookie.com", "instagram-brand.com", "googleapis.com",
    ])
    def test_brand_owned_domains_stay_allowed(self, pipeline, domain):
        assert verdict(pipeline, domain)[1] == "ALLOW", domain

    @pytest.mark.parametrize("domain", [
        "apple-id-verify.xyz", "paypal-secure-verify.top",
        "secure-login-microsoft-verify.tk", "hdfcbank-netbanking-verify.xyz",
        "amazon-account-suspended.cf", "github-login-security.example",
    ])
    def test_brand_plus_corroboration_still_escalates(self, pipeline, domain):
        score, decision = verdict(pipeline, domain)
        assert decision in ("MONITOR", "BLOCK"), domain
        assert score >= 60, domain


# -- adversarial matrix -----------------------------------------------------


class TestAttackMatrixIsUnweakened:
    @pytest.mark.parametrize("domain,score,decision", [
        ("github-login-security.example", 88, "BLOCK"),
        ("github-security.example", 61, "MONITOR"),
        ("github.verify.example", 60, "MONITOR"),
        ("paypal-secure-verify.top", 91, "BLOCK"),
        ("secure-login-microsoft-verify.tk", 100, "BLOCK"),
        ("hdfcbank-netbanking-verify.xyz", 100, "BLOCK"),
        ("amazon-account-suspended.cf", 91, "BLOCK"),
        ("zxqvbnmkljhgfd.tk", 99, "BLOCK"),
        ("xjqzwvbnmk4d8f2.top", 100, "BLOCK"),
        ("p9x2m7k4q1w8z3.buzz", 98, "BLOCK"),
        ("vhwnxkzptqrjmb.top", 98, "BLOCK"),
        ("dzlkbjnr8dfg7.cloudfront.net", 89, "BLOCK"),
        ("paypa1.com", 60, "MONITOR"),
        ("gooogle.com", 60, "MONITOR"),
        ("githhub.com", 60, "MONITOR"),
        ("paypal.tk", 60, "MONITOR"),
    ])
    def test_exact_score_unchanged(self, pipeline, domain, score, decision):
        assert verdict(pipeline, domain) == (score, decision)

    @pytest.mark.parametrize("domain", [
        "botnet-controller.test", "dropper-stage2.test",
        "tunnel-relay-node.test",
    ])
    def test_single_indicator_iocs_still_block(self, pipeline, domain):
        """These block on TI_MALICIOUS alone and must never be capped."""
        assert verdict(pipeline, domain)[1] == "BLOCK", domain

    @pytest.mark.parametrize("domain", [
        "qwzkxjvbnmrtplf.com", "zxcvbnmasdfghjk.com", "kqjxzvwmbnrt.net",
        "xkzqmwvbtrn.org", "dzlkbjnrdfg.com",
    ])
    def test_generated_names_on_clean_tlds_still_block(self, pipeline, domain):
        assert verdict(pipeline, domain)[1] == "BLOCK", domain


# -- D. Phase 3 protected values ---------------------------------------------


class TestPhase3ReferenceValues:
    @pytest.mark.parametrize("domain,score,decision", [
        ("malware-c2-panel.test", 85, "BLOCK"),
        ("malware-c2-panel.invalid", 18, "ALLOW"),
        ("kq3v9z7jx1p8w.info", 95, "BLOCK"),
    ])
    def test_reference_value_unchanged(self, pipeline, domain, score, decision):
        assert verdict(pipeline, domain) == (score, decision)

    def test_behavioural_reference_value_unchanged(self, tmp_path):
        """46/MONITOR, with the seeded DNS history it depends on."""
        import backend.app.storage.events as events_module

        previous = events_module._repository
        repo = EventRepository(path=tmp_path / "phase3.db")
        set_event_repository(repo)
        reset_pipeline()
        try:
            pipe = get_pipeline()
            for index in range(1, 10):
                result = pipe.analyse(
                    "host{:02d}.behaviour-demo.invalid".format(index))
                repo.log(result, source="dns", dns=DNSContext(
                    query_type="A", client_address="127.0.0.1",
                    response_code="NXDOMAIN", blocked=False))
            a = pipe.analyse("host10.behaviour-demo.invalid").assessment
            assert (a.score, a.decision) == (46, "MONITOR")
        finally:
            set_event_repository(previous)
            reset_pipeline()


# -- E. idempotency ----------------------------------------------------------


class TestRepetitionCannotSoftenAVerdict:
    def test_repeated_analysis_of_a_blocked_domain_is_stable(self, pipeline):
        first = verdict(pipeline, "apple-id-verify.xyz")
        assert first[1] == "BLOCK"
        for _ in range(20):
            assert verdict(pipeline, "apple-id-verify.xyz") == first

    def test_repeated_analysis_of_a_legitimate_domain_is_stable(self, pipeline):
        first = verdict(pipeline, "cdn.jsdelivr.net")
        for _ in range(20):
            assert verdict(pipeline, "cdn.jsdelivr.net") == first


# -- what was measured and rejected ------------------------------------------


class TestRejectedFixIsRecorded:
    def test_netdna_cdn_still_blocks_and_here_is_why_it_was_not_fixed(
            self, pipeline):
        """netdna-cdn.com: 92/BLOCK, a legitimate CDN, on DGA_HIGH alone.

        The mirror of the Phase 5E rule - capping a block that rests on one
        heuristic finding - fixes it (92/BLOCK -> 69/MONITOR) and cost nothing
        across a 55-domain sweep: no attack weakened, no reference value moved,
        and the three IOCs that block on TI_MALICIOUS alone were protected by
        an explicit threat-intelligence exemption.

        It was still REJECTED. It downgrades a behavioural-only detection - a
        domain with an ordinary name whose query pattern is anomalous, which is
        the DNS fan-out attack the engine exists to catch - and
        test_risk_engine.py pins that behaviour deliberately. Trading a real
        detection for a false positive is the wrong direction, so the false
        positive stands and is recorded here instead.
        """
        assert verdict(pipeline, "netdna-cdn.com") == (92, "BLOCK")
