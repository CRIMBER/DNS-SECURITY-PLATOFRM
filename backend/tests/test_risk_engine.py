"""Risk-engine tests.

The two properties that matter most:
  1. contributions always sum to the final score (the explanation IS the maths)
  2. a zero-confidence signal is excluded, never averaged in as "safe"
"""

import pytest

from backend.app.config import get_risk_config
from backend.app.core.risk_engine import RiskEngine
from backend.app.core.signals import RiskFactor, Severity, Signal


def signal(name, score, confidence, points=None, code="X", metadata=None):
    return Signal(
        name=name,
        score=score,
        confidence=confidence,
        factors=[
            RiskFactor(
                code=code,
                label="factor",
                severity=Severity.MEDIUM,
                detail="detail",
                raw_points=score if points is None else points,
            )
        ],
        metadata=metadata or {},
    )


@pytest.fixture
def engine():
    return RiskEngine(get_risk_config())


class TestFusion:
    def test_single_signal_drives_the_score(self, engine):
        result = engine.assess([signal("dga", 80.0, 1.0)])
        assert result.score == 80

    def test_weighted_average_of_two_signals(self, engine):
        """dga 0.35 and lexical 0.25 at full confidence -> weighted mean."""
        result = engine.assess([
            signal("dga", 100.0, 1.0),
            signal("lexical", 0.0, 1.0, points=0.0),
        ])
        expected = (0.35 * 100 + 0.25 * 0) / (0.35 + 0.25)
        assert abs(result.raw_score - expected) < 0.5

    def test_zero_confidence_signal_is_excluded(self, engine):
        """The central requirement: a miss must not vote for safety."""
        with_miss = engine.assess([
            signal("threat_intel", 0.0, 0.0, points=0.0),
            signal("dga", 90.0, 1.0),
        ])
        without = engine.assess([signal("dga", 90.0, 1.0)])
        assert with_miss.score == without.score == 90

    def test_zero_confidence_marked_as_not_used(self, engine):
        result = engine.assess([
            signal("threat_intel", 0.0, 0.0, points=0.0),
            signal("dga", 90.0, 1.0),
        ])
        ti = [s for s in result.signals if s.name == "threat_intel"][0]
        assert ti.used_in_fusion is False
        assert ti.weighted_contribution == 0.0

    def test_no_signals_at_all_is_handled(self, engine):
        result = engine.assess([])
        assert result.score == 0
        assert result.classification == "SAFE"

    def test_all_signals_silent_reports_no_evidence(self, engine):
        result = engine.assess([signal("dga", 0.0, 0.0, points=0.0)])
        assert any(f.code == "NO_EVIDENCE" for f in result.factors)

    def test_evidence_coverage_reflects_reporting_weight(self, engine):
        full = engine.assess([
            signal("threat_intel", 50.0, 1.0),
            signal("dga", 50.0, 1.0),
            signal("lexical", 50.0, 1.0),
        ])
        partial = engine.assess([
            signal("threat_intel", 0.0, 0.0, points=0.0),
            signal("dga", 50.0, 1.0),
        ])
        assert full.confidence > partial.confidence


class TestExplanationIntegrity:
    """Factor contributions must always reconstruct the score."""

    @pytest.mark.parametrize("scores", [
        (95.0, 20.0, 40.0), (0.0, 0.0, 0.0), (100.0, 100.0, 100.0), (10.0, 85.0, 5.0),
    ])
    def test_contributions_sum_to_score(self, engine, scores):
        ti, dga, lex = scores
        result = engine.assess([
            signal("threat_intel", ti, 0.9, metadata={"verdict": "SUSPICIOUS"}),
            signal("dga", dga, 0.8),
            signal("lexical", lex, 0.85),
        ])
        total = sum(f.contribution for f in result.factors)
        assert abs(total - result.raw_score) < 0.05

    def test_sum_holds_when_overrides_fire(self, engine):
        result = engine.assess([
            signal("threat_intel", 95.0, 0.98, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 10.0, 0.8),
            signal("lexical", 5.0, 0.85),
        ])
        total = sum(f.contribution for f in result.factors)
        assert abs(total - result.raw_score) < 0.05
        assert "ti_malicious_floor" in result.overrides_applied

    def test_every_factor_carries_an_explanation(self, engine):
        result = engine.assess([
            signal("threat_intel", 95.0, 0.98, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 90.0, 0.8),
        ])
        for factor in result.factors:
            assert factor.label and factor.detail and factor.code


class TestOverrides:
    def test_ti_malicious_applies_a_floor(self, engine):
        result = engine.assess([
            signal("threat_intel", 95.0, 0.98, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 0.0, 0.8, points=0.0),
            signal("lexical", 0.0, 0.85, points=0.0),
        ])
        assert result.score >= 85
        assert result.decision == "BLOCK"

    def test_floor_is_not_a_short_circuit(self, engine):
        """Other signals can still push the score above the floor."""
        low = engine.assess([
            signal("threat_intel", 95.0, 0.98, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 0.0, 0.8, points=0.0),
        ])
        high = engine.assess([
            signal("threat_intel", 95.0, 0.98, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 100.0, 0.8),
        ])
        assert high.score > low.score

    def test_trusted_applies_a_ceiling(self, engine):
        result = engine.assess([
            signal("threat_intel", 0.0, 0.9, points=0.0, metadata={"verdict": "TRUSTED"}),
            signal("lexical", 100.0, 0.85),
            signal("dga", 100.0, 0.8),
        ])
        assert result.score <= 25
        assert result.decision == "ALLOW"
        assert "ti_trusted_ceiling" in result.overrides_applied

    def test_brand_impersonation_floor(self, engine):
        result = engine.assess([
            signal("threat_intel", 0.0, 0.0, points=0.0, metadata={"verdict": "UNKNOWN"}),
            signal("lexical", 28.0, 0.85, code="BRAND_IMPERSONATION"),
        ])
        assert result.score >= 60
        assert "brand_impersonation_floor" in result.overrides_applied

    def test_corroboration_bonus_needs_two_signals(self, engine):
        one = engine.assess([signal("dga", 90.0, 0.8)])
        two = engine.assess([signal("dga", 90.0, 0.8), signal("lexical", 90.0, 0.85)])
        assert "corroboration_bonus" not in one.overrides_applied
        assert "corroboration_bonus" in two.overrides_applied

    def test_score_never_leaves_bounds(self, engine):
        result = engine.assess([
            signal("threat_intel", 100.0, 1.0, metadata={"verdict": "MALICIOUS"}),
            signal("dga", 100.0, 1.0),
            signal("lexical", 100.0, 1.0),
        ])
        assert 0 <= result.score <= 100


class TestClassification:
    @pytest.mark.parametrize("score,classification,decision", [
        (0, "SAFE", "ALLOW"), (29, "SAFE", "ALLOW"),
        (30, "SUSPICIOUS", "MONITOR"), (69, "SUSPICIOUS", "MONITOR"),
        (70, "MALICIOUS", "BLOCK"), (100, "MALICIOUS", "BLOCK"),
    ])
    def test_bands_match_configuration(self, score, classification, decision):
        band = get_risk_config().classify(score)
        assert band["classification"] == classification
        assert band["decision"] == decision

    def test_recommendation_is_present_for_every_decision(self, engine):
        for score in (5.0, 50.0, 95.0):
            result = engine.assess([signal("dga", score, 1.0)])
            assert len(result.recommended_action) > 20
