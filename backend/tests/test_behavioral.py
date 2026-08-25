"""Behavioural analyser tests.

Runs against a temporary event store so the real log is never touched.

The property that matters most: with no history the analyser **abstains**. It
must never guess, and it must never argue that a domain is safe just because it
has not seen it misbehave yet.
"""

import pytest

from backend.app.config import get_risk_config
from backend.app.core.features import extract_features
from backend.app.core.normalizer import normalize
from backend.app.core.pipeline import get_pipeline
from backend.app.detection import HistoryBehavioralAnalyzer, behavioral_to_signal
from backend.app.dns_gateway.models import DNSContext
from backend.app.storage.events import EventRepository


@pytest.fixture
def repository(tmp_path):
    return EventRepository(path=tmp_path / "behavioral.db")


@pytest.fixture
def analyzer(repository):
    return HistoryBehavioralAnalyzer(repository=repository)


def seed(repository, domain, times=1, response_code="NOERROR", blocked=False):
    """Write real analysis events for a domain."""
    pipeline = get_pipeline()
    for _ in range(times):
        result = pipeline.analyse(domain)
        repository.log(
            result,
            source="test",
            dns=DNSContext(
                query_type="A",
                response_code=response_code,
                blocked=blocked,
            ),
        )


def analyse(analyzer, domain):
    return analyzer.analyse(extract_features(normalize(domain)))


class TestAbstention:
    def test_unseen_domain_produces_no_opinion(self, analyzer):
        result = analyse(analyzer, "never-seen-before.com")
        assert result.confidence == 0.0
        assert result.score == 0.0
        assert result.indicators == []

    def test_barely_seen_domain_still_abstains(self, analyzer, repository):
        seed(repository, "seen-twice.com", times=2)
        result = analyse(analyzer, "seen-twice.com")
        assert result.confidence == 0.0, "two sightings is not behaviour"

    def test_abstaining_signal_is_excluded_from_fusion(self, analyzer):
        signal = behavioral_to_signal(
            analyse(analyzer, "never-seen-before.com"), get_risk_config()
        )
        assert signal.is_informative is False
        assert signal.factors[0].code == "BEHAVIORAL_NO_HISTORY"

    def test_normal_history_does_not_add_risk(self, analyzer, repository):
        seed(repository, "well-behaved.com", times=6)
        result = analyse(analyzer, "well-behaved.com")
        assert result.score == 0.0
        assert result.confidence == 0.0
        signal = behavioral_to_signal(result, get_risk_config())
        assert signal.factors[0].code == "BEHAVIORAL_NORMAL"
        assert "not evidence of safety" in signal.factors[0].detail

    def test_missing_store_is_survived(self):
        class Broken:
            def domain_history(self, *args, **kwargs):
                raise RuntimeError("store unavailable")

        result = HistoryBehavioralAnalyzer(repository=Broken()).analyse(
            extract_features(normalize("example.com"))
        )
        assert result.confidence == 0.0
        assert result.observations["history_available"] is False


class TestDetection:
    def test_query_burst_is_detected(self, analyzer, repository):
        seed(repository, "beacon.example.org", times=25)
        result = analyse(analyzer, "beacon.example.org")
        assert "query_burst" in result.indicators
        assert result.confidence > 0.0

    def test_subdomain_fanout_is_detected(self, analyzer, repository):
        for index in range(10):
            seed(repository, "node{}.fanout-test.com".format(index), times=1)
        result = analyse(analyzer, "fanout-test.com")
        assert "subdomain_fanout" in result.indicators
        assert result.observations["distinct_subdomains"] >= 8

    def test_high_nxdomain_ratio_is_detected(self, analyzer, repository):
        for index in range(8):
            seed(
                repository,
                "gen{}.dga-test.com".format(index),
                times=1,
                response_code="NXDOMAIN",
            )
        result = analyse(analyzer, "dga-test.com")
        assert "high_nxdomain_ratio" in result.indicators

    def test_repeated_blocks_are_remembered(self, analyzer, repository):
        seed(repository, "repeat-offender.com", times=4, blocked=True)
        result = analyse(analyzer, "repeat-offender.com")
        assert "repeatedly_blocked" in result.indicators

    def test_confidence_grows_with_history(self, analyzer, repository):
        seed(repository, "growing.example.org", times=21)
        small = analyse(analyzer, "growing.example.org").confidence
        seed(repository, "growing.example.org", times=40)
        large = analyse(analyzer, "growing.example.org").confidence
        assert large > small

    def test_confidence_is_capped(self, analyzer, repository):
        seed(repository, "very-busy.example.org", times=60)
        assert analyse(analyzer, "very-busy.example.org").confidence <= 0.85


class TestSignalConversion:
    def test_anomaly_factor_reports_what_was_observed(self, analyzer, repository):
        seed(repository, "beacon2.example.org", times=25)
        signal = behavioral_to_signal(
            analyse(analyzer, "beacon2.example.org"), get_risk_config()
        )
        factor = signal.factors[0]
        assert factor.code == "BEHAVIORAL_ANOMALY"
        assert "queries across" in factor.detail
        assert factor.raw_points > 0

    def test_score_is_bounded(self, analyzer, repository):
        for index in range(12):
            seed(
                repository,
                "n{}.everything-wrong.com".format(index),
                times=3,
                response_code="NXDOMAIN",
                blocked=True,
            )
        result = analyse(analyzer, "everything-wrong.com")
        assert 0.0 <= result.score <= 100.0


class TestHonestLabelling:
    def test_declared_as_heuristic(self, analyzer):
        assert analyzer.info()["model_type"] == "PROTOTYPE_HEURISTIC"

    def test_no_accuracy_claimed(self, analyzer):
        assert analyzer.info()["accuracy_claimed"] is None
