"""Event persistence and dashboard aggregation tests.

Runs against a temporary database so the real event log is never touched.
"""

import pytest

from backend.app.core.pipeline import get_pipeline
from backend.app.storage.events import EventRepository


@pytest.fixture
def repository(tmp_path):
    return EventRepository(path=tmp_path / "events.db")


@pytest.fixture
def seeded(repository):
    pipeline = get_pipeline()
    for domain in [
        "github.com", "wikipedia.org",              # safe
        "malware-c2-panel.test", "kq3v9z7jx1p8w.info",  # blocked
        "paypa1.com",                                # monitored
    ]:
        repository.log(pipeline.analyse(domain), source="test")
    return repository


class TestPersistence:
    def test_log_returns_an_id(self, repository):
        event_id = repository.log(get_pipeline().analyse("github.com"))
        assert event_id > 0

    def test_stored_event_round_trips(self, repository):
        event_id = repository.log(get_pipeline().analyse("malware-c2-panel.test"))
        event = repository.get_event(event_id)
        assert event["domain"] == "malware-c2-panel.test"
        assert event["decision"] == "BLOCK"
        assert event["threat_intelligence_verdict"] == "MALICIOUS"
        assert event["top_factors"]

    def test_schema_is_created_on_first_use(self, tmp_path):
        database = tmp_path / "nested" / "fresh.db"
        repository = EventRepository(path=database)
        assert repository.stats()["total_analyzed"] == 0
        assert database.exists()

    def test_clear_removes_everything(self, seeded):
        assert seeded.stats()["total_analyzed"] == 5
        removed = seeded.clear()
        assert removed == 5
        assert seeded.stats()["total_analyzed"] == 0


class TestListing:
    def test_newest_first(self, seeded):
        events = seeded.list_events()["events"]
        assert events[0]["domain"] == "paypa1.com"

    def test_pagination(self, seeded):
        page = seeded.list_events(limit=2, offset=0)
        assert len(page["events"]) == 2
        assert page["total"] == 5

    def test_filter_by_classification(self, seeded):
        result = seeded.list_events(classification="MALICIOUS")
        assert result["total"] >= 2
        assert all(e["classification"] == "MALICIOUS" for e in result["events"])

    def test_filter_by_decision(self, seeded):
        result = seeded.list_events(decision="ALLOW")
        assert all(e["decision"] == "ALLOW" for e in result["events"])

    def test_search_by_domain_substring(self, seeded):
        result = seeded.list_events(query="malware")
        assert result["total"] == 1
        assert result["events"][0]["domain"] == "malware-c2-panel.test"

    def test_missing_event_returns_none(self, repository):
        assert repository.get_event(9999) is None


class TestAggregation:
    def test_totals_are_consistent(self, seeded):
        stats = seeded.stats()
        assert stats["total_analyzed"] == 5
        assert (stats["allowed"] + stats["monitored"] + stats["blocked"]
                == stats["total_analyzed"])

    def test_threats_detected_counts_non_safe(self, seeded):
        stats = seeded.stats()
        assert stats["threats_detected"] == (
            stats["by_classification"]["SUSPICIOUS"]
            + stats["by_classification"]["MALICIOUS"]
        )

    def test_risk_distribution_covers_every_event(self, seeded):
        stats = seeded.stats()
        assert sum(b["count"] for b in stats["risk_distribution"]) == 5
        assert len(stats["risk_distribution"]) == 10

    def test_threat_categories_exclude_allowlist_marker(self, seeded):
        assert "allowlisted" not in seeded.stats()["threat_categories"]

    def test_threat_categories_are_counted(self, seeded):
        categories = seeded.stats()["threat_categories"]
        assert categories.get("c2", 0) >= 1

    def test_top_risky_domains_only_lists_elevated_scores(self, seeded):
        for row in seeded.stats()["top_risky_domains"]:
            assert row["risk_score"] >= 30

    def test_performance_metrics_are_measured(self, seeded):
        performance = seeded.stats()["performance"]
        assert performance["mean_analysis_time_ms"] > 0
        assert performance["slowest_ms"] >= performance["fastest_ms"]

    def test_activity_buckets_by_hour(self, seeded):
        activity = seeded.stats()["activity"]
        assert activity
        assert sum(
            b["SAFE"] + b["SUSPICIOUS"] + b["MALICIOUS"] for b in activity
        ) == 5

    def test_empty_database_produces_zeroed_stats(self, repository):
        stats = repository.stats()
        assert stats["total_analyzed"] == 0
        assert stats["threats_detected"] == 0
        assert stats["performance"]["mean_analysis_time_ms"] == 0
        assert sum(b["count"] for b in stats["risk_distribution"]) == 0
