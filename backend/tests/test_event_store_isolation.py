"""The suite must never write into the real event log.

This is not hypothetical tidiness. The behavioural detector scores a domain by
what it has DONE, reading the same event store the API writes to. When the
suite leaked into ``data/platform.db`` it wrote 372 analyses across eight
names in under an hour - past the burst threshold of 20 - so a demo of those
names showed a +26 behavioural finding produced entirely by the test run that
had just finished. The detector was right; the history was ours.

The leak was a polite ``finally: set_event_repository(None)``. Resetting the
global to None does not disable the store, it re-arms the lazy constructor,
and ``EventRepository()`` with no path opens whatever database the settings
name. Every module that ran afterwards logged into the real one.

These tests pin the two defences: nothing in the suite resolves to the
production database, and dropping the global cannot reach it either.
"""

import pytest

from backend.app import config
from backend.app.storage import db
from backend.app.storage.events import (
    EventRepository, get_event_repository, set_event_repository,
)

PRODUCTION_DB = config.PROJECT_ROOT / "data" / "platform.db"


class TestTheSuiteIsPointedAwayFromRealData:
    def test_the_configured_database_is_not_the_production_one(self):
        assert db.database_path() != PRODUCTION_DB
        assert config.get_settings().database_path != PRODUCTION_DB

    def test_the_global_repository_is_not_the_production_one(self):
        assert get_event_repository().path != PRODUCTION_DB

    def test_a_lazily_constructed_repository_lands_somewhere_safe(self):
        """The exact failure mode: no explicit path, so it uses the settings.

        With only the global swapped this opened data/platform.db. The
        configured path is redirected too, so the fallback is harmless.
        """
        assert EventRepository().path is None
        assert db.database_path() != PRODUCTION_DB

    def test_dropping_the_global_does_not_reach_production(self):
        original = get_event_repository()
        try:
            set_event_repository(None)
            rebuilt = get_event_repository()
            assert rebuilt.path != PRODUCTION_DB
            # A write through the rebuilt handle must not touch real data.
            assert db.database_path() != PRODUCTION_DB
        finally:
            set_event_repository(original)

    def test_the_isolated_store_is_the_one_being_written(self, isolated_event_store):
        repository = get_event_repository()
        assert repository.path == isolated_event_store

    def test_production_event_count_is_untouched_by_a_pipeline_run(self):
        """Analyse something and prove the real log did not grow."""
        import sqlite3

        if not PRODUCTION_DB.exists():
            pytest.skip("no production database on this machine")

        def count():
            connection = sqlite3.connect(str(PRODUCTION_DB))
            try:
                return connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            except sqlite3.OperationalError:
                return 0
            finally:
                connection.close()

        from backend.app.core.pipeline import get_pipeline

        before = count()
        result = get_pipeline().analyse("isolation-probe.test")
        get_event_repository().log(result, source="isolation-test")
        assert count() == before, (
            "the suite wrote into the real event log; the behavioural "
            "detector will read this back during a demo")
