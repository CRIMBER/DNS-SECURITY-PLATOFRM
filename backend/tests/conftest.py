"""Shared test fixtures.

Isolates the suite from the real event log. This became necessary when the
behavioural analyser was added: it reads query history from the event store, so
without this every test that runs the pipeline would silently depend on
whatever happens to be in ``data/platform.db``. A developer who had just run
the seed script could see different results from CI.

The swap is autouse and session-scoped, so no individual test has to remember.
"""

import pytest

from backend.app.storage.events import EventRepository, set_event_repository


@pytest.fixture(scope="session", autouse=True)
def isolated_event_store(tmp_path_factory):
    """Point the global event repository at a temporary database."""
    database = tmp_path_factory.mktemp("event-store") / "test-platform.db"
    set_event_repository(EventRepository(path=database))
    yield database
    set_event_repository(None)
