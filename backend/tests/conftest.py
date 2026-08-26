"""Shared test fixtures.

Isolates the suite from the real event log. This became necessary when the
behavioural analyser was added: it reads query history from the event store, so
without this every test that runs the pipeline would silently depend on
whatever happens to be in ``data/platform.db``. A developer who had just run
the seed script could see different results from CI.

Swapping the global repository is not enough on its own. ``EventRepository()``
with no path falls back to the configured database, so any test that reset the
global to ``None`` - even politely, in a ``finally`` - made the next lazy
construction open the real one. The suite then wrote its own traffic into the
demo database for the rest of the session: 372 analyses across eight names,
enough to trip the behavioural burst threshold of 20 and put +26 on names that
should have scored nothing during a demo.

So the isolation is done twice, at both levels: the configured path is
redirected for the whole session, and the global repository is pointed at the
same file. A stray ``set_event_repository(None)`` now costs a fresh handle to
the temporary database instead of contaminating real data.
"""

import os

import pytest

from backend.app import config
from backend.app.storage import events as events_module
from backend.app.storage.events import EventRepository, set_event_repository


@pytest.fixture(scope="session", autouse=True)
def isolated_event_store(tmp_path_factory):
    """Point both the configured path and the global repository at a temp DB."""
    database = tmp_path_factory.mktemp("event-store") / "test-platform.db"

    previous_env = os.environ.get("DNSSEC_DB_PATH")
    os.environ["DNSSEC_DB_PATH"] = str(database)
    # Settings are cached in a module global; drop it so the new path is read.
    config._settings = None

    # Read the global directly rather than through get_event_repository(),
    # which would construct one as a side effect of asking.
    previous_repository = events_module._repository
    set_event_repository(EventRepository(path=database))
    try:
        yield database
    finally:
        set_event_repository(previous_repository)
        if previous_env is None:
            os.environ.pop("DNSSEC_DB_PATH", None)
        else:
            os.environ["DNSSEC_DB_PATH"] = previous_env
        config._settings = None
