"""SQLite connection handling and schema.

Deliberately no ORM. One table and a handful of queries do not justify the
dependency, and raw SQL keeps what the dashboard shows obvious.

A connection is opened per operation. SQLite handles this efficiently, and it
sidesteps the thread-affinity problems of sharing one connection across
FastAPI's worker threads.
"""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from ..config import get_settings

logger = logging.getLogger("dnssec.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc             TEXT    NOT NULL,
    domain             TEXT    NOT NULL,
    registrable_domain TEXT    NOT NULL,
    risk_score         INTEGER NOT NULL,
    classification     TEXT    NOT NULL,
    decision           TEXT    NOT NULL,
    confidence         REAL    NOT NULL DEFAULT 0,
    ti_verdict         TEXT    NOT NULL,
    ti_categories      TEXT    NOT NULL DEFAULT '[]',
    ti_indicator       TEXT,
    dga_score          REAL    NOT NULL DEFAULT 0,
    lexical_score      REAL    NOT NULL DEFAULT 0,
    analysis_time_ms   REAL    NOT NULL DEFAULT 0,
    top_factors        TEXT    NOT NULL DEFAULT '[]',
    overrides_applied  TEXT    NOT NULL DEFAULT '[]',
    features           TEXT    NOT NULL DEFAULT '{}',
    source             TEXT    NOT NULL DEFAULT 'api',

    -- phase 2: DNS gateway columns. NULL on plain analysis events.
    event_type            TEXT    NOT NULL DEFAULT 'analysis',
    query_type            TEXT,
    query_class           TEXT,
    client_address        TEXT,
    blocked               INTEGER NOT NULL DEFAULT 0,
    upstream_used         INTEGER NOT NULL DEFAULT 0,
    cache_hit             INTEGER NOT NULL DEFAULT 0,
    response_code         TEXT,
    block_policy          TEXT,
    dns_upstream_time_ms  REAL,
    total_gateway_time_ms REAL
);

"""

# Indexes are applied AFTER the migration, not as part of SCHEMA. On an existing
# database the table is not recreated, so an index over a newly added column
# would be built before that column exists.
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts_utc DESC);
CREATE INDEX IF NOT EXISTS idx_events_class  ON events(classification);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(registrable_domain);
CREATE INDEX IF NOT EXISTS idx_events_score  ON events(risk_score);
CREATE INDEX IF NOT EXISTS idx_events_type   ON events(event_type);
"""

# Columns added after the first release. ``CREATE TABLE IF NOT EXISTS`` will not
# touch a table that already exists, so an existing database would silently keep
# the old shape and every DNS insert would fail with "no such column". These are
# applied additively at startup instead, preserving stored events.
ADDED_COLUMNS = [
    ("event_type", "TEXT NOT NULL DEFAULT 'analysis'"),
    ("query_type", "TEXT"),
    ("query_class", "TEXT"),
    ("client_address", "TEXT"),
    ("blocked", "INTEGER NOT NULL DEFAULT 0"),
    ("upstream_used", "INTEGER NOT NULL DEFAULT 0"),
    ("cache_hit", "INTEGER NOT NULL DEFAULT 0"),
    ("response_code", "TEXT"),
    ("block_policy", "TEXT"),
    ("dns_upstream_time_ms", "REAL"),
    ("total_gateway_time_ms", "REAL"),
]

_initialised_paths = set()


def database_path() -> Path:
    return get_settings().database_path


@contextmanager
def connect(path: Optional[Path] = None):
    """Yield a configured connection, committing on clean exit."""
    target = Path(path) if path else database_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    # An explicit busy timeout matters now that the DNS gateway and the HTTP
    # API can write concurrently; the 5s default is left to chance otherwise.
    connection = sqlite3.connect(str(target), timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        # WAL keeps reads from blocking the write of a concurrent analysis.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def migrate(connection) -> list:
    """Add any missing columns to an existing events table.

    Additive only - no column is ever dropped, renamed or retyped, so an
    existing event log survives the upgrade intact. Returns the columns added.
    """
    existing = {
        row["name"] for row in connection.execute("PRAGMA table_info(events)")
    }
    if not existing:
        return []

    added = []
    for name, definition in ADDED_COLUMNS:
        if name not in existing:
            connection.execute(
                "ALTER TABLE events ADD COLUMN {} {}".format(name, definition)
            )
            added.append(name)
    return added


def init_db(path: Optional[Path] = None) -> None:
    """Create the schema if it does not exist, then migrate it.

    Safe to call repeatedly.
    """
    target = str(Path(path) if path else database_path())
    with connect(path) as connection:
        connection.executescript(SCHEMA)   # table (new databases only)
        added = migrate(connection)        # columns (existing databases)
        connection.executescript(INDEXES)  # indexes, once columns are present
    if added:
        logger.info("Migrated events table, added columns: %s", ", ".join(added))
    _initialised_paths.add(target)


def ensure_initialised(path: Optional[Path] = None) -> None:
    target = str(Path(path) if path else database_path())
    if target not in _initialised_paths:
        init_db(path)
