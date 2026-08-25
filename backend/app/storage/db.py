"""SQLite connection handling and schema.

Deliberately no ORM. One table and a handful of queries do not justify the
dependency, and raw SQL keeps what the dashboard shows obvious.

A connection is opened per operation. SQLite handles this efficiently, and it
sidesteps the thread-affinity problems of sharing one connection across
FastAPI's worker threads.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from ..config import get_settings

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
    source             TEXT    NOT NULL DEFAULT 'api'
);

CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts_utc DESC);
CREATE INDEX IF NOT EXISTS idx_events_class  ON events(classification);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(registrable_domain);
CREATE INDEX IF NOT EXISTS idx_events_score  ON events(risk_score);
"""

_initialised_paths = set()


def database_path() -> Path:
    return get_settings().database_path


@contextmanager
def connect(path: Optional[Path] = None):
    """Yield a configured connection, committing on clean exit."""
    target = Path(path) if path else database_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(target))
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


def init_db(path: Optional[Path] = None) -> None:
    """Create the schema if it does not exist. Safe to call repeatedly."""
    target = str(Path(path) if path else database_path())
    with connect(path) as connection:
        connection.executescript(SCHEMA)
    _initialised_paths.add(target)


def ensure_initialised(path: Optional[Path] = None) -> None:
    target = str(Path(path) if path else database_path())
    if target not in _initialised_paths:
        init_db(path)
