"""SQLite schema creation and database helpers."""

import logging
import sqlite3
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id               TEXT PRIMARY KEY,
    vendor_project       TEXT,
    product              TEXT,
    vulnerability_name   TEXT,
    date_added           TEXT,
    short_description    TEXT,
    required_action      TEXT,
    due_date             TEXT,
    known_ransomware_use INTEGER NOT NULL DEFAULT 0,
    notes                TEXT,
    first_seen_at        TEXT NOT NULL,
    last_updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    source            TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    status            TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
    records_processed INTEGER,
    error             TEXT
);
"""

# ON CONFLICT turns a duplicate insert into an update, so re-running ingest is safe.
# first_seen_at is left out of the UPDATE on purpose so it keeps its original value.
UPSERT_KEV_SQL = """
INSERT INTO kev_entries (
    cve_id, vendor_project, product, vulnerability_name, date_added,
    short_description, required_action, due_date, known_ransomware_use, notes,
    first_seen_at, last_updated_at
) VALUES (
    :cve_id, :vendor_project, :product, :vulnerability_name, :date_added,
    :short_description, :required_action, :due_date, :known_ransomware_use, :notes,
    :now, :now
)
ON CONFLICT (cve_id) DO UPDATE SET
    vendor_project       = excluded.vendor_project,
    product              = excluded.product,
    vulnerability_name   = excluded.vulnerability_name,
    date_added           = excluded.date_added,
    short_description    = excluded.short_description,
    required_action      = excluded.required_action,
    due_date             = excluded.due_date,
    known_ransomware_use = excluded.known_ransomware_use,
    notes                = excluded.notes,
    last_updated_at      = excluded.last_updated_at
"""


@dataclass(frozen=True)
class KevEntry:
    """One row of the CISA KEV catalog, cleaned up for storage."""

    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str | None
    short_description: str | None
    required_action: str | None
    due_date: str | None
    known_ransomware_use: bool
    notes: str | None


def _now() -> str:
    """Current UTC time as an ISO 8601 string (SQLite has no native datetime type)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database, creating its folder if needed. Rows can be read by column name."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they don't exist. Safe to call on every run."""
    conn.executescript(SCHEMA)
    conn.commit()


def upsert_kev_entries(conn: sqlite3.Connection, entries: Iterable[KevEntry]) -> int:
    """Insert new KEV entries or update existing ones. Returns the number of rows written."""
    now = _now()
    rows = [
        {**asdict(e), "known_ransomware_use": int(e.known_ransomware_use), "now": now}
        for e in entries
    ]
    conn.executemany(UPSERT_KEV_SQL, rows)
    conn.commit()
    logger.info("Upserted %d KEV entries", len(rows))
    return len(rows)


def start_ingest_run(conn: sqlite3.Connection, source: str) -> int:
    """Record that an ingest run has started. Returns the run id."""
    cur = conn.execute(
        "INSERT INTO ingest_runs (source, started_at, status) VALUES (?, ?, 'running')",
        (source, _now()),
    )
    conn.commit()
    return cur.lastrowid


def finish_ingest_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    success: bool,
    records_processed: int | None = None,
    error: str | None = None,
) -> None:
    """Mark an ingest run as finished, successfully or not."""
    conn.execute(
        """
        UPDATE ingest_runs
        SET finished_at = ?, status = ?, records_processed = ?, error = ?
        WHERE id = ?
        """,
        (_now(), "success" if success else "failed", records_processed, error, run_id),
    )
    conn.commit()
