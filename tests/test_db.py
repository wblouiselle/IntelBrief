import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from intelbrief import db


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = db.connect(tmp_path / "test.db")
    db.init_db(connection)
    yield connection
    connection.close()


def make_entry(cve_id: str = "CVE-2024-0001", **overrides: object) -> db.KevEntry:
    fields: dict[str, object] = {
        "cve_id": cve_id,
        "vendor_project": "Acme",
        "product": "Widget",
        "vulnerability_name": "Acme Widget RCE",
        "date_added": "2024-01-01",
        "short_description": "Remote code execution.",
        "required_action": "Apply updates.",
        "due_date": "2024-01-22",
        "known_ransomware_use": False,
        "notes": None,
    }
    fields.update(overrides)
    return db.KevEntry(**fields)


def test_init_db_is_idempotent(conn: sqlite3.Connection) -> None:
    db.init_db(conn)  # a second call must not fail or wipe anything
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"kev_entries", "ingest_runs"} <= tables


def test_upsert_inserts_new_entries(conn: sqlite3.Connection) -> None:
    written = db.upsert_kev_entries(conn, [make_entry("CVE-1"), make_entry("CVE-2")])
    assert written == 2
    assert conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0] == 2


def test_upsert_twice_updates_without_duplicating(conn: sqlite3.Connection) -> None:
    db.upsert_kev_entries(conn, [make_entry(known_ransomware_use=False)])
    first_seen = conn.execute("SELECT first_seen_at FROM kev_entries").fetchone()[0]

    db.upsert_kev_entries(conn, [make_entry(known_ransomware_use=True)])

    rows = conn.execute("SELECT * FROM kev_entries").fetchall()
    assert len(rows) == 1
    assert rows[0]["known_ransomware_use"] == 1
    assert rows[0]["first_seen_at"] == first_seen


def test_ingest_run_lifecycle(conn: sqlite3.Connection) -> None:
    run_id = db.start_ingest_run(conn, "cisa_kev")
    assert conn.execute("SELECT status FROM ingest_runs").fetchone()[0] == "running"

    db.finish_ingest_run(conn, run_id, success=True, records_processed=5)

    row = conn.execute("SELECT * FROM ingest_runs WHERE id = ?", (run_id,)).fetchone()
    assert row["status"] == "success"
    assert row["records_processed"] == 5
    assert row["finished_at"] is not None


def test_failed_ingest_run_records_error(conn: sqlite3.Connection) -> None:
    run_id = db.start_ingest_run(conn, "cisa_kev")
    db.finish_ingest_run(conn, run_id, success=False, error="timeout")

    row = conn.execute("SELECT status, error FROM ingest_runs").fetchone()
    assert (row["status"], row["error"]) == ("failed", "timeout")
