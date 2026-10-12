"""Tests for CISA KEV ingestion. They use a saved sample file and never touch the network."""

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import requests

from intelbrief import db
from intelbrief.ingest import cisa_kev

FIXTURE = Path(__file__).parent / "fixtures" / "cisa_kev_sample.json"
URL = "https://example.test/kev.json"


@pytest.fixture
def raw() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = db.connect(tmp_path / "test.db")
    db.init_db(connection)
    yield connection
    connection.close()


class FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self) -> dict[str, Any]:
        return self._payload


class FakeSession:
    """Stands in for requests.Session and records how many requests were made."""

    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code
        self.calls = 0

    def get(self, url: str, timeout: float) -> FakeResponse:
        self.calls += 1
        return FakeResponse(self.payload, self.status_code)


# --- parse_kev -------------------------------------------------------------


def test_parse_skips_invalid_cve_ids(raw: dict[str, Any]) -> None:
    entries = cisa_kev.parse_kev(raw)
    assert [e.cve_id for e in entries] == ["CVE-2023-4966", "CVE-2021-44228", "CVE-2022-0001"]


def test_parse_normalizes_messy_values(raw: dict[str, Any]) -> None:
    by_id = {e.cve_id: e for e in cisa_kev.parse_kev(raw)}

    log4j = by_id["CVE-2021-44228"]  # lowercase, padded ID in the source
    assert log4j.known_ransomware_use is True
    assert log4j.notes is None  # empty string becomes None

    sparse = by_id["CVE-2022-0001"]
    assert sparse.vendor_project == "Example Vendor"
    assert sparse.due_date is None
    assert sparse.short_description is None
    assert sparse.known_ransomware_use is False


def test_parse_handles_missing_vulnerabilities_key() -> None:
    assert cisa_kev.parse_kev({}) == []


# --- fetch_kev -------------------------------------------------------------


def test_fetch_downloads_and_writes_cache(raw: dict[str, Any], tmp_path: Path) -> None:
    cache = tmp_path / "cache" / "kev.json"
    session = FakeSession(raw)

    result = cisa_kev.fetch_kev(session, URL, cache, timeout=5)

    assert result == raw
    assert session.calls == 1
    assert json.loads(cache.read_text(encoding="utf-8")) == raw


def test_fetch_uses_fresh_cache(raw: dict[str, Any], tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(raw), encoding="utf-8")
    session = FakeSession({"vulnerabilities": []})

    result = cisa_kev.fetch_kev(session, URL, cache, timeout=5)

    assert result == raw
    assert session.calls == 0


def test_fetch_redownloads_stale_cache(raw: dict[str, Any], tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    old = time.time() - cisa_kev.DEFAULT_MAX_CACHE_AGE_SECONDS - 60
    os.utime(cache, (old, old))
    session = FakeSession(raw)

    result = cisa_kev.fetch_kev(session, URL, cache, timeout=5)

    assert result == raw
    assert session.calls == 1


# --- ingest_kev ------------------------------------------------------------


def test_ingest_stores_entries_and_logs_run(
    raw: dict[str, Any], conn: sqlite3.Connection, tmp_path: Path
) -> None:
    written = cisa_kev.ingest_kev(conn, FakeSession(raw), URL, tmp_path / "kev.json", timeout=5)

    assert written == 3
    assert conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0] == 3
    run = conn.execute("SELECT * FROM ingest_runs").fetchone()
    assert (run["source"], run["status"], run["records_processed"]) == ("cisa_kev", "success", 3)


def test_ingest_twice_does_not_duplicate(
    raw: dict[str, Any], conn: sqlite3.Connection, tmp_path: Path
) -> None:
    for _ in range(2):
        cisa_kev.ingest_kev(conn, FakeSession(raw), URL, tmp_path / "kev.json", timeout=5)

    assert conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM ingest_runs").fetchone()[0] == 2


def test_ingest_failure_is_recorded(conn: sqlite3.Connection, tmp_path: Path) -> None:
    session = FakeSession({}, status_code=503)

    with pytest.raises(requests.HTTPError):
        cisa_kev.ingest_kev(conn, session, URL, tmp_path / "kev.json", timeout=5)

    run = conn.execute("SELECT status, error FROM ingest_runs").fetchone()
    assert run["status"] == "failed"
    assert "503" in run["error"]
