"""Tests for the command-line interface. Feeds are replaced with the saved sample file."""

import json
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from intelbrief import db
from intelbrief.cli import app
from intelbrief.ingest import cisa_kev

FIXTURE = Path(__file__).parent / "fixtures" / "cisa_kev_sample.json"

runner = CliRunner()


@pytest.fixture
def tmp_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the database and cache at a temp folder. Returns the database path."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("INTELBRIEF_DB_PATH", str(db_path))
    monkeypatch.setenv("INTELBRIEF_CACHE_DIR", str(tmp_path / "cache"))
    return db_path


def fake_fetch(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_ingest_stores_entries_and_logs_success(
    monkeypatch: pytest.MonkeyPatch, tmp_settings: Path
) -> None:
    monkeypatch.setattr(cisa_kev, "fetch_kev", fake_fetch)
    expected = len(cisa_kev.parse_kev(fake_fetch()))

    result = runner.invoke(app, ["ingest"])

    assert result.exit_code == 0, result.output
    assert f"{expected} entries" in result.output
    with closing(db.connect(tmp_settings)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0] == expected
        assert conn.execute("SELECT status FROM ingest_runs").fetchone()[0] == "success"


def test_ingest_failure_exits_nonzero_and_logs_failed_run(
    monkeypatch: pytest.MonkeyPatch, tmp_settings: Path
) -> None:
    def broken_fetch(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise ConnectionError("feed unreachable")

    monkeypatch.setattr(cisa_kev, "fetch_kev", broken_fetch)

    result = runner.invoke(app, ["ingest"])

    assert result.exit_code == 1
    assert "feed unreachable" in result.output
    with closing(db.connect(tmp_settings)) as conn:
        assert conn.execute("SELECT status FROM ingest_runs").fetchone()[0] == "failed"


def test_site_builds_after_ingest(
    monkeypatch: pytest.MonkeyPatch, tmp_settings: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("INTELBRIEF_SITE_DIR", str(tmp_path / "site"))
    monkeypatch.setattr(cisa_kev, "fetch_kev", fake_fetch)
    runner.invoke(app, ["ingest"])

    result = runner.invoke(app, ["site"])

    assert result.exit_code == 0, result.output
    assert "CVE-2023-4966" in (tmp_path / "site" / "catalog.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("command", ["score", "brief"])
def test_unimplemented_commands_exit_nonzero(command: str) -> None:
    result = runner.invoke(app, [command])
    assert result.exit_code == 1
    assert "not implemented yet" in result.output
