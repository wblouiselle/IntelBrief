from pathlib import Path

import pytest

from intelbrief import config


def test_relative_db_path_resolves_to_project_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTELBRIEF_DB_PATH", "data/custom.db")
    assert config.get_settings().db_path == config.PROJECT_ROOT / "data" / "custom.db"


def test_absolute_db_path_is_kept(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INTELBRIEF_DB_PATH", str(tmp_path / "x.db"))
    assert config.get_settings().db_path == tmp_path / "x.db"


def test_user_agent_identifies_project() -> None:
    assert config.get_settings().user_agent.startswith("IntelBrief/")
