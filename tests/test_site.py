"""Tests for the static website builder. They use a temporary database, never the network."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from intelbrief import db, site

TODAY = date(2026, 10, 12)
GENERATED_AT = datetime(2026, 10, 12, 11, 30, tzinfo=UTC)


def entry(cve_id: str, date_added: str, **overrides: object) -> db.KevEntry:
    fields = {
        "cve_id": cve_id,
        "vendor_project": "Acme",
        "product": "Gateway",
        "vulnerability_name": f"Acme Gateway flaw {cve_id}",
        "date_added": date_added,
        "short_description": "A test vulnerability.",
        "required_action": "Apply updates.",
        "due_date": "2026-11-01",
        "known_ransomware_use": False,
        "notes": None,
    }
    fields.update(overrides)
    return db.KevEntry(**fields)


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = db.connect(tmp_path / "test.db")
    db.init_db(connection)
    db.upsert_kev_entries(
        connection,
        [
            entry("CVE-2026-0001", "2026-10-10", known_ransomware_use=True),  # last 7 days
            entry("CVE-2026-0002", "2026-09-20"),  # last 30 days
            entry("CVE-2025-0003", "2025-01-15"),  # older
        ],
    )
    yield connection
    connection.close()


def build(conn: sqlite3.Connection, out_dir: Path) -> dict[str, str]:
    """Build the site and return the text of each HTML page by file name."""
    site.build_site(conn, out_dir, today=TODAY, generated_at=GENERATED_AT)
    return {p.name: p.read_text(encoding="utf-8") for p in out_dir.glob("*.html")}


def test_builds_all_pages_and_static_files(conn: sqlite3.Connection, tmp_path: Path) -> None:
    out_dir = tmp_path / "site"
    files = build(conn, out_dir)
    assert {p.name for p in out_dir.iterdir()} == {
        "index.html",
        "catalog.html",
        "about.html",
        "style.css",
        "filter.js",
        "author.jpg",
    }
    assert all("Updated 2026-10-12 11:30 UTC" in files[p] for p in ("index.html", "about.html"))


def test_author_photo_is_copied_byte_for_byte(conn: sqlite3.Connection, tmp_path: Path) -> None:
    build(conn, tmp_path / "site")
    original = Path(site.__file__).parent / "site_assets" / "author.jpg"
    assert (tmp_path / "site" / "author.jpg").read_bytes() == original.read_bytes()


def test_overview_lists_only_recent_entries(conn: sqlite3.Connection, tmp_path: Path) -> None:
    index = build(conn, tmp_path / "site")["index.html"]
    assert "CVE-2026-0001" in index
    assert "CVE-2026-0002" in index
    assert "CVE-2025-0003" not in index


def test_overview_statistics(conn: sqlite3.Connection, tmp_path: Path) -> None:
    index = build(conn, tmp_path / "site")["index.html"]
    assert '<span class="stat-value">3</span>in the catalog' in index
    assert '<span class="stat-value">1</span>added in the last 7 days' in index
    assert '<span class="stat-value">2</span>added in the last 30 days' in index
    assert '<span class="stat-value">1</span>linked to ransomware' in index


def test_catalog_lists_everything_with_links(conn: sqlite3.Connection, tmp_path: Path) -> None:
    catalog = build(conn, tmp_path / "site")["catalog.html"]
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2025-0003"):
        assert f"https://nvd.nist.gov/vuln/detail/{cve}" in catalog
    assert catalog.count('data-ransomware="1"') == 1


def test_feed_text_is_escaped(conn: sqlite3.Connection, tmp_path: Path) -> None:
    db.upsert_kev_entries(
        conn, [entry("CVE-2026-0666", "2026-10-11", vendor_project="<script>alert(1)</script>")]
    )
    index = build(conn, tmp_path / "site")["index.html"]
    assert "<script>alert(1)</script>" not in index
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in index


def test_missing_fields_show_fallback(conn: sqlite3.Connection, tmp_path: Path) -> None:
    db.upsert_kev_entries(conn, [entry("CVE-2026-0777", "2026-10-11", due_date=None)])
    index = build(conn, tmp_path / "site")["index.html"]
    assert "Not listed" in index


def test_empty_database_still_builds(tmp_path: Path) -> None:
    with closing(db.connect(tmp_path / "empty.db")) as empty:
        db.init_db(empty)
        files = build(empty, tmp_path / "site")
    assert "No vulnerabilities were added" in files["index.html"]


def test_rebuild_removes_stale_files(conn: sqlite3.Connection, tmp_path: Path) -> None:
    out_dir = tmp_path / "site"
    out_dir.mkdir()
    (out_dir / "old-page.html").write_text("stale", encoding="utf-8")
    assert "old-page.html" not in build(conn, out_dir)


def test_outside_links_open_in_new_tab_safely(conn: sqlite3.Connection, tmp_path: Path) -> None:
    catalog = build(conn, tmp_path / "site")["catalog.html"]
    nvd_link = 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" target="_blank"'
    assert nvd_link in catalog
    assert catalog.count('target="_blank"') == catalog.count('rel="noopener noreferrer"')


def test_catalog_rows_carry_dates_for_sorting(conn: sqlite3.Connection, tmp_path: Path) -> None:
    catalog = build(conn, tmp_path / "site")["catalog.html"]
    assert 'id="sort"' in catalog
    assert 'data-added="2026-10-10" data-due="2026-11-01"' in catalog


def test_about_page_credits_author(conn: sqlite3.Connection, tmp_path: Path) -> None:
    about = build(conn, tmp_path / "site")["about.html"]
    assert f"Created by {site.AUTHOR_NAME}" in about
    assert f"First published {site.SITE_LAUNCHED}" in about
    assert "James Madison University" in about


def test_about_page_has_contact_links(conn: sqlite3.Connection, tmp_path: Path) -> None:
    about = build(conn, tmp_path / "site")["about.html"]
    assert 'href="https://www.linkedin.com/in/will-louiselle/"' in about
    # Contact goes through LinkedIn only; no email or phone number on the public page.
    assert "mailto:" not in about
    assert "tel:" not in about
