"""CISA Known Exploited Vulnerabilities (KEV) catalog: fetch, parse, and store.

The three steps are separate functions so each can be tested on its own:
fetch_kev talks to the network (or the cache), parse_kev is pure data cleanup,
and ingest_kev wires them together with the database.
"""

import json
import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

import requests

from intelbrief import db

logger = logging.getLogger(__name__)

SOURCE_NAME = "cisa_kev"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# KEV is updated a few times a week, so a 6-hour-old copy is fresh enough during development.
DEFAULT_MAX_CACHE_AGE_SECONDS = 6 * 60 * 60


def fetch_kev(
    session: requests.Session,
    url: str,
    cache_path: Path,
    timeout: float,
    max_cache_age_seconds: float = DEFAULT_MAX_CACHE_AGE_SECONDS,
) -> dict[str, Any]:
    """Return the raw KEV JSON, from the local cache if it is fresh, otherwise downloaded."""
    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < max_cache_age_seconds:
            logger.info("Using cached KEV catalog (%.0f minutes old)", age / 60)
            return json.loads(cache_path.read_text(encoding="utf-8"))

    logger.info("Downloading KEV catalog from %s", url)
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data), encoding="utf-8")
    return data


def _clean(value: Any) -> str | None:
    """Strip whitespace from text fields and turn empty or missing values into None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_kev(raw: dict[str, Any]) -> list[db.KevEntry]:
    """Convert the raw KEV JSON into KevEntry objects, skipping records without a valid CVE ID."""
    entries: list[db.KevEntry] = []
    skipped = 0
    for item in raw.get("vulnerabilities", []):
        cve_id = (_clean(item.get("cveID")) or "").upper()
        if not CVE_ID_PATTERN.match(cve_id):
            skipped += 1
            logger.warning("Skipping KEV record with invalid CVE ID: %r", item.get("cveID"))
            continue

        ransomware = (_clean(item.get("knownRansomwareCampaignUse")) or "").lower()
        entries.append(
            db.KevEntry(
                cve_id=cve_id,
                vendor_project=_clean(item.get("vendorProject")),
                product=_clean(item.get("product")),
                vulnerability_name=_clean(item.get("vulnerabilityName")),
                date_added=_clean(item.get("dateAdded")),
                short_description=_clean(item.get("shortDescription")),
                required_action=_clean(item.get("requiredAction")),
                due_date=_clean(item.get("dueDate")),
                known_ransomware_use=ransomware == "known",
                notes=_clean(item.get("notes")),
            )
        )

    logger.info("Parsed %d KEV entries (%d skipped)", len(entries), skipped)
    return entries


def ingest_kev(
    conn: sqlite3.Connection,
    session: requests.Session,
    url: str,
    cache_path: Path,
    timeout: float,
) -> int:
    """Fetch, parse, and store the KEV catalog, logging the run. Returns rows written."""
    run_id = db.start_ingest_run(conn, SOURCE_NAME)
    try:
        raw = fetch_kev(session, url, cache_path, timeout)
        entries = parse_kev(raw)
        written = db.upsert_kev_entries(conn, entries)
    except Exception as exc:
        db.finish_ingest_run(conn, run_id, success=False, error=str(exc))
        raise
    db.finish_ingest_run(conn, run_id, success=True, records_processed=written)
    return written
