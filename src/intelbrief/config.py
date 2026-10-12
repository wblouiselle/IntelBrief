"""Settings and environment variables.

Everything configurable lives here so the rest of the code never reads os.environ directly.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from intelbrief import __version__

# src/intelbrief/config.py -> the project root is two folders above the package.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Sent in the User-Agent so feed operators can see who is calling and how to reach us.
CONTACT_URL = "https://github.com/wblouiselle/IntelBrief"
USER_AGENT = f"IntelBrief/{__version__} (+{CONTACT_URL})"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class Settings:
    """Runtime settings, built from environment variables (and .env) with safe defaults."""

    db_path: Path
    cache_dir: Path
    site_dir: Path
    user_agent: str
    http_timeout_seconds: float


def _resolve(path_str: str) -> Path:
    """Treat relative paths as relative to the project root, not the current folder."""
    path = Path(path_str)
    return path if path.is_absolute() else PROJECT_ROOT / path


def get_settings() -> Settings:
    """Load .env (if present) and return the current settings."""
    load_dotenv(PROJECT_ROOT / ".env")
    return Settings(
        db_path=_resolve(os.getenv("INTELBRIEF_DB_PATH", "data/intelbrief.db")),
        cache_dir=_resolve(os.getenv("INTELBRIEF_CACHE_DIR", "data/cache")),
        site_dir=_resolve(os.getenv("INTELBRIEF_SITE_DIR", "site")),
        user_agent=USER_AGENT,
        http_timeout_seconds=float(os.getenv("INTELBRIEF_HTTP_TIMEOUT", "30")),
    )
