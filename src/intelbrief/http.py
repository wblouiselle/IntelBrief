"""Shared HTTP session with a descriptive User-Agent and automatic retries."""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Status codes worth retrying: rate limited (429) or a temporary server-side problem (5xx).
RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


def build_session(
    user_agent: str, total_retries: int = 3, backoff_factor: float = 1.0
) -> requests.Session:
    """Return a requests Session that retries failed GETs with exponential backoff.

    With backoff_factor=1.0 the waits between attempts grow roughly 1s, 2s, 4s.
    If the server sends a Retry-After header (common with 429), that wait is used instead.
    """
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session
