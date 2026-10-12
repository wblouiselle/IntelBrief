from intelbrief.http import RETRY_STATUS_CODES, build_session


def test_session_sets_user_agent() -> None:
    session = build_session("IntelBrief/test")
    assert session.headers["User-Agent"] == "IntelBrief/test"


def test_session_retries_on_rate_limit_and_server_errors() -> None:
    retry = build_session("IntelBrief/test", total_retries=5).get_adapter("https://x").max_retries
    assert retry.total == 5
    assert set(RETRY_STATUS_CODES) <= set(retry.status_forcelist)
    assert retry.respect_retry_after_header
