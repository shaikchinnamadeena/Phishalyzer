
"""Tests for URLScan.io integration."""

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from pydantic import SecretStr

from phishalyzer.integrations.urlscan import URLScanAnalyzer


@pytest.fixture
def analyzer(monkeypatch):
    """Create URLScan analyzer with mocked configuration."""

    settings = SimpleNamespace(
        urlscan_api_key=SecretStr("test-urlscan-key"),
        request_timeout=10,
    )

    monkeypatch.setattr(
        "phishalyzer.integrations.urlscan.get_settings",
        lambda: settings,
    )

    session = MagicMock()

    return URLScanAnalyzer(session=session), session


def mock_response(data, status_code=200):
    """Create a simulated API response."""

    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = data

    return response


def valid_scan_result():
    """Return a simulated URLScan result."""

    return {
        "task": {
            "url": "https://example.com",
        },
        "page": {
            "url": "https://example.com",
            "domain": "example.com",
            "ip": "93.184.216.34",
            "title": "Example Domain",
            "status": "200",
            "redirected": False,
        },
        "lists": {
            "ips": ["93.184.216.34"],
            "domains": ["example.com"],
        },
        "verdicts": {
            "urlscan": {
                "score": 0,
                "categories": ["benign"],
            }
        },
    }


def test_successful_url_submission(analyzer):
    client, session = analyzer
    scan_id = str(uuid.uuid4())

    session.post.return_value = mock_response({
        "uuid": scan_id,
        "visibility": "private",
    })

    result = client.submit_url("https://example.com")

    assert result.scan_id == scan_id
    assert result.url == "https://example.com"
    assert result.visibility == "private"
    assert result.result_url.endswith(f"/{scan_id}/")

    payload = session.post.call_args.kwargs["json"]

    assert payload["url"] == "https://example.com"
    assert payload["visibility"] == "private"


def test_successful_result_retrieval(analyzer):
    client, session = analyzer
    scan_id = str(uuid.uuid4())

    session.get.return_value = mock_response(
        valid_scan_result()
    )

    result = client.get_result(scan_id)

    assert result.scan_id == scan_id
    assert result.page_domain == "example.com"
    assert result.page_ip == "93.184.216.34"
    assert result.page_title == "Example Domain"
    assert result.redirected is False
    assert result.ips == ("93.184.216.34",)
    assert result.domains == ("example.com",)
    assert result.verdict_score == 0
    assert result.categories == ("benign",)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        None,
        123,
        "ftp://example.com",
        "javascript:alert(1)",
        "//example.com",
        "https://",
        "https://user:password@example.com",
        "https://example.com:99999",
        "https://example.com/path with spaces",
    ],
)
def test_invalid_url_input(analyzer, url):
    client, session = analyzer

    with pytest.raises(ValueError):
        client.submit_url(url)

    session.post.assert_not_called()


def test_invalid_visibility(analyzer):
    client, session = analyzer

    with pytest.raises(ValueError):
        client.submit_url(
            "https://example.com",
            visibility="invalid",
        )

    session.post.assert_not_called()


@pytest.mark.parametrize(
    "scan_id",
    ["", "invalid-uuid", None, 123],
)
def test_invalid_scan_id(analyzer, scan_id):
    client, session = analyzer

    with pytest.raises(ValueError):
        client.get_result(scan_id)

    session.get.assert_not_called()


def test_missing_api_key(analyzer):
    client, session = analyzer

    client.api_key = None

    with pytest.raises(ValueError, match="API key"):
        client.submit_url("https://example.com")

    session.post.assert_not_called()


def test_rate_limit_on_submission(analyzer):
    client, session = analyzer

    session.post.return_value = mock_response(
        {},
        status_code=429,
    )

    with pytest.raises(RuntimeError, match="rate limit"):
        client.submit_url("https://example.com")


def test_rate_limit_on_result(analyzer):
    client, session = analyzer

    session.get.return_value = mock_response(
        {},
        status_code=429,
    )

    with pytest.raises(RuntimeError, match="rate limit"):
        client.get_result(str(uuid.uuid4()))


@pytest.mark.parametrize("status_code", [401, 403])
def test_authentication_failure(analyzer, status_code):
    client, session = analyzer

    session.post.return_value = mock_response(
        {},
        status_code=status_code,
    )

    with pytest.raises(RuntimeError, match="authentication"):
        client.submit_url("https://example.com")


def test_scan_result_not_ready(analyzer):
    client, session = analyzer

    session.get.return_value = mock_response(
        {},
        status_code=404,
    )

    with pytest.raises(RuntimeError, match="not ready"):
        client.get_result(str(uuid.uuid4()))


def test_deleted_scan_result(analyzer):
    client, session = analyzer

    session.get.return_value = mock_response(
        {},
        status_code=410,
    )

    with pytest.raises(RuntimeError, match="deleted"):
        client.get_result(str(uuid.uuid4()))


def test_submission_timeout(analyzer):
    client, session = analyzer

    session.post.side_effect = requests.Timeout

    with pytest.raises(RuntimeError, match="timed out"):
        client.submit_url("https://example.com")


def test_result_timeout(analyzer):
    client, session = analyzer

    session.get.side_effect = requests.Timeout

    with pytest.raises(RuntimeError, match="timed out"):
        client.get_result(str(uuid.uuid4()))


def test_http_error(analyzer):
    client, session = analyzer

    response = mock_response({}, status_code=500)
    response.raise_for_status.side_effect = requests.HTTPError(
        "Server error"
    )

    session.post.return_value = response

    with pytest.raises(RuntimeError, match="request failed"):
        client.submit_url("https://example.com")


def test_invalid_json_response(analyzer):
    client, session = analyzer

    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("Invalid JSON")

    session.post.return_value = response

    with pytest.raises(RuntimeError, match="invalid JSON"):
        client.submit_url("https://example.com")


def test_missing_scan_uuid(analyzer):
    client, session = analyzer

    session.post.return_value = mock_response({
        "visibility": "private",
    })

    with pytest.raises(RuntimeError, match="missing scan UUID"):
        client.submit_url("https://example.com")


def test_malformed_result_structure(analyzer):
    client, session = analyzer

    session.get.return_value = mock_response({
        "task": [],
        "page": {},
        "lists": {},
        "verdicts": {},
    })

    with pytest.raises(RuntimeError, match="structure"):
        client.get_result(str(uuid.uuid4()))


def test_optional_result_fields(analyzer):
    client, session = analyzer

    session.get.return_value = mock_response({
        "task": {},
        "page": {},
        "lists": {},
        "verdicts": {},
    })

    result = client.get_result(str(uuid.uuid4()))

    assert result.page_domain is None
    assert result.page_ip is None
    assert result.page_title is None
    assert result.ips == ()
    assert result.domains == ()
    assert result.categories == ()
    assert result.verdict_score is None


def test_private_visibility_is_default(analyzer):
    client, session = analyzer

    session.post.return_value = mock_response({
        "uuid": str(uuid.uuid4()),
    })

    client.submit_url("https://example.com")

    payload = session.post.call_args.kwargs["json"]

    assert payload["visibility"] == "private"


def test_close_session(analyzer):
    client, session = analyzer

    client.close()

    session.close.assert_called_once()
