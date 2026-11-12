
"""Tests for VirusTotal integration."""

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from pydantic import SecretStr

from phishalyzer.integrations.virustotal import VirusTotalAnalyzer


@pytest.fixture
def analyzer(monkeypatch):
    """Create an analyzer with a mock API key."""

    settings = SimpleNamespace(
        virustotal_api_key=SecretStr("test-api-key"),
        request_timeout=10,
    )

    monkeypatch.setattr(
        "phishalyzer.integrations.virustotal.get_settings",
        lambda: settings,
    )

    return VirusTotalAnalyzer()


def mock_response(stats=None):
    """Create a simulated VirusTotal response."""

    response = MagicMock()
    response.status_code = 200

    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": stats or {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10,
                },
                "reputation": 5,
            }
        }
    }

    return response


def test_successful_domain_analysis(analyzer):
    response = mock_response()
    analyzer.session.get = MagicMock(return_value=response)

    result = analyzer.analyze_domain("example.com")

    assert result.resource == "example.com"
    assert result.resource_type == "domain"
    assert result.malicious == 2
    assert result.suspicious == 1
    assert result.is_malicious is True
    assert result.reputation == 5


def test_successful_url_analysis(analyzer):
    response = mock_response()
    analyzer.session.get = MagicMock(return_value=response)

    url = "https://example.com"

    result = analyzer.analyze_url(url)

    encoded_url = (
        base64.urlsafe_b64encode(url.encode())
        .decode()
        .rstrip("=")
    )

    analyzer.session.get.assert_called_once()

    assert analyzer.session.get.call_args.args[0].endswith(
        f"/urls/{encoded_url}"
    )

    assert result.resource == url
    assert result.resource_type == "url"


@pytest.mark.parametrize("domain", ["", "   ", None, 123])
def test_invalid_domain_input(analyzer, domain):
    with pytest.raises(ValueError):
        analyzer.analyze_domain(domain)


@pytest.mark.parametrize("url", ["", "   ", None, 123])
def test_invalid_url_input(analyzer, url):
    with pytest.raises(ValueError):
        analyzer.analyze_url(url)


def test_missing_api_key(analyzer):
    analyzer.api_key = None

    with pytest.raises(ValueError, match="API key"):
        analyzer.analyze_domain("example.com")


def test_virus_total_rate_limit(analyzer):
    response = MagicMock()
    response.status_code = 429

    analyzer.session.get = MagicMock(return_value=response)

    with pytest.raises(RuntimeError, match="rate limit"):
        analyzer.analyze_domain("example.com")


def test_request_timeout(analyzer):
    analyzer.session.get = MagicMock(
        side_effect=requests.Timeout
    )

    with pytest.raises(RuntimeError, match="timed out"):
        analyzer.analyze_domain("example.com")


def test_no_malicious_detections(analyzer):
    response = mock_response({
        "malicious": 0,
        "suspicious": 0,
        "harmless": 70,
        "undetected": 5,
    })

    analyzer.session.get = MagicMock(return_value=response)

    result = analyzer.analyze_domain("example.com")

    assert result.is_malicious is False
    assert result.malicious == 0
    assert result.suspicious == 0


def test_http_error(analyzer):
    response = MagicMock()
    response.status_code = 404
    response.raise_for_status.side_effect = (
        requests.HTTPError("Not found")
    )

    analyzer.session.get = MagicMock(return_value=response)

    with pytest.raises(RuntimeError, match="request failed"):
        analyzer.analyze_domain("example.com")


def test_close_session(analyzer):
    analyzer.session.close = MagicMock()

    analyzer.close()

    analyzer.session.close.assert_called_once()
