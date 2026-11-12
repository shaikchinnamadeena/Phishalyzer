
"""Tests for URL reputation analysis."""

from unittest.mock import MagicMock

import pytest

from phishalyzer.analyzers.url_reputation import (
    URLReputationAnalyzer,
)
from phishalyzer.integrations.virustotal import (
    VirusTotalResult,
)


@pytest.fixture
def virustotal():
    """Create a mocked VirusTotal analyzer."""

    return MagicMock()


@pytest.fixture
def analyzer(virustotal):
    """Create URL reputation analyzer."""

    return URLReputationAnalyzer(
        virustotal_analyzer=virustotal
    )


def mock_result(
    malicious=0,
    suspicious=0,
    harmless=0,
    undetected=0,
):
    """Create a simulated VirusTotal result."""

    return VirusTotalResult(
        resource="https://example.com",
        resource_type="url",
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        reputation=0,
        is_malicious=malicious > 0 or suspicious > 0,
        errors=(),
    )


def test_successful_malicious_analysis(analyzer, virustotal):
    virustotal.analyze_url.return_value = mock_result(
        malicious=5,
        suspicious=2,
        harmless=10,
        undetected=3,
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is True
    assert result.reputation == "malicious"
    assert result.source == "VirusTotal"
    assert result.url == "https://example.com"
    assert result.errors == ()


def test_successful_harmless_analysis(analyzer, virustotal):
    virustotal.analyze_url.return_value = mock_result(
        harmless=15,
        undetected=5,
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is False
    assert result.reputation == "harmless"
    assert result.source == "VirusTotal"


def test_suspicious_url_analysis(analyzer, virustotal):
    virustotal.analyze_url.return_value = mock_result(
        suspicious=3,
        harmless=5,
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is True
    assert result.reputation == "malicious"


def test_unknown_reputation(analyzer, virustotal):
    virustotal.analyze_url.return_value = mock_result(
        undetected=10,
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is None
    assert result.reputation == "unknown"


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
def test_invalid_url_input(analyzer, virustotal, url):
    with pytest.raises(ValueError):
        analyzer.analyze(url)

    virustotal.analyze_url.assert_not_called()


def test_url_normalization(analyzer, virustotal):
    virustotal.analyze_url.return_value = mock_result(
        harmless=10,
    )

    result = analyzer.analyze("  https://example.com  ")

    assert result.url == "https://example.com"
    virustotal.analyze_url.assert_called_once_with(
        "https://example.com"
    )


def test_missing_api_key(analyzer, virustotal):
    virustotal.analyze_url.side_effect = ValueError(
        "VirusTotal API key is not configured"
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is None
    assert result.reputation == "unknown"
    assert result.source == "VirusTotal"
    assert result.errors


def test_virus_total_timeout(analyzer, virustotal):
    virustotal.analyze_url.side_effect = RuntimeError(
        "VirusTotal request timed out"
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is None
    assert result.reputation == "unknown"
    assert result.errors


def test_virus_total_rate_limit(analyzer, virustotal):
    virustotal.analyze_url.side_effect = RuntimeError(
        "VirusTotal rate limit exceeded"
    )

    result = analyzer.analyze("https://example.com")

    assert result.is_malicious is None
    assert result.reputation == "unknown"
    assert "rate limit" in result.errors[0].lower()


def test_virus_total_api_failure(analyzer, virustotal):
    virustotal.analyze_url.side_effect = RuntimeError(
        "VirusTotal request failed"
    )

    result = analyzer.analyze("https://example.com")

    assert result.reputation == "unknown"
    assert result.is_malicious is None
    assert result.errors


def test_result_details_include_detection_counts(
    analyzer,
    virustotal,
):
    virustotal.analyze_url.return_value = mock_result(
        malicious=4,
        suspicious=2,
        harmless=8,
        undetected=6,
    )

    result = analyzer.analyze("https://example.com")

    assert "4" in result.details
    assert "2" in result.details
    assert "8" in result.details
    assert "6" in result.details
