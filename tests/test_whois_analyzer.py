
"""Tests for Phishalyzer WHOIS analyzer."""

from datetime import date, datetime, timedelta
from unittest.mock import patch

import pytest

from phishalyzer.analyzers.whois_analyzer import WhoisAnalyzer


def test_invalid_domain_input():
    analyzer = WhoisAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("")


def test_non_string_domain_input():
    analyzer = WhoisAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(None)


def test_invalid_domain_format():
    analyzer = WhoisAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("-invalid.com")


def test_successful_whois_analysis():
    analyzer = WhoisAnalyzer()

    today = date.today()

    mock_result = {
        "registrar": "Example Registrar",
        "creation_date": datetime.combine(
            today - timedelta(days=100),
            datetime.min.time()
        ),
        "expiration_date": datetime.combine(
            today + timedelta(days=265),
            datetime.min.time()
        )
    }

    with patch(
        "phishalyzer.analyzers.whois_analyzer.whois.whois",
        return_value=mock_result
    ):
        result = analyzer.analyze("example.com")

    assert result.domain == "example.com"
    assert result.registrar == "Example Registrar"
    assert result.domain_age_days == 100
    assert result.days_until_expiration == 265
    assert result.errors == ()


def test_whois_lookup_failure():
    analyzer = WhoisAnalyzer()

    with patch(
        "phishalyzer.analyzers.whois_analyzer.whois.whois",
        side_effect=Exception("Connection failed")
    ):
        result = analyzer.analyze("example.com")

    assert result.domain == "example.com"
    assert result.registrar is None
    assert result.creation_date is None
    assert result.expiration_date is None
    assert len(result.errors) == 1


def test_missing_whois_records():
    analyzer = WhoisAnalyzer()

    with patch(
        "phishalyzer.analyzers.whois_analyzer.whois.whois",
        return_value={}
    ):
        result = analyzer.analyze("example.com")

    assert result.registrar is None
    assert result.domain_age_days is None
    assert result.days_until_expiration is None
    assert len(result.errors) == 1


def test_domain_normalization():
    analyzer = WhoisAnalyzer()

    mock_result = {
        "registrar": "Example Registrar",
        "creation_date": None,
        "expiration_date": None
    }

    with patch(
        "phishalyzer.analyzers.whois_analyzer.whois.whois",
        return_value=mock_result
    ) as mock_lookup:

        result = analyzer.analyze(" EXAMPLE.COM. ")

    assert result.domain == "example.com"
    mock_lookup.assert_called_once_with("example.com")


def test_list_date_normalization():
    analyzer = WhoisAnalyzer()

    today = date.today()

    mock_result = {
        "registrar": ["Example Registrar"],
        "creation_date": [
            datetime.combine(
                today - timedelta(days=50),
                datetime.min.time()
            )
        ],
        "expiration_date": [
            datetime.combine(
                today + timedelta(days=300),
                datetime.min.time()
            )
        ]
    }

    with patch(
        "phishalyzer.analyzers.whois_analyzer.whois.whois",
        return_value=mock_result
    ):
        result = analyzer.analyze("example.com")

    assert result.registrar == "Example Registrar"
    assert result.domain_age_days == 50
    assert result.days_until_expiration == 300
