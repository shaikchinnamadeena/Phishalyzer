
"""Tests for Phishalyzer domain analyzer."""

import socket
from unittest.mock import patch

import pytest

from phishalyzer.analyzers.domain_analyzer import DomainAnalyzer


def test_invalid_domain_input():
    analyzer = DomainAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("")


def test_non_string_domain_input():
    analyzer = DomainAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(None)


def test_invalid_domain_format():
    analyzer = DomainAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("-invalid.com")


def test_successful_domain_analysis():
    analyzer = DomainAnalyzer()

    mock_results = [
        (None, None, None, None, ("93.184.216.34", 0))
    ]

    with patch(
        "phishalyzer.analyzers.domain_analyzer.socket.getaddrinfo",
        return_value=mock_results
    ):
        result = analyzer.analyze("example.com")

    assert result.domain == "example.com"
    assert result.is_valid is True
    assert result.ip_addresses == ("93.184.216.34",)
    assert result.has_dns_records is True
    assert result.is_ip_address is False
    assert result.errors == ()


def test_dns_lookup_failure():
    analyzer = DomainAnalyzer()

    with patch(
        "phishalyzer.analyzers.domain_analyzer.socket.getaddrinfo",
        side_effect=socket.gaierror("DNS lookup failed")
    ):
        result = analyzer.analyze("example.com")

    assert result.is_valid is True
    assert result.ip_addresses == ()
    assert result.has_dns_records is False
    assert len(result.errors) == 1


def test_ip_address_detection():
    analyzer = DomainAnalyzer()

    result = analyzer.analyze("8.8.8.8")

    assert result.is_valid is True
    assert result.is_ip_address is True
    assert result.ip_addresses == ("8.8.8.8",)
    assert result.has_dns_records is False


def test_domain_normalization():
    analyzer = DomainAnalyzer()

    mock_results = [
        (None, None, None, None, ("93.184.216.34", 0))
    ]

    with patch(
        "phishalyzer.analyzers.domain_analyzer.socket.getaddrinfo",
        return_value=mock_results
    ):
        result = analyzer.analyze("  EXAMPLE.COM.  ")

    assert result.domain == "example.com"


def test_duplicate_ip_addresses_are_removed():
    analyzer = DomainAnalyzer()

    mock_results = [
        (None, None, None, None, ("93.184.216.34", 0)),
        (None, None, None, None, ("93.184.216.34", 0)),
    ]

    with patch(
        "phishalyzer.analyzers.domain_analyzer.socket.getaddrinfo",
        return_value=mock_results
    ):
        result = analyzer.analyze("example.com")

    assert result.ip_addresses == ("93.184.216.34",)
