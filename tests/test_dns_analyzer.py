
import pytest
from unittest.mock import patch, MagicMock
from phishalyzer.analyzers.dns_analyzer import DNSAnalyzer


def test_invalid_domain_input():
    analyzer = DNSAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("")


def test_non_string_domain_input():
    analyzer = DNSAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(None)


def test_invalid_url_input():
    analyzer = DNSAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("https://example.com")


def test_invalid_timeout():
    with pytest.raises(ValueError):
        DNSAnalyzer(timeout=0)


@patch("phishalyzer.analyzers.dns_analyzer.dns.resolver.Resolver")
def test_successful_dns_analysis(mock_resolver):
    resolver = mock_resolver.return_value

    def mock_resolve(domain, record_type, **kwargs):
        response = MagicMock()

        if record_type == "A":
            response.rrset = True
            response.__iter__.return_value = [
                MagicMock(to_text=lambda: "93.184.216.34")
            ]
        else:
            response.rrset = None

        return response

    resolver.resolve.side_effect = mock_resolve

    result = DNSAnalyzer().analyze("example.com")

    assert result.domain == "example.com"
    assert result.records["A"] == ["93.184.216.34"]
    assert result.records["AAAA"] == []
    assert result.errors == ()


@patch("phishalyzer.analyzers.dns_analyzer.dns.resolver.Resolver")
def test_dns_timeout(mock_resolver):
    import dns.exception

    resolver = mock_resolver.return_value
    resolver.resolve.side_effect = dns.exception.Timeout

    result = DNSAnalyzer().analyze("example.com")

    assert result.domain == "example.com"
    assert any("timeout" in error.lower() for error in result.errors)


@patch("phishalyzer.analyzers.dns_analyzer.dns.resolver.Resolver")
def test_missing_dns_records(mock_resolver):
    resolver = mock_resolver.return_value
    response = MagicMock()
    response.rrset = None
    resolver.resolve.return_value = response

    result = DNSAnalyzer().analyze("example.com")

    assert result.records["A"] == []
    assert result.records["MX"] == []
    assert result.errors == ()


def test_domain_normalization():
    analyzer = DNSAnalyzer()

    with patch(
        "phishalyzer.analyzers.dns_analyzer.dns.resolver.Resolver"
    ) as mock_resolver:
        response = MagicMock()
        response.rrset = None
        mock_resolver.return_value.resolve.return_value = response

        result = analyzer.analyze(" EXAMPLE.COM. ")

    assert result.domain == "example.com"


