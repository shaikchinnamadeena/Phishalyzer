
"""Comprehensive tests for URL parsing and validation."""

import pytest

from phishalyzer.utils.url_parser import parse_url


def test_basic_https_url():
    result = parse_url("https://example.com")

    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.path == "/"


def test_url_without_scheme():
    result = parse_url("example.com")

    assert result.scheme == "https"
    assert result.normalized_url == "https://example.com/"


def test_http_url():
    result = parse_url("http://example.com")

    assert result.scheme == "http"


def test_port_preservation():
    result = parse_url("https://example.com:8443/login")

    assert result.port == 8443
    assert result.normalized_url == "https://example.com:8443/login"


def test_default_path():
    result = parse_url("https://example.com")

    assert result.path == "/"


def test_ip_address_detection():
    result = parse_url("http://192.168.1.10/login")

    assert result.is_ip_address is True
    assert result.hostname == "192.168.1.10"


def test_ipv6_address_detection():
    result = parse_url("https://[2001:db8::1]/")

    assert result.is_ip_address is True
    assert result.hostname == "2001:db8::1"
    assert "[2001:db8::1]" in result.normalized_url


def test_punycode_detection():
    result = parse_url("https://xn--bcher-kva.de")

    assert result.has_punycode is True


def test_url_shortener_detection():
    result = parse_url("https://bit.ly/example")

    assert result.is_shortened is True


def test_shortener_subdomain_not_exact_match():
    result = parse_url("https://sub.bit.ly/example")

    assert result.is_shortened is False


def test_suspicious_keyword_detection():
    result = parse_url("https://example.com/login")

    assert "login" in result.suspicious_keywords


def test_multiple_suspicious_keywords():
    result = parse_url(
        "https://example.com/login?account=verify"
    )

    assert set(result.suspicious_keywords) == {
        "login",
        "account",
        "verify",
    }


def test_query_string_preservation():
    result = parse_url(
        "https://example.com/search?id=123"
    )

    assert result.query == "id=123"
    assert "id=123" in result.normalized_url


def test_fragment_removed_from_normalized_url():
    result = parse_url("https://example.com/page#section")

    assert "#" not in result.normalized_url


def test_hostname_normalization():
    result = parse_url("HTTPS://EXAMPLE.COM")

    assert result.hostname == "example.com"
    assert result.scheme == "https"


def test_trailing_hostname_dot_removed():
    result = parse_url("https://example.com.")

    assert result.hostname == "example.com"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com",
        "javascript:alert(1)",
        "//example.com",
        "https://",
        "https://user:password@example.com",
        "https://example.com:99999",
        "https://example.com:invalid",
        "https://-invalid.com",
        "https://example..com",
        "https://example",
        "https://example.com\\evil",
        "https://example.com/path with spaces",
    ],
)
def test_invalid_urls_are_rejected(url):
    with pytest.raises(ValueError):
        parse_url(url)


def test_non_string_input():
    with pytest.raises(TypeError):
        parse_url(None)


def test_url_exceeding_maximum_length():
    url = "https://example.com/" + ("a" * 2050)

    with pytest.raises(ValueError, match="maximum supported length"):
        parse_url(url)


def test_control_characters_are_rejected():
    with pytest.raises(ValueError):
        parse_url("https://example.com/\nlogin")


def test_embedded_credentials_are_rejected():
    with pytest.raises(ValueError, match="credentials"):
        parse_url("https://admin:secret@example.com")


def test_original_url_is_preserved():
    url = "HTTPS://EXAMPLE.COM/login"

    result = parse_url(url)

    assert result.original_url == url


def test_parsed_result_is_immutable():
    result = parse_url("https://example.com")

    with pytest.raises(AttributeError):
        result.hostname = "malicious.com"
