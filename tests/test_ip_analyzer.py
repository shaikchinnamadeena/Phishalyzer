
import pytest

from phishalyzer.analyzers.ip_analyzer import IPAnalyzer


def test_invalid_ip_input():
    with pytest.raises(ValueError):
        IPAnalyzer().analyze("")


def test_non_string_ip_input():
    with pytest.raises(ValueError):
        IPAnalyzer().analyze(None)


def test_invalid_ip_format():
    with pytest.raises(ValueError):
        IPAnalyzer().analyze("999.999.999.999")


def test_public_ipv4():
    result = IPAnalyzer().analyze("8.8.8.8")

    assert result.is_valid is True
    assert result.version == 4
    assert result.is_public is True
    assert result.is_private is False


def test_private_ipv4():
    result = IPAnalyzer().analyze("192.168.1.1")

    assert result.is_private is True
    assert result.is_public is False


def test_loopback_ip():
    result = IPAnalyzer().analyze("127.0.0.1")

    assert result.is_loopback is True


def test_ipv6_detection():
    result = IPAnalyzer().analyze("2001:4860:4860::8888")

    assert result.version == 6
    assert result.is_valid is True


def test_link_local_ip():
    result = IPAnalyzer().analyze("169.254.1.1")

    assert result.is_link_local is True
