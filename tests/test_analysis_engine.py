
"""Tests for the central Phishalyzer analysis engine."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from phishalyzer.core.analysis_engine import AnalysisEngine


@pytest.fixture
def dependencies():
    domain = MagicMock()
    domain.analyze.return_value = SimpleNamespace(
        domain="example.com",
        is_valid=True,
        ip_addresses=("93.184.216.34",),
        has_dns_records=True,
        is_ip_address=False,
        errors=(),
    )

    dns = MagicMock()
    dns.analyze.return_value = SimpleNamespace(
        domain="example.com",
        records={"A": ["93.184.216.34"]},
        errors=(),
    )

    ip = MagicMock()
    ip.analyze.return_value = SimpleNamespace(
        ip_address="93.184.216.34",
        is_valid=True,
        version=4,
        is_private=False,
        is_public=True,
        is_loopback=False,
        is_reserved=False,
        is_multicast=False,
        is_link_local=False,
        errors=(),
    )

    whois = MagicMock()
    whois.analyze.return_value = SimpleNamespace(
        domain="example.com",
        registrar="Example Registrar",
        creation_date=None,
        expiration_date=None,
        domain_age_days=365,
        days_until_expiration=None,
        errors=(),
    )

    vt = MagicMock()
    vt.analyze_url.return_value = SimpleNamespace(
        resource="https://example.com/",
        resource_type="url",
        malicious=0,
        suspicious=0,
        harmless=10,
        undetected=5,
        reputation=0,
        is_malicious=False,
        errors=(),
    )

    urlscan = MagicMock()
    urlscan.submit_url.return_value = SimpleNamespace(
        scan_id="00000000-0000-4000-8000-000000000001",
        url="https://example.com/",
        visibility="private",
        result_url="https://urlscan.io/result/example/",
        api_url="https://urlscan.io/api/v1/result/example/",
    )
    urlscan.get_result.return_value = SimpleNamespace(
        categories=(),
        verdict_score=0,
    )

    return {
        "domain_analyzer": domain,
        "dns_analyzer": dns,
        "ip_analyzer": ip,
        "whois_analyzer": whois,
        "virustotal_analyzer": vt,
        "urlscan_analyzer": urlscan,
    }


@pytest.fixture
def engine(dependencies):
    return AnalysisEngine(**dependencies)


def test_successful_analysis_returns_combined_result(engine):
    result = engine.analyze("https://example.com")

    assert result.parsed_url.hostname == "example.com"
    assert result.domain is not None
    assert result.dns is not None
    assert result.whois is not None
    assert result.virustotal is not None
    assert result.urlscan is None
    assert result.urlscan_submission is None
    assert len(result.ip) == 1
    assert result.risk.score == 0


def test_invalid_url_is_rejected_before_network_calls(
    engine,
    dependencies,
):
    with pytest.raises(ValueError):
        engine.analyze("javascript:alert(1)")

    dependencies["domain_analyzer"].analyze.assert_not_called()
    dependencies["virustotal_analyzer"].analyze_url.assert_not_called()


def test_urlscan_is_not_submitted_by_default(engine, dependencies):
    engine.analyze("https://example.com")

    dependencies["urlscan_analyzer"].submit_url.assert_not_called()
    dependencies["urlscan_analyzer"].get_result.assert_not_called()


def test_urlscan_opt_in_stores_submission_without_immediate_retrieval(
    engine,
    dependencies,
):
    result = engine.analyze(
        "https://example.com",
        enable_urlscan=True,
    )

    dependencies["urlscan_analyzer"].submit_url.assert_called_once()
    dependencies["urlscan_analyzer"].get_result.assert_not_called()

    assert result.urlscan_submission is not None
    assert result.urlscan_submission.scan_id == (
        "00000000-0000-4000-8000-000000000001"
    )
    assert result.urlscan is None


def test_urlscan_result_can_be_retrieved_later(engine, dependencies):
    analysis = engine.analyze(
        "https://example.com",
        enable_urlscan=True,
    )

    dependencies["urlscan_analyzer"].get_result.return_value = (
        SimpleNamespace(
            categories=("phishing",),
            verdict_score=100,
        )
    )

    completed = engine.complete_urlscan(analysis)

    dependencies["urlscan_analyzer"].get_result.assert_called_once_with(
        analysis.urlscan_submission.scan_id
    )

    assert completed.urlscan is not None
    assert completed.risk.score == 20
    assert completed.risk.level == "Low"


def test_urlscan_pending_result_preserves_analysis(
    engine,
    dependencies,
):
    analysis = engine.analyze(
        "https://example.com",
        enable_urlscan=True,
    )

    dependencies["urlscan_analyzer"].get_result.side_effect = RuntimeError(
        "Result is not ready yet"
    )

    pending = engine.complete_urlscan(analysis)

    assert pending.urlscan is None
    assert pending.urlscan_submission == analysis.urlscan_submission
    assert pending.risk.score == analysis.risk.score
    assert any(
        "not available yet" in warning
        for warning in pending.warnings
    )


def test_urlscan_can_be_retried_after_pending_result(
    engine,
    dependencies,
):
    analysis = engine.analyze(
        "https://example.com",
        enable_urlscan=True,
    )

    dependencies["urlscan_analyzer"].get_result.side_effect = [
        RuntimeError("Result is not ready yet"),
        SimpleNamespace(categories=("phishing",), verdict_score=100),
    ]

    pending = engine.complete_urlscan(analysis)
    completed = engine.complete_urlscan(pending)

    assert pending.urlscan is None
    assert completed.urlscan is not None
    assert completed.risk.score == 20
    assert dependencies["urlscan_analyzer"].get_result.call_count == 2


def test_completion_without_submission_returns_original_result(engine):
    analysis = engine.analyze("https://example.com")

    completed = engine.complete_urlscan(analysis)

    assert completed is analysis


def test_virustotal_failure_does_not_stop_local_analysis(
    engine,
    dependencies,
):
    dependencies["virustotal_analyzer"].analyze_url.side_effect = (
        RuntimeError("Service unavailable")
    )

    result = engine.analyze("https://example.com")

    assert result.virustotal is None
    assert result.domain is not None
    assert result.dns is not None
    assert result.whois is not None
    assert any("VirusTotal" in warning for warning in result.warnings)


def test_dns_failure_does_not_stop_other_analysis(engine, dependencies):
    dependencies["dns_analyzer"].analyze.side_effect = RuntimeError(
        "DNS unavailable"
    )

    result = engine.analyze("https://example.com")

    assert result.dns is None
    assert result.domain is not None
    assert result.virustotal is not None
    assert any("DNS" in warning for warning in result.warnings)


def test_whois_failure_does_not_stop_other_analysis(engine, dependencies):
    dependencies["whois_analyzer"].analyze.side_effect = RuntimeError(
        "WHOIS unavailable"
    )

    result = engine.analyze("https://example.com")

    assert result.whois is None
    assert result.domain is not None
    assert result.virustotal is not None
    assert any("WHOIS" in warning for warning in result.warnings)


def test_domain_failure_does_not_stop_virustotal(engine, dependencies):
    dependencies["domain_analyzer"].analyze.side_effect = RuntimeError(
        "Domain lookup failed"
    )

    result = engine.analyze("https://example.com")

    assert result.domain is None
    assert result.virustotal is not None
    assert result.ip == ()
    assert any("Domain" in warning for warning in result.warnings)


def test_ip_hostname_skips_dns_and_whois(engine, dependencies):
    result = engine.analyze("https://8.8.8.8")

    dependencies["dns_analyzer"].analyze.assert_not_called()
    dependencies["whois_analyzer"].analyze.assert_not_called()
    dependencies["ip_analyzer"].analyze.assert_called_once_with("8.8.8.8")

    assert result.parsed_url.is_ip_address is True


def test_urlscan_submission_failure_does_not_stop_analysis(
    engine,
    dependencies,
):
    dependencies["urlscan_analyzer"].submit_url.side_effect = (
        RuntimeError("URLScan unavailable")
    )

    result = engine.analyze(
        "https://example.com",
        enable_urlscan=True,
    )

    assert result.urlscan_submission is None
    assert result.urlscan is None
    assert result.virustotal is not None
    assert any("URLScan" in warning for warning in result.warnings)


def test_multiple_resolved_ips_are_analyzed(engine, dependencies):
    dependencies["domain_analyzer"].analyze.return_value = SimpleNamespace(
        domain="example.com",
        is_valid=True,
        ip_addresses=("93.184.216.34", "1.1.1.1"),
        has_dns_records=True,
        is_ip_address=False,
        errors=(),
    )

    result = engine.analyze("https://example.com")

    assert len(result.ip) == 2
    assert dependencies["ip_analyzer"].analyze.call_count == 2


def test_close_closes_both_external_analyzers(engine, dependencies):
    engine.close()

    dependencies["virustotal_analyzer"].close.assert_called_once()
    dependencies["urlscan_analyzer"].close.assert_called_once()


def test_close_attempts_both_analyzers_if_one_fails(
    engine,
    dependencies,
):
    dependencies["virustotal_analyzer"].close.side_effect = RuntimeError(
        "VirusTotal close failed"
    )

    with pytest.raises(RuntimeError, match="Failed to close"):
        engine.close()

    dependencies["virustotal_analyzer"].close.assert_called_once()
    dependencies["urlscan_analyzer"].close.assert_called_once()
