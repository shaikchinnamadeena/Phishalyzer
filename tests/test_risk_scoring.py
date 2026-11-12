
"""Tests for the Phishalyzer risk-scoring engine."""

from types import SimpleNamespace

import pytest

from phishalyzer.core.risk_scoring import RiskScoringEngine


@pytest.fixture
def engine():
    return RiskScoringEngine()


@pytest.fixture
def parsed_url():
    return SimpleNamespace(
        is_ip_address=False,
        is_shortened=False,
        has_punycode=False,
        suspicious_keywords=(),
    )


def test_clean_inputs_produce_low_score(engine, parsed_url):
    result = engine.analyze(parsed_url)

    assert result.score == 0
    assert result.level == "Low"
    assert result.evidence == ()
    assert result.evidence_coverage == 25


def test_ip_address_url_adds_ten_points(engine):
    parsed = SimpleNamespace(
        is_ip_address=True,
        is_shortened=False,
        has_punycode=False,
        suspicious_keywords=(),
    )

    result = engine.analyze(parsed)

    assert result.score == 10
    assert result.evidence[0].points == 10


def test_punycode_url_adds_ten_points(engine):
    parsed = SimpleNamespace(
        is_ip_address=False,
        is_shortened=False,
        has_punycode=True,
        suspicious_keywords=(),
    )

    result = engine.analyze(parsed)

    assert result.score == 10


def test_shortened_url_adds_five_points(engine):
    parsed = SimpleNamespace(
        is_ip_address=False,
        is_shortened=True,
        has_punycode=False,
        suspicious_keywords=(),
    )

    result = engine.analyze(parsed)

    assert result.score == 5


def test_suspicious_keywords_are_scored(engine, parsed_url):
    parsed_url.suspicious_keywords = ("login", "verify")

    result = engine.analyze(parsed_url)

    assert result.score == 4


def test_url_structural_score_is_capped_at_25(engine):
    parsed = SimpleNamespace(
        is_ip_address=True,
        is_shortened=True,
        has_punycode=True,
        suspicious_keywords=("login", "verify", "account", "password"),
    )

    result = engine.analyze(parsed)

    assert result.score == 25
    assert sum(item.points for item in result.evidence) == 25


def test_virustotal_malicious_detections(engine, parsed_url):
    vt = SimpleNamespace(
        malicious=2,
        suspicious=0,
        harmless=10,
        undetected=5,
    )

    result = engine.analyze(parsed_url, virustotal=vt)

    assert result.score == 20
    assert result.evidence_coverage == 50


def test_virustotal_suspicious_detections(engine, parsed_url):
    vt = SimpleNamespace(
        malicious=0,
        suspicious=3,
        harmless=10,
        undetected=5,
    )

    result = engine.analyze(parsed_url, virustotal=vt)

    assert result.score == 6


def test_virustotal_detection_points_are_capped(engine, parsed_url):
    vt = SimpleNamespace(
        malicious=100,
        suspicious=100,
        harmless=0,
        undetected=0,
    )

    result = engine.analyze(parsed_url, virustotal=vt)

    assert result.score == 40


def test_invalid_virustotal_counts_are_not_scored(engine, parsed_url):
    vt = SimpleNamespace(
        malicious=-1,
        suspicious=0,
        harmless=10,
        undetected=5,
    )

    result = engine.analyze(parsed_url, virustotal=vt)

    assert result.score == 0
    assert "VirusTotal statistics are incomplete or invalid." in result.warnings


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (0, 15),
        (7, 15),
        (8, 12),
        (30, 12),
        (31, 8),
        (90, 8),
        (91, 5),
        (180, 5),
        (181, 0),
        (365, 0),
    ],
)
def test_whois_domain_age_scoring(engine, parsed_url, age, expected):
    whois = SimpleNamespace(domain_age_days=age)

    result = engine.analyze(parsed_url, whois=whois)

    assert result.score == expected


def test_invalid_whois_age_is_not_scored(engine, parsed_url):
    whois = SimpleNamespace(domain_age_days=-5)

    result = engine.analyze(parsed_url, whois=whois)

    assert result.score == 0
    assert "WHOIS domain age is unavailable or invalid." in result.warnings


def test_urlscan_phishing_category_adds_twenty_points(
    engine,
    parsed_url,
):
    urlscan = SimpleNamespace(categories=("phishing",))

    result = engine.analyze(parsed_url, urlscan=urlscan)

    assert result.score == 20


def test_urlscan_categories_are_normalized(engine, parsed_url):
    urlscan = SimpleNamespace(categories=("Credential_Theft",))

    result = engine.analyze(parsed_url, urlscan=urlscan)

    assert result.score == 20


def test_benign_urlscan_categories_add_no_points(engine, parsed_url):
    urlscan = SimpleNamespace(categories=("technology", "business"))

    result = engine.analyze(parsed_url, urlscan=urlscan)

    assert result.score == 0
    assert result.evidence_coverage == 50


def test_urlscan_verdict_score_is_not_used_without_validation(
    engine,
    parsed_url,
):
    urlscan = SimpleNamespace(
        categories=(),
        verdict_score=100,
    )

    result = engine.analyze(parsed_url, urlscan=urlscan)

    assert result.score == 0


def test_missing_intelligence_is_reported(engine, parsed_url):
    result = engine.analyze(parsed_url)

    assert len(result.warnings) == 3
    assert result.evidence_coverage == 25


def test_dns_and_ip_are_context_only(engine, parsed_url):
    dns = SimpleNamespace(records={"A": ["192.0.2.1"]})
    ip = SimpleNamespace(is_public=False, is_private=True)

    result = engine.analyze(
        parsed_url,
        dns=dns,
        ip=ip,
    )

    assert result.score == 0
    assert result.evidence_coverage == 25
    assert len(result.warnings) == 5


def test_all_sources_can_produce_maximum_score(engine):
    parsed = SimpleNamespace(
        is_ip_address=True,
        is_shortened=True,
        has_punycode=True,
        suspicious_keywords=("login", "verify", "account", "password"),
    )
    vt = SimpleNamespace(
        malicious=10,
        suspicious=10,
        harmless=0,
        undetected=0,
    )
    whois = SimpleNamespace(domain_age_days=2)
    urlscan = SimpleNamespace(categories=("phishing",))

    result = engine.analyze(
        parsed,
        virustotal=vt,
        whois=whois,
        urlscan=urlscan,
    )

    assert result.score == 100
    assert result.level == "Critical"
    assert result.evidence_coverage == 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Low"),
        (19, "Low"),
        (20, "Medium"),
        (39, "Medium"),
        (40, "High"),
        (69, "High"),
        (70, "Critical"),
        (100, "Critical"),
    ],
)
def test_risk_level_boundaries(score, expected):
    assert RiskScoringEngine._risk_level(score) == expected


def test_parsed_url_is_required(engine):
    with pytest.raises(ValueError, match="Parsed URL analysis is required"):
        engine.analyze(None)


def test_evidence_has_explanations(engine):
    parsed = SimpleNamespace(
        is_ip_address=True,
        is_shortened=False,
        has_punycode=False,
        suspicious_keywords=(),
    )

    result = engine.analyze(parsed)

    assert result.evidence
    assert all(item.explanation for item in result.evidence)
    assert all(item.points > 0 for item in result.evidence)
