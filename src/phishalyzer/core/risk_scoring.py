
"""Explainable risk scoring engine for Phishalyzer."""

from dataclasses import dataclass
from typing import Any

from phishalyzer.core.config import Settings, get_settings


@dataclass(frozen=True)
class RiskEvidence:
    """A single explainable contribution to a risk assessment."""

    source: str
    indicator: str
    points: int
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    """Immutable result of a risk assessment."""

    score: int
    level: str
    evidence: tuple[RiskEvidence, ...]
    evidence_coverage: int
    warnings: tuple[str, ...]


class RiskScoringEngine:
    """Calculate a transparent heuristic phishing risk score."""

    MAX_SCORE = 100

    THREAT_CATEGORIES = frozenset({
        "phishing",
        "malware",
        "malicious",
        "scam",
        "credential theft",
        "malware distribution",
        "social engineering",
    })

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize scoring with validated application settings."""

        self.settings = settings if settings is not None else get_settings()
        self.settings.validate_risk_thresholds()

    def analyze(
        self,
        parsed_url: Any,
        virustotal: Any = None,
        whois: Any = None,
        urlscan: Any = None,
        dns: Any = None,
        ip: Any = None,
    ) -> RiskAssessment:
        """Score supplied analyzer results without performing network calls."""

        if parsed_url is None:
            raise ValueError("Parsed URL analysis is required")

        evidence: list[RiskEvidence] = []
        warnings: list[str] = []
        completed_sources = 1

        self._score_url_structure(parsed_url, evidence)

        if virustotal is None:
            warnings.append("VirusTotal intelligence is unavailable.")
        elif self._score_virustotal(virustotal, evidence):
            completed_sources += 1
        else:
            warnings.append(
                "VirusTotal statistics are incomplete or invalid."
            )

        if whois is None:
            warnings.append("WHOIS intelligence is unavailable.")
        elif self._score_whois(whois, evidence):
            completed_sources += 1
        else:
            warnings.append(
                "WHOIS domain age is unavailable or invalid."
            )

        if urlscan is None:
            warnings.append("URLScan intelligence is unavailable.")
        elif self._score_urlscan(urlscan, evidence):
            completed_sources += 1
        else:
            warnings.append(
                "URLScan threat categories are unavailable or invalid."
            )

        # DNS and IP are retained as context.
        # They do not add points until validated risk indicators are defined.
        if dns is not None:
            warnings.append(
                "DNS results are contextual and do not currently "
                "add risk points."
            )

        if ip is not None:
            warnings.append(
                "IP classification is contextual and does not currently "
                "add risk points."
            )

        score = min(
            self.MAX_SCORE,
            sum(item.points for item in evidence),
        )

        return RiskAssessment(
            score=score,
            level=self._risk_level(score),
            evidence=tuple(evidence),
            evidence_coverage=completed_sources * 25,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _add(
        evidence: list[RiskEvidence],
        source: str,
        indicator: str,
        points: int,
        explanation: str,
    ) -> None:
        """Append a positive, explainable scoring contribution."""

        if points > 0:
            evidence.append(
                RiskEvidence(
                    source=source,
                    indicator=indicator,
                    points=points,
                    explanation=explanation,
                )
            )

    def _score_url_structure(
        self,
        parsed_url: Any,
        evidence: list[RiskEvidence],
    ) -> None:
        """Score structural URL indicators, capped at 25 points."""

        points = 0

        if getattr(parsed_url, "is_ip_address", False) is True:
            points += 10
            self._add(
                evidence,
                "URL",
                "IP-address hostname",
                10,
                "The URL uses an IP address instead of a domain name.",
            )

        if getattr(parsed_url, "has_punycode", False) is True:
            points += 10
            self._add(
                evidence,
                "URL",
                "Punycode hostname",
                10,
                "The hostname contains an internationalized Punycode label.",
            )

        if getattr(parsed_url, "is_shortened", False) is True:
            points += 5
            self._add(
                evidence,
                "URL",
                "URL shortener",
                5,
                "The URL uses a recognized URL-shortening service.",
            )

        keywords = getattr(parsed_url, "suspicious_keywords", ())

        if isinstance(keywords, (tuple, list, set, frozenset)):
            valid_keywords = sorted({
                item.strip().lower()
                for item in keywords
                if isinstance(item, str) and item.strip()
            })
        else:
            valid_keywords = []

        keyword_points = min(10, len(valid_keywords) * 2)

        if keyword_points:
            points += keyword_points
            self._add(
                evidence,
                "URL",
                "Suspicious URL keywords",
                keyword_points,
                "Suspicious keywords found: "
                + ", ".join(valid_keywords),
            )

        # Structural indicators share a maximum budget of 25.
        overflow = max(0, points - 25)

        if overflow:
            remaining = overflow

            for index in range(len(evidence) - 1, -1, -1):
                item = evidence[index]

                if item.source != "URL":
                    continue

                reduction = min(item.points, remaining)

                evidence[index] = RiskEvidence(
                    source=item.source,
                    indicator=item.indicator,
                    points=item.points - reduction,
                    explanation=item.explanation,
                )

                remaining -= reduction

                if remaining == 0:
                    break

            evidence[:] = [
                item for item in evidence if item.points > 0
            ]

    def _score_virustotal(
        self,
        result: Any,
        evidence: list[RiskEvidence],
    ) -> bool:
        """Score VirusTotal malicious and suspicious detections."""

        malicious = getattr(result, "malicious", None)
        suspicious = getattr(result, "suspicious", None)
        harmless = getattr(result, "harmless", None)
        undetected = getattr(result, "undetected", None)

        counts = (malicious, suspicious, harmless, undetected)

        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in counts
        ):
            return False

        malicious_points = min(30, malicious * 10)
        suspicious_points = min(10, suspicious * 2)

        self._add(
            evidence,
            "VirusTotal",
            "Malicious detections",
            malicious_points,
            f"VirusTotal reported {malicious} malicious detections.",
        )

        self._add(
            evidence,
            "VirusTotal",
            "Suspicious detections",
            suspicious_points,
            f"VirusTotal reported {suspicious} suspicious detections.",
        )

        return True

    def _score_whois(
        self,
        result: Any,
        evidence: list[RiskEvidence],
    ) -> bool:
        """Score domain age using conservative age bands."""

        age = getattr(result, "domain_age_days", None)

        if (
            not isinstance(age, int)
            or isinstance(age, bool)
            or age < 0
        ):
            return False

        if age <= 7:
            points = 15
            explanation = (
                "The domain was registered within the last 7 days."
            )
        elif age <= 30:
            points = 12
            explanation = (
                "The domain was registered within the last 30 days."
            )
        elif age <= 90:
            points = 8
            explanation = (
                "The domain was registered within the last 90 days."
            )
        elif age <= 180:
            points = 5
            explanation = (
                "The domain was registered within the last 180 days."
            )
        else:
            points = 0
            explanation = "The domain is older than 180 days."

        self._add(
            evidence,
            "WHOIS",
            "Domain age",
            points,
            explanation,
        )

        return True

    def _score_urlscan(
        self,
        result: Any,
        evidence: list[RiskEvidence],
    ) -> bool:
        """Score explicit URLScan threat categories."""

        categories = getattr(result, "categories", None)

        if not isinstance(
            categories,
            (tuple, list, set, frozenset),
        ):
            return False

        if any(not isinstance(item, str) for item in categories):
            return False

        normalized = {
            " ".join(
                item.strip().lower()
                .replace("_", " ")
                .replace("-", " ")
                .split()
            )
            for item in categories
            if item.strip()
        }

        matched = sorted(normalized & self.THREAT_CATEGORIES)

        if matched:
            self._add(
                evidence,
                "URLScan",
                "Threat category",
                20,
                "URLScan reported threat categories: "
                + ", ".join(matched),
            )

        return True

    def _risk_level(self, score: int) -> str:
        """Map a risk score to its configured classification."""

        if score <= self.settings.risk_low_max:
            return "Low"

        if score <= self.settings.risk_moderate_max:
            return "Medium"

        if score <= self.settings.risk_high_max:
            return "High"

        return "Critical"
