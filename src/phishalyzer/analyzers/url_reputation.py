
"""URL reputation analyzer for Phishalyzer."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from phishalyzer.integrations.virustotal import (
    VirusTotalAnalyzer,
)


@dataclass(frozen=True)
class URLReputation:
    """Normalized URL reputation information."""

    url: str
    is_malicious: bool | None
    reputation: str
    source: str
    details: str
    errors: tuple[str, ...]


class URLReputationAnalyzer:
    """Analyze URL reputation using VirusTotal."""

    def __init__(
        self,
        virustotal_analyzer: VirusTotalAnalyzer | None = None,
    ):
        self.virustotal_analyzer = (
            virustotal_analyzer
            if virustotal_analyzer is not None
            else VirusTotalAnalyzer()
        )

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate and normalize an HTTP or HTTPS URL."""

        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        url = url.strip()

        if not url or len(url) > 8192:
            raise ValueError("Invalid URL")

        if any(
            char.isspace() or ord(char) < 32 or ord(char) == 127
            for char in url
        ):
            raise ValueError("URL contains invalid characters")

        try:
            parsed = urlsplit(url)

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Invalid URL format")

            _ = parsed.port

        except ValueError as exc:
            raise ValueError("Invalid URL format") from exc

        return url

    def analyze(self, url: str) -> URLReputation:
        """Analyze URL reputation through VirusTotal."""

        url = self._validate_url(url)

        try:
            result = self.virustotal_analyzer.analyze_url(url)

            malicious = result.malicious
            suspicious = result.suspicious
            harmless = result.harmless
            undetected = result.undetected

            details = (
                f"VirusTotal detections: "
                f"{malicious} malicious, "
                f"{suspicious} suspicious, "
                f"{harmless} harmless, "
                f"{undetected} undetected."
            )

            if malicious > 0 or suspicious > 0:
                reputation = "malicious"
                is_malicious = True

            elif harmless > 0:
                reputation = "harmless"
                is_malicious = False

            else:
                reputation = "unknown"
                is_malicious = None

            return URLReputation(
                url=url,
                is_malicious=is_malicious,
                reputation=reputation,
                source="VirusTotal",
                details=details,
                errors=(),
            )

        except (ValueError, RuntimeError) as exc:
            return URLReputation(
                url=url,
                is_malicious=None,
                reputation="unknown",
                source="VirusTotal",
                details="VirusTotal reputation lookup failed",
                errors=(str(exc),),
            )
