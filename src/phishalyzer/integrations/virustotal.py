
"""VirusTotal API integration for Phishalyzer."""

import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from phishalyzer.core.config import get_settings


VT_BASE_URL = "https://www.virustotal.com/api/v3"


@dataclass(frozen=True)
class VirusTotalResult:
    """Normalized VirusTotal reputation information."""

    resource: str
    resource_type: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: int
    is_malicious: bool
    errors: tuple[str, ...]


class VirusTotalAnalyzer:
    """Safely retrieve URL and domain reputation from VirusTotal."""

    def __init__(
        self,
        timeout: int | None = None,
        session: requests.Session | None = None,
    ):
        settings = get_settings()

        self.api_key = settings.virustotal_api_key
        self.timeout = (
            settings.request_timeout if timeout is None else timeout
        )

        if (
            not isinstance(self.timeout, int)
            or isinstance(self.timeout, bool)
            or not 1 <= self.timeout <= 60
        ):
            raise ValueError("Timeout must be between 1 and 60")

        self.session = (
            session if session is not None else requests.Session()
        )

    def _get_headers(self) -> dict[str, str]:
        """Build authenticated request headers."""

        if not self.api_key:
            raise ValueError(
                "VirusTotal API key is not configured"
            )

        return {
            "x-apikey": self.api_key.get_secret_value(),
            "Accept": "application/json",
        }

    def _request(self, endpoint: str) -> dict[str, Any]:
        """Perform an authenticated VirusTotal API request."""

        # Validate the API key outside the request exception handler.
        # This prevents authentication configuration errors from
        # being incorrectly reported as JSON errors.
        headers = self._get_headers()

        try:
            response = self.session.get(
                f"{VT_BASE_URL}/{endpoint}",
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )

            if response.status_code == 429:
                raise RuntimeError(
                    "VirusTotal rate limit exceeded"
                )

            response.raise_for_status()

            try:
                data = response.json()
            except ValueError as exc:
                raise RuntimeError(
                    "VirusTotal returned invalid JSON"
                ) from exc

            if not isinstance(data, dict):
                raise RuntimeError(
                    "VirusTotal returned an invalid response format"
                )

            return data

        except requests.Timeout as exc:
            raise RuntimeError(
                "VirusTotal request timed out"
            ) from exc

        except requests.RequestException as exc:
            raise RuntimeError(
                f"VirusTotal request failed: {exc}"
            ) from exc

    @staticmethod
    def _validate_domain(domain: str) -> str:
        """Validate and normalize a domain name."""

        if not isinstance(domain, str):
            raise ValueError("Domain must be a string")

        domain = domain.strip().lower().rstrip(".")

        if not domain or len(domain) > 253:
            raise ValueError("Invalid domain format")

        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("Expected a domain, not an IP address")

        labels = domain.split(".")

        if len(labels) < 2:
            raise ValueError("Invalid domain format")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                raise ValueError("Invalid domain format")

        return domain

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate an HTTP or HTTPS URL."""

        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        url = url.strip()

        if not url or len(url) > 8192:
            raise ValueError("Invalid URL")

        if any(
            ord(char) < 32 or ord(char) == 127
            for char in url
        ):
            raise ValueError("URL contains control characters")

        try:
            parsed = urlsplit(url)

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Invalid URL format")

            # Accessing port validates its numeric range.
            _ = parsed.port

        except ValueError as exc:
            raise ValueError("Invalid URL format") from exc

        return url

    @staticmethod
    def _parse_result(
        resource: str,
        resource_type: str,
        data: dict[str, Any],
    ) -> VirusTotalResult:
        """Extract and validate VirusTotal reputation statistics."""

        if not isinstance(data, dict):
            raise RuntimeError(
                "Invalid VirusTotal response structure"
            )

        attributes = data.get("data", {})

        if not isinstance(attributes, dict):
            raise RuntimeError(
                "Invalid VirusTotal response structure"
            )

        attributes = attributes.get("attributes", {})

        if not isinstance(attributes, dict):
            raise RuntimeError(
                "Invalid VirusTotal response structure"
            )

        stats = attributes.get("last_analysis_stats", {})

        if not isinstance(stats, dict):
            raise RuntimeError(
                "Invalid VirusTotal analysis statistics"
            )

        def safe_count(value: Any) -> int:
            """Return a valid non-negative integer."""

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                return 0

            return value

        malicious = safe_count(stats.get("malicious", 0))
        suspicious = safe_count(stats.get("suspicious", 0))
        harmless = safe_count(stats.get("harmless", 0))
        undetected = safe_count(stats.get("undetected", 0))

        reputation = attributes.get("reputation", 0)

        if (
            not isinstance(reputation, int)
            or isinstance(reputation, bool)
        ):
            reputation = 0

        return VirusTotalResult(
            resource=resource,
            resource_type=resource_type,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            reputation=reputation,
            is_malicious=(
                malicious > 0 or suspicious > 0
            ),
            errors=(),
        )

    def analyze_url(self, url: str) -> VirusTotalResult:
        """Retrieve reputation for an existing URL in VirusTotal."""

        url = self._validate_url(url)

        url_id = (
            base64.urlsafe_b64encode(
                url.encode("utf-8")
            )
            .decode("ascii")
            .rstrip("=")
        )

        data = self._request(f"urls/{url_id}")

        return self._parse_result(
            resource=url,
            resource_type="url",
            data=data,
        )

    def analyze_domain(self, domain: str) -> VirusTotalResult:
        """Retrieve reputation information for a domain."""

        domain = self._validate_domain(domain)

        data = self._request(f"domains/{domain}")

        return self._parse_result(
            resource=domain,
            resource_type="domain",
            data=data,
        )

    def close(self) -> None:
        """Close the HTTP session."""

        self.session.close()
