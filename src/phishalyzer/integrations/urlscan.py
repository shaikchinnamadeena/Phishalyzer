
"""URLScan.io integration for Phishalyzer."""

import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import requests

from phishalyzer.core.config import get_settings

URLSCAN_BASE_URL = "https://urlscan.io/api/v1"


@dataclass(frozen=True)
class URLScanSubmission:
    """Information returned after submitting a URL."""

    scan_id: str
    url: str
    visibility: str
    result_url: str
    api_url: str


@dataclass(frozen=True)
class URLScanResult:
    """Normalized URLScan intelligence."""

    scan_id: str
    url: str
    page_domain: str | None
    page_ip: str | None
    page_title: str | None
    page_status: int | str | None
    redirected: bool | None
    ips: tuple[str, ...]
    domains: tuple[str, ...]
    verdict_score: int | None
    categories: tuple[str, ...]
    result_url: str


class URLScanAnalyzer:
    """Submit URLs and retrieve URLScan.io intelligence."""

    def __init__(
        self,
        timeout: int | None = None,
        session: requests.Session | None = None,
    ):
        settings = get_settings()

        self.api_key = settings.urlscan_api_key
        self.timeout = (
            timeout if timeout is not None else settings.request_timeout
        )
        self.session = (
            session if session is not None else requests.Session()
        )

    def _get_headers(self) -> dict[str, str]:
        """Build authenticated request headers."""

        if not self.api_key:
            raise ValueError("URLScan API key is not configured")

        return {
            "API-Key": self.api_key.get_secret_value(),
            "Accept": "application/json",
        }

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate an HTTP or HTTPS URL."""

        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        url = url.strip()

        if not url or len(url) > 8192:
            raise ValueError("Invalid URL")

        # Reject whitespace and control characters anywhere in the URL.
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127
               for char in url):
            raise ValueError("URL contains invalid whitespace or characters")

        try:
            parsed = urlsplit(url)

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Invalid HTTP or HTTPS URL")

            # Accessing port validates its numeric range.
            _ = parsed.port

        except ValueError as exc:
            raise ValueError("Invalid URL format") from exc

        return url

    def _handle_response(
        self,
        response: requests.Response,
        *,
        result_request: bool = False,
    ) -> dict[str, Any]:
        """Validate HTTP status and decode the API response."""

        if response.status_code == 429:
            raise RuntimeError("URLScan rate limit exceeded")

        if response.status_code in (401, 403):
            raise RuntimeError("URLScan authentication failed")

        if result_request and response.status_code == 404:
            raise RuntimeError(
                "Scan result is not ready yet. Try again later."
            )

        if result_request and response.status_code == 410:
            raise RuntimeError("URLScan result has been deleted")

        try:
            response.raise_for_status()
            data = response.json()

        except requests.Timeout as exc:
            raise RuntimeError(
                "URLScan request timed out"
            ) from exc

        except ValueError as exc:
            raise RuntimeError(
                "URLScan returned invalid JSON"
            ) from exc

        except requests.RequestException as exc:
            raise RuntimeError(
                f"URLScan request failed: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError("Invalid URLScan response format")

        return data

    def submit_url(
        self,
        url: str,
        visibility: Literal["public", "unlisted", "private"] = "private",
        tags: list[str] | None = None,
        country: str | None = None,
    ) -> URLScanSubmission:
        """Submit a URL for scanning."""

        url = self._validate_url(url)

        if visibility not in {"public", "unlisted", "private"}:
            raise ValueError("Invalid scan visibility")

        if tags is not None:
            if (
                not isinstance(tags, list)
                or len(tags) > 10
                or any(
                    not isinstance(tag, str) or not tag.strip()
                    for tag in tags
                )
            ):
                raise ValueError("Invalid tags")

        if country is not None:
            if (
                not isinstance(country, str)
                or not re.fullmatch(r"[A-Za-z]{2}", country)
            ):
                raise ValueError(
                    "Country must be a two-letter ISO code"
                )

            country = country.lower()

        payload: dict[str, Any] = {
            "url": url,
            "visibility": visibility,
        }

        if tags:
            payload["tags"] = tags

        if country:
            payload["country"] = country

        try:
            response = self.session.post(
                f"{URLSCAN_BASE_URL}/scan/",
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout,
                allow_redirects=False,
            )

            data = self._handle_response(response)

        except requests.Timeout as exc:
            raise RuntimeError(
                "URLScan submission timed out"
            ) from exc

        except requests.RequestException as exc:
            raise RuntimeError(
                f"URLScan submission failed: {exc}"
            ) from exc

        scan_id = data.get("uuid")

        if not isinstance(scan_id, str):
            raise RuntimeError(
                "URLScan response is missing scan UUID"
            )

        try:
            scan_id = str(UUID(scan_id))
        except ValueError as exc:
            raise RuntimeError(
                "URLScan returned an invalid scan UUID"
            ) from exc

        returned_visibility = data.get("visibility", visibility)

        if not isinstance(returned_visibility, str):
            raise RuntimeError(
                "URLScan returned invalid visibility"
            )

        return URLScanSubmission(
            scan_id=scan_id,
            url=url,
            visibility=returned_visibility,
            result_url=f"https://urlscan.io/result/{scan_id}/",
            api_url=f"{URLSCAN_BASE_URL}/result/{scan_id}/",
        )

    def get_result(self, scan_id: str) -> URLScanResult:
        """Retrieve and normalize an existing scan result."""

        if not isinstance(scan_id, str):
            raise ValueError("Scan ID must be a string")

        try:
            scan_id = str(UUID(scan_id.strip()))
        except (ValueError, AttributeError) as exc:
            raise ValueError("Invalid scan UUID") from exc

        try:
            response = self.session.get(
                f"{URLSCAN_BASE_URL}/result/{scan_id}/",
                headers=self._get_headers(),
                timeout=self.timeout,
                allow_redirects=False,
            )

            data = self._handle_response(
                response,
                result_request=True,
            )

        except requests.Timeout as exc:
            raise RuntimeError(
                "URLScan request timed out"
            ) from exc

        except requests.RequestException as exc:
            raise RuntimeError(
                f"URLScan request failed: {exc}"
            ) from exc

        # Validate original structures before using them.
        # Do not use "or {}" here because it hides malformed values
        # such as empty lists, None, and other unexpected types.

        task = data.get("task", {})
        page = data.get("page", {})
        lists = data.get("lists", {})
        verdicts = data.get("verdicts", {})

        if not all(
            isinstance(item, dict)
            for item in (task, page, lists, verdicts)
        ):
            raise RuntimeError(
                "Invalid URLScan result structure"
            )

        urlscan_verdict = verdicts.get("urlscan", {})

        if not isinstance(urlscan_verdict, dict):
            raise RuntimeError(
                "Invalid URLScan verdict structure"
            )

        ips = lists.get("ips", [])
        domains = lists.get("domains", [])
        categories = urlscan_verdict.get("categories", [])

        def safe_tuple(value: Any) -> tuple[str, ...]:
            """Convert a list of strings into an immutable tuple."""

            if not isinstance(value, list):
                return ()

            return tuple(
                item for item in value
                if isinstance(item, str)
            )

        redirected = page.get("redirected")

        if redirected is not None and not isinstance(redirected, bool):
            redirected = None

        score = urlscan_verdict.get("score")

        if not isinstance(score, int) or isinstance(score, bool):
            score = None

        page_domain = page.get("domain")
        page_ip = page.get("ip")
        page_title = page.get("title")
        page_status = page.get("status")

        return URLScanResult(
            scan_id=scan_id,
            url=task.get("url") or page.get("url") or "",
            page_domain=(
                page_domain if isinstance(page_domain, str) else None
            ),
            page_ip=page_ip if isinstance(page_ip, str) else None,
            page_title=(
                page_title if isinstance(page_title, str) else None
            ),
            page_status=(
                page_status
                if isinstance(page_status, (int, str))
                and not isinstance(page_status, bool)
                else None
            ),
            redirected=redirected,
            ips=safe_tuple(ips),
            domains=safe_tuple(domains),
            verdict_score=score,
            categories=safe_tuple(categories),
            result_url=f"https://urlscan.io/result/{scan_id}/",
        )

    def close(self) -> None:
        """Close the HTTP session."""

        self.session.close()
