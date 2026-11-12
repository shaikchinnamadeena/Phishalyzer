
"""Secure URL parsing and structural analysis."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

URL_SHORTENERS = frozenset({
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
})

SUSPICIOUS_KEYWORDS = frozenset({
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "banking",
    "wallet",
})

ALLOWED_SCHEMES = frozenset({"http", "https"})

MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class ParsedURL:
    """Immutable representation of parsed URL intelligence."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    is_ip_address: bool
    is_shortened: bool
    has_punycode: bool
    suspicious_keywords: tuple[str, ...]


def _normalize_hostname(hostname: str) -> str:
    """Normalize hostname using IDNA and lowercase conversion."""

    return hostname.rstrip(".").encode("idna").decode("ascii").lower()


def _validate_hostname(hostname: str) -> bool:
    """Validate a DNS hostname."""

    if not hostname or len(hostname) > 253:
        return False

    labels = hostname.split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
        ):
            return False

    return True


def parse_url(raw_url: str) -> ParsedURL:
    """
    Parse a URL and extract structural security indicators.

    This function does not resolve DNS, follow redirects,
    establish network connections, or determine whether
    a URL is definitively malicious.
    """

    if not isinstance(raw_url, str):
        raise TypeError("URL must be a string.")

    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("URL cannot be empty.")

    if len(raw_url) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds the maximum supported length.")

    if any(ord(char) < 32 or ord(char) == 127 for char in raw_url):
        raise ValueError("URL contains control characters.")

    if any(char.isspace() for char in raw_url):
        raise ValueError("URL contains whitespace.")

    if "\\" in raw_url:
        raise ValueError("URL contains invalid backslash characters.")

    if raw_url.startswith("//"):
        raise ValueError("Protocol-relative URLs are not accepted.")

    candidate = (
        raw_url
        if "://" in raw_url
        else f"https://{raw_url}"
    )

    try:
        parts = urlsplit(candidate)

        scheme = parts.scheme.lower()

        if scheme not in ALLOWED_SCHEMES:
            raise ValueError(
                "Only HTTP and HTTPS URLs are supported."
            )

        if not parts.netloc or not parts.hostname:
            raise ValueError("URL must contain a valid hostname.")

        if parts.username is not None or parts.password is not None:
            raise ValueError(
                "URLs containing embedded credentials are rejected."
            )

        port = parts.port
        hostname = _normalize_hostname(parts.hostname)

        if not hostname:
            raise ValueError("Hostname cannot be empty.")

        # Validate IP addresses separately from DNS hostnames.
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True

        except ValueError:
            is_ip_address = False

        # Apply DNS hostname validation only to domain names.
        if not is_ip_address and not _validate_hostname(hostname):
            raise ValueError("Invalid hostname format.") from None

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid port.")

        # Preserve explicitly supplied ports during normalization.
        host_for_url = (
            f"[{hostname}]" if ":" in hostname else hostname
        )

        netloc = host_for_url

        if port is not None:
            netloc = f"{netloc}:{port}"

        path = parts.path or "/"

        normalized_url = urlunsplit(
            (
                scheme,
                netloc,
                path,
                parts.query,
                "",
            )
        )

        # Identify suspicious keywords in path and query.
        searchable_content = (
            f"{path} {parts.query}"
        ).lower()

        suspicious_keywords = tuple(
            sorted(
                keyword
                for keyword in SUSPICIOUS_KEYWORDS
                if keyword in searchable_content
            )
        )

        # Identify URL shorteners using exact hostname matching.
        is_shortened = hostname in URL_SHORTENERS

        # Identify internationalized domains represented as Punycode.
        has_punycode = any(
            label.startswith("xn--")
            for label in hostname.split(".")
        )

        return ParsedURL(
            original_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=parts.query,
            is_ip_address=is_ip_address,
            is_shortened=is_shortened,
            has_punycode=has_punycode,
            suspicious_keywords=suspicious_keywords,
        )

    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc
