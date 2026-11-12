
"""Domain intelligence analyzer for Phishalyzer."""

import ipaddress
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class DomainAnalysis:
    """Immutable result of domain analysis."""

    domain: str
    is_valid: bool
    ip_addresses: tuple[str, ...]
    has_dns_records: bool
    is_ip_address: bool
    errors: tuple[str, ...]


class DomainAnalyzer:
    """Perform basic, safe domain intelligence checks."""

    def analyze(self, domain: str) -> DomainAnalysis:
        """Validate a domain and perform DNS resolution."""

        # Step 1: Validate input type
        if not isinstance(domain, str):
            raise ValueError("Domain must be a string")

        # Step 2: Normalize domain
        domain = domain.strip().lower().rstrip(".")
        errors = []

        if not domain:
            raise ValueError("Domain cannot be empty")

        if len(domain) > 253 or any(
            char.isspace() for char in domain
        ):
            raise ValueError("Invalid domain format")

        # Step 3: Check IP address
        try:
            ipaddress.ip_address(domain)

            return DomainAnalysis(
                domain=domain,
                is_valid=True,
                ip_addresses=(domain,),
                has_dns_records=False,
                is_ip_address=True,
                errors=()
            )

        except ValueError:
            pass

        # Step 4: Validate domain labels
        labels = domain.split(".")

        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                char.isalnum() or char == "-"
                for char in label
            )
            for label in labels
        ):
            raise ValueError("Invalid domain format")

        # Step 5: Perform DNS lookup
        try:
            results = socket.getaddrinfo(
                domain,
                None,
                type=socket.SOCK_STREAM
            )

            addresses = tuple(sorted({
                result[4][0]
                for result in results
            }))

        except (socket.gaierror, OSError) as exc:
            addresses = ()
            errors.append(f"DNS lookup failed: {exc}")

        # Step 6: Return analysis result
        return DomainAnalysis(
            domain=domain,
            is_valid=True,
            ip_addresses=addresses,
            has_dns_records=bool(addresses),
            is_ip_address=False,
            errors=tuple(errors)
        )
