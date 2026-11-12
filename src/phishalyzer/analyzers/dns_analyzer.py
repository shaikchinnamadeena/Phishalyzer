
"""DNS record analysis module for Phishalyzer."""

from dataclasses import dataclass, field

import dns.exception
import dns.resolver


@dataclass(frozen=True)
class DNSAnalysis:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: tuple = ()


class DNSAnalyzer:
    """Retrieve common DNS records for a domain."""

    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

    def __init__(self, timeout: float = 5.0):
        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        self.timeout = timeout

    def analyze(self, domain: str) -> DNSAnalysis:
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("A valid domain is required.")

        domain = domain.strip().lower().rstrip(".")

        if "/" in domain or " " in domain or "://" in domain:
            raise ValueError("Provide a domain name, not a URL.")

        records = {}
        errors = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(
                    domain,
                    record_type,
                    raise_on_no_answer=False
                )

                if answers.rrset is None:
                    records[record_type] = []
                else:
                    records[record_type] = [
                        answer.to_text() for answer in answers
                    ]

            except dns.resolver.NXDOMAIN:
                errors.append("Domain does not exist.")
                break

            except dns.resolver.NoNameservers:
                errors.append(
                    f"No nameservers available for {record_type}."
                )
                records[record_type] = []

            except dns.resolver.NoAnswer:
                records[record_type] = []

            except dns.exception.Timeout:
                errors.append(f"DNS timeout for {record_type}.")
                records[record_type] = []

            except dns.exception.DNSException as exc:
                errors.append(f"{record_type}: {exc}")
                records[record_type] = []

        return DNSAnalysis(
            domain=domain,
            records=records,
            errors=tuple(errors)
        )
