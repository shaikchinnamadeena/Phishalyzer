
"""WHOIS intelligence analyzer for Phishalyzer."""

from dataclasses import dataclass
from datetime import date, datetime
import re

import whois


@dataclass(frozen=True)
class WhoisAnalysis:
    """Immutable result of WHOIS analysis."""

    domain: str
    registrar: str | None
    creation_date: date | None
    expiration_date: date | None
    domain_age_days: int | None
    days_until_expiration: int | None
    errors: tuple[str, ...]


class WhoisAnalyzer:
    """Perform basic WHOIS domain intelligence checks."""

    @staticmethod
    def _normalize_date(value):
        """Convert WHOIS date values into date objects."""

        if isinstance(value, list):
            value = next(
                (item for item in value if item is not None),
                None
            )

        if isinstance(value, datetime):
            return value.date()

        if isinstance(value, date):
            return value

        return None

    def analyze(self, domain: str) -> WhoisAnalysis:
        """Retrieve and analyze WHOIS registration information."""

        # Step 1: Validate input
        if not isinstance(domain, str):
            raise ValueError("Domain must be a string")

        domain = domain.strip().lower().rstrip(".")

        if not domain:
            raise ValueError("Domain cannot be empty")

        if len(domain) > 253:
            raise ValueError("Invalid domain format")

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

        errors = []

        # Step 2: Perform WHOIS lookup
        try:
            result = whois.whois(domain)

            if not result:
                errors.append("No WHOIS information available")

                return WhoisAnalysis(
                    domain=domain,
                    registrar=None,
                    creation_date=None,
                    expiration_date=None,
                    domain_age_days=None,
                    days_until_expiration=None,
                    errors=tuple(errors)
                )

        except Exception as exc:
            errors.append(f"WHOIS lookup failed: {exc}")

            return WhoisAnalysis(
                domain=domain,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                domain_age_days=None,
                days_until_expiration=None,
                errors=tuple(errors)
            )

        # Step 3: Extract registrar
        registrar = result.get("registrar")

        if isinstance(registrar, list):
            registrar = next(
                (item for item in registrar if item),
                None
            )

        # Step 4: Extract registration dates
        creation_date = self._normalize_date(
            result.get("creation_date")
        )

        expiration_date = self._normalize_date(
            result.get("expiration_date")
        )

        # Step 5: Calculate domain age
        today = date.today()

        domain_age_days = None
        days_until_expiration = None

        if creation_date:
            domain_age_days = (
                today - creation_date
            ).days

            if domain_age_days < 0:
                errors.append(
                    "Creation date is in the future"
                )
                domain_age_days = None

        # Step 6: Calculate remaining registration period
        if expiration_date:
            days_until_expiration = (
                expiration_date - today
            ).days

        # Step 7: Return analysis
        return WhoisAnalysis(
            domain=domain,
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            domain_age_days=domain_age_days,
            days_until_expiration=days_until_expiration,
            errors=tuple(errors)
        )
