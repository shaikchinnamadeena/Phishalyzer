
"""IP address intelligence analyzer for Phishalyzer."""

from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True)
class IPAnalysis:
    ip_address: str
    is_valid: bool
    version: int
    is_private: bool
    is_public: bool
    is_loopback: bool
    is_reserved: bool
    is_multicast: bool
    is_link_local: bool
    errors: tuple[str, ...]


class IPAnalyzer:
    """Perform safe IP address classification."""

    def analyze(self, ip_address: str) -> IPAnalysis:
        if not isinstance(ip_address, str):
            raise ValueError("IP address must be a string")

        ip_address = ip_address.strip()

        if not ip_address:
            raise ValueError("IP address cannot be empty")

        try:
            address = ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc

        return IPAnalysis(
            ip_address=str(address),
            is_valid=True,
            version=address.version,
            is_private=address.is_private,
            is_public=address.is_global,
            is_loopback=address.is_loopback,
            is_reserved=address.is_reserved,
            is_multicast=address.is_multicast,
            is_link_local=address.is_link_local,
            errors=()
        )
