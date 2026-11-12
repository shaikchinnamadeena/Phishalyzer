
"""Central analysis orchestrator for Phishalyzer."""

from dataclasses import dataclass, replace

from phishalyzer.analyzers.dns_analyzer import DNSAnalysis, DNSAnalyzer
from phishalyzer.analyzers.domain_analyzer import (
    DomainAnalysis,
    DomainAnalyzer,
)
from phishalyzer.analyzers.ip_analyzer import IPAnalysis, IPAnalyzer
from phishalyzer.analyzers.whois_analyzer import (
    WhoisAnalysis,
    WhoisAnalyzer,
)
from phishalyzer.core.risk_scoring import (
    RiskAssessment,
    RiskScoringEngine,
)
from phishalyzer.integrations.urlscan import (
    URLScanAnalyzer,
    URLScanResult,
    URLScanSubmission,
)
from phishalyzer.integrations.virustotal import (
    VirusTotalAnalyzer,
    VirusTotalResult,
)
from phishalyzer.utils.url_parser import ParsedURL, parse_url


@dataclass(frozen=True)
class AnalysisResult:
    """Combined result of a Phishalyzer investigation."""

    parsed_url: ParsedURL
    domain: DomainAnalysis | None
    dns: DNSAnalysis | None
    ip: tuple[IPAnalysis, ...]
    whois: WhoisAnalysis | None
    virustotal: VirusTotalResult | None
    urlscan_submission: URLScanSubmission | None
    urlscan: URLScanResult | None
    risk: RiskAssessment
    warnings: tuple[str, ...]
    collection_warnings: tuple[str, ...]


class AnalysisEngine:
    """Coordinate analyzers and produce a combined investigation result."""

    def __init__(
        self,
        domain_analyzer: DomainAnalyzer | None = None,
        dns_analyzer: DNSAnalyzer | None = None,
        ip_analyzer: IPAnalyzer | None = None,
        whois_analyzer: WhoisAnalyzer | None = None,
        virustotal_analyzer: VirusTotalAnalyzer | None = None,
        urlscan_analyzer: URLScanAnalyzer | None = None,
        risk_engine: RiskScoringEngine | None = None,
    ) -> None:
        """Initialize analyzers, allowing dependencies to be injected."""

        self.domain_analyzer = (
            domain_analyzer if domain_analyzer is not None else DomainAnalyzer()
        )
        self.dns_analyzer = (
            dns_analyzer if dns_analyzer is not None else DNSAnalyzer()
        )
        self.ip_analyzer = (
            ip_analyzer if ip_analyzer is not None else IPAnalyzer()
        )
        self.whois_analyzer = (
            whois_analyzer if whois_analyzer is not None else WhoisAnalyzer()
        )
        self.virustotal_analyzer = (
            virustotal_analyzer
            if virustotal_analyzer is not None
            else VirusTotalAnalyzer()
        )
        self.urlscan_analyzer = (
            urlscan_analyzer
            if urlscan_analyzer is not None
            else URLScanAnalyzer()
        )
        self.risk_engine = (
            risk_engine if risk_engine is not None else RiskScoringEngine()
        )

    @staticmethod
    def _warning(source: str, exc: Exception) -> str:
        """Create a consistent warning without exposing credentials."""

        return f"{source} analysis unavailable: {exc}"

    def _calculate_risk(
        self,
        parsed_url: ParsedURL,
        virustotal: VirusTotalResult | None,
        whois: WhoisAnalysis | None,
        urlscan: URLScanResult | None,
        dns: DNSAnalysis | None,
        ip: tuple[IPAnalysis, ...],
    ) -> RiskAssessment:
        """Calculate risk from the evidence collected so far."""

        return self.risk_engine.analyze(
            parsed_url=parsed_url,
            virustotal=virustotal,
            whois=whois,
            urlscan=urlscan,
            dns=dns,
            ip=ip[0] if ip else None,
        )

    def analyze(
        self,
        url: str,
        *,
        enable_urlscan: bool = False,
    ) -> AnalysisResult:
        """
        Analyze a URL and return combined intelligence.

        URLScan submission is opt-in. Submission sends the URL to an
        external service, so callers must obtain user consent first.

        The URLScan result is not retrieved immediately. The submission
        and scan ID are returned so the result can be checked later.
        """

        parsed_url = parse_url(url)
        hostname = parsed_url.hostname

        collection_warnings: list[str] = []

        domain_result: DomainAnalysis | None = None
        dns_result: DNSAnalysis | None = None
        whois_result: WhoisAnalysis | None = None
        virustotal_result: VirusTotalResult | None = None
        urlscan_submission: URLScanSubmission | None = None
        urlscan_result: URLScanResult | None = None
        ip_results: list[IPAnalysis] = []

        # Domain analysis
        try:
            domain_result = self.domain_analyzer.analyze(hostname)
        except Exception as exc:
            collection_warnings.append(self._warning("Domain", exc))

        # DNS and WHOIS are not applicable to IP-address hostnames.
        if not parsed_url.is_ip_address:
            try:
                dns_result = self.dns_analyzer.analyze(hostname)
            except Exception as exc:
                collection_warnings.append(self._warning("DNS", exc))

            try:
                whois_result = self.whois_analyzer.analyze(hostname)
            except Exception as exc:
                collection_warnings.append(self._warning("WHOIS", exc))

        # Analyze the literal IP or IP addresses resolved for the domain.
        candidate_ips = (
            (hostname,)
            if parsed_url.is_ip_address
            else (
                domain_result.ip_addresses
                if domain_result is not None
                else ()
            )
        )

        for address in dict.fromkeys(candidate_ips):
            try:
                ip_results.append(self.ip_analyzer.analyze(address))
            except Exception as exc:
                collection_warnings.append(
                    self._warning(f"IP ({address})", exc)
                )

        # VirusTotal lookup
        try:
            virustotal_result = self.virustotal_analyzer.analyze_url(
                parsed_url.normalized_url
            )
        except Exception as exc:
            collection_warnings.append(self._warning("VirusTotal", exc))

        # URLScan submission is opt-in. Do not assume the scan is ready.
        if enable_urlscan:
            try:
                urlscan_submission = self.urlscan_analyzer.submit_url(
                    parsed_url.normalized_url,
                    visibility="private",
                )
            except Exception as exc:
                collection_warnings.append(self._warning("URLScan", exc))

        ip_tuple = tuple(ip_results)

        try:
            risk_result = self._calculate_risk(
                parsed_url,
                virustotal_result,
                whois_result,
                urlscan_result,
                dns_result,
                ip_tuple,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Risk assessment could not be completed: {exc}"
            ) from exc

        warnings = tuple(
            dict.fromkeys(
                collection_warnings + list(risk_result.warnings)
            )
        )

        return AnalysisResult(
            parsed_url=parsed_url,
            domain=domain_result,
            dns=dns_result,
            ip=ip_tuple,
            whois=whois_result,
            virustotal=virustotal_result,
            urlscan_submission=urlscan_submission,
            urlscan=urlscan_result,
            risk=risk_result,
            warnings=warnings,
            collection_warnings=tuple(collection_warnings),
        )

    def complete_urlscan(
        self,
        result: AnalysisResult,
    ) -> AnalysisResult:
        """
        Retrieve a previously submitted URLScan result and update risk.

        If URLScan has not finished processing, the original investigation
        is retained and a retrieval warning is returned. Call this method
        again later using the returned AnalysisResult.
        """

        if result.urlscan_submission is None:
            return result

        if result.urlscan is not None:
            return result

        try:
            urlscan_result = self.urlscan_analyzer.get_result(
                result.urlscan_submission.scan_id
            )
        except Exception as exc:
            try:
                risk_result = self._calculate_risk(
                    result.parsed_url,
                    result.virustotal,
                    result.whois,
                    None,
                    result.dns,
                    result.ip,
                )
            except Exception as scoring_exc:
                raise RuntimeError(
                    "Risk assessment could not be completed: "
                    f"{scoring_exc}"
                ) from scoring_exc

            retrieval_warning = (
                "URLScan result is not available yet or retrieval failed: "
                f"{exc}"
            )

            warnings = tuple(
                dict.fromkeys(
                    list(result.collection_warnings)
                    + [retrieval_warning]
                    + list(risk_result.warnings)
                )
            )

            return replace(
                result,
                urlscan=None,
                risk=risk_result,
                warnings=warnings,
            )

        try:
            risk_result = self._calculate_risk(
                result.parsed_url,
                result.virustotal,
                result.whois,
                urlscan_result,
                result.dns,
                result.ip,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Risk assessment could not be completed: {exc}"
            ) from exc

        warnings = tuple(
            dict.fromkeys(
                list(result.collection_warnings)
                + list(risk_result.warnings)
            )
        )

        return replace(
            result,
            urlscan=urlscan_result,
            risk=risk_result,
            warnings=warnings,
        )

    def close(self) -> None:
        """Close external analyzer sessions and report cleanup failures."""

        errors: list[Exception] = []

        for analyzer in (
            self.virustotal_analyzer,
            self.urlscan_analyzer,
        ):
            try:
                analyzer.close()
            except Exception as exc:
                errors.append(exc)

        if errors:
            raise RuntimeError(
                f"Failed to close {len(errors)} analyzer session(s)."
            ) from errors[0]
