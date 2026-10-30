"""PhishGuardAI - Threat Intelligence Multi-Provider Manager

Coordinates multiple threat intelligence feeds, aggregates results, and ensures
that provider outages, timeouts, or rate limits never produce a false 'safe' verdict.
"""

from typing import List, Dict, Optional
from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatLookupResult,
    MultiProviderLookupResult,
    ThreatStatus,
)
from src.threat_intelligence.phishtank import PhishTankProvider
from src.threat_intelligence.urlhaus import URLhausProvider



class ThreatIntelligenceManager:
    """Manages concurrent/sequential execution of threat intelligence feeds."""

    def __init__(self, providers: Optional[List[BaseThreatProvider]] = None) -> None:
        """Initialize the manager with a list of providers.
        
        Args:
            providers: Optional list of instantiated providers.
                       If None, instantiates default PhishTank and URLhaus providers.
        """
        if providers is not None:
            self._providers = providers
        else:
            self._providers = [
                PhishTankProvider(),
                URLhausProvider(),
            ]

    def get_configured_providers(self) -> List[str]:
        """Return names of all configured providers."""
        return [p.get_provider_name() for p in self._providers]

    def check_url(self, url: str) -> MultiProviderLookupResult:
        """Query all enabled providers and aggregate results safely.
        
        Args:
            url: The raw URL to check.
            
        Returns:
            MultiProviderLookupResult containing findings, matched sources, and warning notes.
        """
        results: Dict[str, ThreatLookupResult] = {}
        matched_sources: List[str] = []
        available_providers: List[str] = []
        degraded_providers: List[str] = []
        warnings: List[str] = []

        is_any_threat = False

        for provider in self._providers:
            name = provider.get_provider_name()
            if not provider.is_enabled():
                continue

            res = provider.check_url(url)
            results[name] = res

            if res.is_degraded:
                degraded_providers.append(name)
                warnings.append(
                    f"{name} check was degraded ({res.status.value}: {res.error_message or 'no details'}). "
                    f"A missing intelligence match must NOT be interpreted as proof that a URL is legitimate."
                )
            else:
                available_providers.append(name)

            if res.status == ThreatStatus.MATCHED and res.is_threat:
                is_any_threat = True
                detail_str = f"{name} (Category: {res.threat_category.value if res.threat_category else 'malicious'}"
                if res.reference_url:
                    detail_str += f", ref: {res.reference_url}"
                detail_str += ")"
                matched_sources.append(detail_str)

        # Standard caveat reminder when no feeds matched
        if not is_any_threat:
            warnings.append(
                "No threat intelligence matches found. Note: Zero-day phishing campaigns and newly registered "
                "domains frequently evade active blocklist feeds during early attack hours."
            )

        return MultiProviderLookupResult(
            url=url,
            is_any_threat=is_any_threat,
            matched_sources=matched_sources,
            results=results,
            available_providers=available_providers,
            degraded_providers=degraded_providers,
            warnings=warnings,
        )
