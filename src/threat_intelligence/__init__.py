"""PhishGuardAI - Threat Intelligence Subsystem

Exports data classes, status enums, provider implementations for external
threat feeds (PhishTank, URLhaus, OpenPhish), domain age telemetry, and whitelist registries.
"""

from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatStatus,
    ThreatCategory,
    ThreatLookupResult,
    MultiProviderLookupResult,
)
from src.threat_intelligence.phishtank import PhishTankProvider
from src.threat_intelligence.urlhaus import URLhausProvider
from src.threat_intelligence.openphish import OpenPhishProvider
from src.threat_intelligence.whois_checker import DomainAgeChecker, DomainAgeResult
from src.threat_intelligence.whitelist import VerifiedDomainWhitelist, WhitelistResult
from src.threat_intelligence.manager import ThreatIntelligenceManager

__all__ = [
    "BaseThreatProvider",
    "ThreatStatus",
    "ThreatCategory",
    "ThreatLookupResult",
    "MultiProviderLookupResult",
    "PhishTankProvider",
    "URLhausProvider",
    "OpenPhishProvider",
    "DomainAgeChecker",
    "DomainAgeResult",
    "VerifiedDomainWhitelist",
    "WhitelistResult",
    "ThreatIntelligenceManager",
]
