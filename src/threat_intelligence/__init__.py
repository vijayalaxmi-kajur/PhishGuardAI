"""PhishGuardAI - Threat Intelligence Subsystem

Exports data classes, status enums, and provider implementations for external
threat feeds (PhishTank, URLhaus).
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
from src.threat_intelligence.manager import ThreatIntelligenceManager

__all__ = [
    "BaseThreatProvider",
    "ThreatStatus",
    "ThreatCategory",
    "ThreatLookupResult",
    "MultiProviderLookupResult",
    "PhishTankProvider",
    "URLhausProvider",
    "ThreatIntelligenceManager",
]
