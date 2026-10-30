"""PhishGuardAI - Threat Intelligence Base Abstractions

Defines the core data contracts, status enums, and base interface for external
threat intelligence providers (e.g. PhishTank, URLhaus).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class ThreatStatus(str, Enum):
    """Execution status of a threat intelligence query."""
    MATCHED = "matched"              # Successfully queried, confirmed in threat database
    NO_MATCH = "no_match"            # Successfully queried, NOT present in database
    TIMEOUT = "timeout"              # Request exceeded timeout limit
    UNAVAILABLE = "unavailable"      # Provider connection failure or host down
    RATE_LIMITED = "rate_limited"    # Exceeded provider rate limit (e.g. HTTP 429)
    INVALID_INPUT = "invalid_input"  # Provider rejected URL formatting
    ERROR = "error"                  # Unexpected server error or malformed payload


class ThreatCategory(str, Enum):
    """Categorization of verified malicious activity."""
    PHISHING = "phishing"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALWARE = "malware"
    BOTNET_C2 = "botnet_c2"
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class ThreatLookupResult:
    """Individual query result returned by a threat intelligence provider."""
    provider_name: str
    status: ThreatStatus
    is_threat: bool = False
    threat_category: Optional[ThreatCategory] = None
    confidence: float = 0.0
    verified: bool = False
    reference_url: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    latency_ms: float = 0.0

    @property
    def is_degraded(self) -> bool:
        """Indicates if provider failed or timed out during lookup."""
        return self.status in {
            ThreatStatus.TIMEOUT,
            ThreatStatus.UNAVAILABLE,
            ThreatStatus.RATE_LIMITED,
            ThreatStatus.ERROR,
        }


@dataclass
class MultiProviderLookupResult:
    """Consolidated findings across all queried threat intelligence providers."""
    url: str
    is_any_threat: bool
    matched_sources: List[str] = field(default_factory=list)
    results: Dict[str, ThreatLookupResult] = field(default_factory=dict)
    available_providers: List[str] = field(default_factory=list)
    degraded_providers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def has_degraded_providers(self) -> bool:
        """True if one or more configured providers failed to produce a valid response."""
        return len(self.degraded_providers) > 0


class BaseThreatProvider(ABC):
    """Abstract interface that all threat intelligence providers must implement."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the unique human-readable provider name."""
        pass

    @abstractmethod
    def check_url(self, url: str) -> ThreatLookupResult:
        """Check the target URL against the threat intelligence provider.
        
        Args:
            url: The raw URL to check.
            
        Returns:
            ThreatLookupResult containing the provider verdict and metadata.
            Must never throw uncaught networking exceptions.
        """
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether the provider is active and configured."""
        pass
