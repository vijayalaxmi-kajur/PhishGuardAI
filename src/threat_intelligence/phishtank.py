"""PhishGuardAI - PhishTank Threat Intelligence Provider

Queries the official PhishTank checkurl API to detect verified phishing URLs.
Documentation & Endpoint: https://checkurl.phishtank.com/checkurl/
"""

import os
import time
from typing import Dict, Any, Optional
import requests

from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatLookupResult,
    ThreatStatus,
    ThreatCategory,
)


class PhishTankProvider(BaseThreatProvider):
    """Integrates with the official PhishTank API."""

    DEFAULT_ENDPOINT: str = "https://checkurl.phishtank.com/checkurl/"
    DEFAULT_TIMEOUT_SEC: float = 3.0
    USER_AGENT: str = "phishtank/phishguardai-security-engine"

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        enabled: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Initialize PhishTank provider.
        
        Args:
            api_key: PhishTank developer app_key. If None, reads from PHISHTANK_API_KEY env var.
            endpoint: API endpoint URL.
            timeout: Request timeout in seconds.
            enabled: Whether this provider is enabled.
            session: Optional custom or mock requests.Session instance.
        """
        self._api_key = api_key or os.getenv("PHISHTANK_API_KEY")
        self._endpoint = endpoint or self.DEFAULT_ENDPOINT
        self._timeout = timeout
        self._enabled = enabled
        self._session = session or requests.Session()

    def get_provider_name(self) -> str:
        return "PhishTank"

    def is_enabled(self) -> bool:
        return self._enabled

    def check_url(self, url: str) -> ThreatLookupResult:
        """Check if URL exists in PhishTank database."""
        if not self._enabled:
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.UNAVAILABLE,
                error_message="Provider is disabled in configuration",
            )

        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.INVALID_INPUT,
                error_message="Target URL is empty or invalid",
            )

        payload = {
            "url": url.strip(),
            "format": "json",
        }
        if self._api_key:
            payload["app_key"] = self._api_key

        headers = {
            "User-Agent": self.USER_AGENT,
        }

        t0 = time.time()
        try:
            response = self._session.post(
                self._endpoint,
                data=payload,
                headers=headers,
                timeout=self._timeout,
            )
            latency_ms = (time.time() - t0) * 1000.0

            if response.status_code == 429:
                return ThreatLookupResult(
                    provider_name=self.get_provider_name(),
                    status=ThreatStatus.RATE_LIMITED,
                    error_message=f"Rate limit exceeded (HTTP 429)",
                    latency_ms=latency_ms,
                )

            if response.status_code in {500, 502, 503, 504}:
                return ThreatLookupResult(
                    provider_name=self.get_provider_name(),
                    status=ThreatStatus.UNAVAILABLE,
                    error_message=f"Service unavailable (HTTP {response.status_code})",
                    latency_ms=latency_ms,
                )

            if response.status_code != 200:
                return ThreatLookupResult(
                    provider_name=self.get_provider_name(),
                    status=ThreatStatus.ERROR,
                    error_message=f"Unexpected HTTP {response.status_code}: {response.text[:100]}",
                    latency_ms=latency_ms,
                )

            data = response.json()
            return self._parse_response(data, latency_ms)

        except requests.exceptions.Timeout:
            latency_ms = (time.time() - t0) * 1000.0
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.TIMEOUT,
                error_message=f"Request timed out after {self._timeout}s",
                latency_ms=latency_ms,
            )
        except requests.exceptions.ConnectionError as e:
            latency_ms = (time.time() - t0) * 1000.0
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.UNAVAILABLE,
                error_message=f"Connection failed: {str(e)[:100]}",
                latency_ms=latency_ms,
            )
        except ValueError as e:
            latency_ms = (time.time() - t0) * 1000.0
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.ERROR,
                error_message=f"Malformed JSON response: {str(e)[:100]}",
                latency_ms=latency_ms,
            )
        except Exception as e:
            latency_ms = (time.time() - t0) * 1000.0
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.ERROR,
                error_message=f"Unexpected error: {str(e)[:100]}",
                latency_ms=latency_ms,
            )

    def _parse_response(self, data: Dict[str, Any], latency_ms: float) -> ThreatLookupResult:
        """Parse JSON response from PhishTank API."""
        results = data.get("results")
        if not results or not isinstance(results, dict):
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.ERROR,
                error_message="Missing 'results' object in PhishTank response",
                latency_ms=latency_ms,
                details=data,
            )

        in_database = results.get("in_database", False)
        if not in_database:
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.NO_MATCH,
                is_threat=False,
                confidence=0.0,
                latency_ms=latency_ms,
                details={"in_database": False},
            )

        def _to_bool(val: Any) -> bool:
            if isinstance(val, str):
                return val.strip().lower() in {"true", "1", "y", "yes"}
            return bool(val)

        verified = _to_bool(results.get("verified", False))
        valid = _to_bool(results.get("valid", False))
        phish_id = results.get("phish_id")
        phish_detail_page = results.get("phish_detail_page")

        # In PhishTank, a phish is considered active/confirmed if verified is true and valid is true
        is_threat = verified and valid
        confidence = 1.0 if is_threat else (0.6 if in_database else 0.0)

        return ThreatLookupResult(
            provider_name=self.get_provider_name(),
            status=ThreatStatus.MATCHED,
            is_threat=is_threat,
            threat_category=ThreatCategory.PHISHING if is_threat else ThreatCategory.SUSPICIOUS,
            confidence=confidence,
            verified=verified,
            reference_url=phish_detail_page,
            details={
                "phish_id": phish_id,
                "verified": verified,
                "valid": valid,
                "verified_at": results.get("verified_at"),
            },
            latency_ms=latency_ms,
        )
