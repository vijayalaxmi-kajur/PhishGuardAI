"""PhishGuardAI - URLhaus Threat Intelligence Provider

Queries the abuse.ch URLhaus API to detect verified malware distribution and
threat delivery URLs.
Documentation & Endpoint: https://urlhaus-api.abuse.ch/v1/url/
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


class URLhausProvider(BaseThreatProvider):
    """Integrates with the official abuse.ch URLhaus API."""

    DEFAULT_ENDPOINT: str = "https://urlhaus-api.abuse.ch/v1/url/"
    DEFAULT_TIMEOUT_SEC: float = 3.0
    USER_AGENT: str = "urlhaus/phishguardai-security-engine"

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        enabled: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Initialize URLhaus provider.
        
        Args:
            api_key: Optional abuse.ch Auth-Key. If None, reads from URLHAUS_API_KEY env var.
            endpoint: API endpoint URL.
            timeout: Request timeout in seconds.
            enabled: Whether this provider is enabled.
            session: Optional custom or mock requests.Session instance.
        """
        self._api_key = api_key or os.getenv("URLHAUS_API_KEY")
        self._endpoint = endpoint or self.DEFAULT_ENDPOINT
        self._timeout = timeout
        self._enabled = enabled
        self._session = session or requests.Session()

    def get_provider_name(self) -> str:
        return "URLhaus"

    def is_enabled(self) -> bool:
        return self._enabled

    def check_url(self, url: str) -> ThreatLookupResult:
        """Check if URL exists in abuse.ch URLhaus database."""
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

        payload = {"url": url.strip()}
        headers = {
            "User-Agent": self.USER_AGENT,
        }
        if self._api_key:
            headers["Auth-Key"] = self._api_key

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
                    error_message="Rate limit exceeded (HTTP 429)",
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
        """Parse JSON response from URLhaus API."""
        query_status = data.get("query_status", "").lower()

        if query_status == "no_results":
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.NO_MATCH,
                is_threat=False,
                confidence=0.0,
                latency_ms=latency_ms,
                details={"query_status": "no_results"},
            )

        if query_status == "invalid_url":
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.INVALID_INPUT,
                error_message="URLhaus reported the URL syntax is invalid",
                latency_ms=latency_ms,
                details=data,
            )

        if query_status == "ok":
            url_status = data.get("url_status", "unknown").lower()
            threat = data.get("threat", "malware_download").lower()
            tags = data.get("tags") or []
            urlhaus_id = data.get("id")

            # Map category
            if "phish" in threat or "phish" in [t.lower() for t in tags]:
                cat = ThreatCategory.PHISHING
            elif "botnet" in threat or "c2" in [t.lower() for t in tags]:
                cat = ThreatCategory.BOTNET_C2
            else:
                cat = ThreatCategory.MALWARE

            # URL is an active threat
            is_threat = True
            confidence = 1.0 if url_status == "online" else 0.85
            ref_url = f"https://urlhaus.abuse.ch/url/{urlhaus_id}/" if urlhaus_id else None

            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.MATCHED,
                is_threat=is_threat,
                threat_category=cat,
                confidence=confidence,
                verified=True,
                reference_url=ref_url,
                details={
                    "urlhaus_id": urlhaus_id,
                    "url_status": url_status,
                    "threat": threat,
                    "tags": tags,
                    "reporter": data.get("reporter"),
                    "date_added": data.get("date_added"),
                },
                latency_ms=latency_ms,
            )

        return ThreatLookupResult(
            provider_name=self.get_provider_name(),
            status=ThreatStatus.ERROR,
            error_message=f"Unrecognized query_status: '{query_status}'",
            latency_ms=latency_ms,
            details=data,
        )
