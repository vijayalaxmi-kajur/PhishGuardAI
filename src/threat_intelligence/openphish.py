"""PhishGuardAI - OpenPhish Community Threat Intelligence Provider

Queries the OpenPhish community feed to detect verified zero-hour phishing URLs.
OpenPhish Community Feed: https://openphish.com/feed.txt
"""

import os
import time
from typing import Dict, Any, Optional, Set
import requests

from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatLookupResult,
    ThreatStatus,
    ThreatCategory,
)


class OpenPhishProvider(BaseThreatProvider):
    """Integrates with OpenPhish live active feed with local synchronization."""

    FEED_URL: str = "https://openphish.com/feed.txt"
    DEFAULT_TIMEOUT_SEC: float = 3.0
    DEFAULT_SYNC_INTERVAL_SEC: int = 1800  # 30 minutes
    USER_AGENT: str = "openphish/phishguardai-security-engine"

    def __init__(
        self,
        feed_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        sync_interval: int = DEFAULT_SYNC_INTERVAL_SEC,
        enabled: bool = True,
        session: Optional[requests.Session] = None,
        initial_cache: Optional[Set[str]] = None,
    ) -> None:
        """Initialize OpenPhish provider.
        
        Args:
            feed_url: Feed URL endpoint (defaults to official community feed).
            timeout: Request timeout in seconds.
            sync_interval: Minimum seconds between feed updates.
            enabled: Whether this provider is active.
            session: Optional custom or mock requests.Session.
            initial_cache: Optional pre-populated set of malicious URLs.
        """
        self._feed_url = feed_url or self.FEED_URL
        self._timeout = timeout
        self._sync_interval = sync_interval
        self._enabled = enabled
        self._session = session or requests.Session()
        self._feed_cache: Set[str] = initial_cache or set()
        self._last_sync_time: float = time.time() if initial_cache else 0.0

    def get_provider_name(self) -> str:
        return "OpenPhish"

    def is_enabled(self) -> bool:
        return self._enabled

    def sync_feed(self) -> bool:
        """Fetch the latest active phishing URLs into local memory."""
        if not self._enabled:
            return False

        headers = {"User-Agent": self.USER_AGENT}
        try:
            resp = self._session.get(self._feed_url, headers=headers, timeout=self._timeout)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                urls = {line.strip() for line in lines if line.strip() and not line.startswith("#")}
                self._feed_cache = urls
                self._last_sync_time = time.time()
                return True
            return False
        except Exception:
            return False

    def check_url(self, url: str) -> ThreatLookupResult:
        """Check if target URL exists in OpenPhish active phishing database."""
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

        clean_url = url.strip()
        t0 = time.time()

        # Check if feed sync is due
        now = time.time()
        if (now - self._last_sync_time > self._sync_interval) and not self._feed_cache:
            self.sync_feed()

        # Exact match or normalized check
        is_hit = clean_url in self._feed_cache
        if not is_hit:
            # Check without trailing slash or with trailing slash
            alt = clean_url[:-1] if clean_url.endswith("/") else f"{clean_url}/"
            is_hit = alt in self._feed_cache

        latency = round((time.time() - t0) * 1000.0, 2)

        if is_hit:
            return ThreatLookupResult(
                provider_name=self.get_provider_name(),
                status=ThreatStatus.MATCHED,
                is_threat=True,
                threat_category=ThreatCategory.PHISHING,
                confidence=0.99,
                verified=True,
                reference_url="https://openphish.com",
                details={"source": "openphish_community_feed"},
                latency_ms=latency,
            )

        return ThreatLookupResult(
            provider_name=self.get_provider_name(),
            status=ThreatStatus.NO_MATCH,
            is_threat=False,
            latency_ms=latency,
        )

