"""PhishGuardAI - Domain Age & Registration Telemetry (RDAP / WHOIS)

Provides real-time domain age intelligence to detect newly registered domains (< 14 days old),
which correlate heavily with zero-day phishing campaigns and ephemeral attack infrastructure.
Operates via low-latency HTTP RDAP with graceful timeout handling and an in-memory TTL cache.
"""

import time
import datetime
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple
import requests
import tldextract

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


@dataclass
class DomainAgeResult:
    """Telemetry report for domain age and registration metadata."""
    domain: str
    registered_domain: str
    creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_new_domain: bool = False       # Age < 14 days (Severe threat indicator)
    is_recent_domain: bool = False    # Age < 30 days (Elevated threat indicator)
    registrar: Optional[str] = None
    is_cached: bool = False
    source: str = "rdap"
    error_message: Optional[str] = None
    query_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "domain": self.domain,
            "registered_domain": self.registered_domain,
            "creation_date": self.creation_date,
            "domain_age_days": self.domain_age_days,
            "is_new_domain": self.is_new_domain,
            "is_recent_domain": self.is_recent_domain,
            "registrar": self.registrar,
            "is_cached": self.is_cached,
            "source": self.source,
            "error_message": self.error_message,
            "query_latency_ms": self.query_latency_ms,
        }


class DomainAgeChecker:
    """Checks domain registration age via RDAP with caching and fail-safe error handling."""

    RDAP_BOOTSTRAP_URL: str = "https://rdap.org/domain/{domain}"
    DEFAULT_TIMEOUT_SEC: float = 2.5
    DEFAULT_CACHE_TTL_SEC: int = 86400  # 24 hours
    NEW_DOMAIN_THRESHOLD_DAYS: int = 14
    RECENT_DOMAIN_THRESHOLD_DAYS: int = 30

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        cache_ttl: int = DEFAULT_CACHE_TTL_SEC,
        session: Optional[requests.Session] = None,
        mock_handler: Optional[Any] = None,
    ) -> None:
        """Initialize domain age checker.
        
        Args:
            timeout: HTTP request timeout in seconds.
            cache_ttl: In-memory cache time-to-live in seconds.
            session: Optional custom requests.Session.
            mock_handler: Optional callable(registered_domain) -> DomainAgeResult for offline testing.
        """
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._session = session or requests.Session()
        self._mock_handler = mock_handler
        self._cache: Dict[str, Tuple[DomainAgeResult, float]] = {}

    def extract_registered_domain(self, target: str) -> str:
        """Extract the root registered domain (e.g. 'google.com' from 'https://sub.google.com/path')."""
        target_str = str(target or "").strip()
        if not target_str:
            return ""

        if "://" not in target_str and not target_str.startswith("//"):
            target_str = f"http://{target_str}"

        try:
            parsed = urllib.parse.urlsplit(target_str)
            host = parsed.netloc.split(":")[0].strip().lower()
        except Exception:
            host = target_str.split("/")[0].split(":")[0].strip().lower()

        ext = _TLD_EXTRACTOR(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return host

    def get_domain_age(self, target: str) -> DomainAgeResult:
        """Query registration age for a URL or hostname.
        
        Args:
            target: Full URL or raw hostname.
            
        Returns:
            DomainAgeResult containing age in days, flags, and error info if degraded.
        """
        start_time = time.time()
        registered_domain = self.extract_registered_domain(target)

        if not registered_domain:
            return DomainAgeResult(
                domain=str(target),
                registered_domain="",
                error_message="Invalid target or hostname could not be determined.",
                query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
            )

        # 1. Check in-memory cache
        now = time.time()
        if registered_domain in self._cache:
            cached_result, timestamp = self._cache[registered_domain]
            if now - timestamp < self._cache_ttl:
                # Return cached copy with cached flag
                return DomainAgeResult(
                    domain=str(target),
                    registered_domain=registered_domain,
                    creation_date=cached_result.creation_date,
                    domain_age_days=cached_result.domain_age_days,
                    is_new_domain=cached_result.is_new_domain,
                    is_recent_domain=cached_result.is_recent_domain,
                    registrar=cached_result.registrar,
                    is_cached=True,
                    source="cache",
                    error_message=cached_result.error_message,
                    query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
                )

        # 2. Check offline/mock handler if provided
        if self._mock_handler is not None:
            res = self._mock_handler(registered_domain)
            res.domain = str(target)
            res.registered_domain = registered_domain
            res.query_latency_ms = round((time.time() - start_time) * 1000.0, 2)
            self._cache[registered_domain] = (res, now)
            return res

        # 3. Query RDAP over HTTPS
        endpoint = self.RDAP_BOOTSTRAP_URL.format(domain=registered_domain)
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "PhishGuardAI-ThreatIntel/2.0 (DomainAgeInspector)",
        }

        try:
            resp = self._session.get(endpoint, headers=headers, timeout=self._timeout)
            if resp.status_code == 404:
                result = DomainAgeResult(
                    domain=str(target),
                    registered_domain=registered_domain,
                    error_message=f"Domain '{registered_domain}' not found in RDAP registry (may be unregistered or private).",
                    query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
                )
                self._cache[registered_domain] = (result, now)
                return result

            if resp.status_code != 200:
                return DomainAgeResult(
                    domain=str(target),
                    registered_domain=registered_domain,
                    error_message=f"RDAP query returned HTTP status {resp.status_code}.",
                    query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
                )

            data = resp.json()
            creation_str, registrar_name = self._parse_rdap_payload(data)

            if not creation_str:
                result = DomainAgeResult(
                    domain=str(target),
                    registered_domain=registered_domain,
                    registrar=registrar_name,
                    error_message="RDAP record found but registration creation event date was omitted.",
                    query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
                )
                self._cache[registered_domain] = (result, now)
                return result

            age_days = self._calculate_age_days(creation_str)
            is_new = (age_days is not None) and (age_days < self.NEW_DOMAIN_THRESHOLD_DAYS)
            is_recent = (age_days is not None) and (age_days < self.RECENT_DOMAIN_THRESHOLD_DAYS)

            result = DomainAgeResult(
                domain=str(target),
                registered_domain=registered_domain,
                creation_date=creation_str,
                domain_age_days=age_days,
                is_new_domain=is_new,
                is_recent_domain=is_recent,
                registrar=registrar_name,
                source="rdap",
                query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
            )
            self._cache[registered_domain] = (result, now)
            return result

        except requests.Timeout:
            return DomainAgeResult(
                domain=str(target),
                registered_domain=registered_domain,
                error_message=f"RDAP lookup timed out after {self._timeout}s.",
                query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
            )
        except Exception as e:
            return DomainAgeResult(
                domain=str(target),
                registered_domain=registered_domain,
                error_message=f"RDAP query failed: {str(e)[:100]}",
                query_latency_ms=round((time.time() - start_time) * 1000.0, 2),
            )

    def _parse_rdap_payload(self, data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract registration date and registrar from RDAP response JSON."""
        creation_str = None
        registrar_name = None

        # 1. Parse Events (Registration / Creation Date)
        events = data.get("events", [])
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict):
                    action = ev.get("eventAction", "").lower()
                    if action in {"registration", "created", "creation"}:
                        creation_str = ev.get("eventDate")
                        break

        # 2. Parse Registrar Entity
        entities = data.get("entities", [])
        if isinstance(entities, list):
            for ent in entities:
                if isinstance(ent, dict):
                    roles = ent.get("roles", [])
                    if isinstance(roles, list) and "registrar" in [r.lower() for r in roles]:
                        vcard = ent.get("vcardArray", [])
                        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if isinstance(prop, list) and len(prop) > 3 and prop[0].lower() == "fn":
                                    registrar_name = str(prop[3])
                                    break
                        if not registrar_name:
                            registrar_name = ent.get("handle")

        return creation_str, registrar_name

    def _calculate_age_days(self, date_str: str) -> Optional[int]:
        """Parse ISO-8601 creation string and compute day difference from now (UTC)."""
        if not date_str:
            return None

        clean_date = date_str.strip()
        # Normalise trailing 'Z'
        if clean_date.endswith("Z"):
            clean_date = clean_date[:-1] + "+00:00"

        try:
            # Handle ISO formats
            parsed_dt = datetime.datetime.fromisoformat(clean_date)
            # Make sure it's timezone-aware UTC
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
            else:
                parsed_dt = parsed_dt.astimezone(datetime.timezone.utc)

            now_utc = datetime.datetime.now(datetime.timezone.utc)
            delta = now_utc - parsed_dt
            return max(0, delta.days)
        except Exception:
            return None
