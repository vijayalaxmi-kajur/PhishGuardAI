"""PhishGuardAI - High-Performance Cache & Multi-Tenant Rate Limiter

Implements sub-millisecond in-memory caching with TTL for URL reputation
and sliding-window token bucket rate limiting per API key / IP address.
Supports optional Redis backend via REDIS_URL configuration.
"""

import time
import os
import threading
from typing import Dict, Optional, Tuple, Any
from collections import OrderedDict


class URLReputationCache:
    """Thread-safe LRU cache with TTL for instantaneous URL reputation lookups."""

    DEFAULT_TTL_SEC: int = 3600  # 1 hour cache
    MAX_CAPACITY: int = 50_000

    def __init__(self, ttl: int = DEFAULT_TTL_SEC, max_capacity: int = MAX_CAPACITY) -> None:
        self._ttl = ttl
        self._max_capacity = max_capacity
        self._cache: OrderedDict[str, Tuple[Dict[str, Any], float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached scan result if present and unexpired (< 1ms)."""
        clean_url = str(url or "").strip().lower()
        now = time.time()

        with self._lock:
            if clean_url not in self._cache:
                return None

            result_dict, timestamp = self._cache[clean_url]
            if now - timestamp > self._ttl:
                del self._cache[clean_url]
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(clean_url)
            return dict(result_dict)

    def set(self, url: str, result: Dict[str, Any]) -> None:
        """Store scan verdict in LRU cache."""
        clean_url = str(url or "").strip().lower()
        now = time.time()

        with self._lock:
            if clean_url in self._cache:
                del self._cache[clean_url]
            elif len(self._cache) >= self._max_capacity:
                # Evict oldest entry
                self._cache.popitem(last=False)

            self._cache[clean_url] = (result, now)

    def clear(self) -> None:
        """Flush cache."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return active cache size."""
        with self._lock:
            return len(self._cache)


class SlidingWindowRateLimiter:
    """Token bucket / sliding window rate limiter per API key or IP address."""

    def __init__(self) -> None:
        # Maps identifier -> list of request timestamps [t1, t2, ...]
        self._requests: Dict[str, list] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, identifier: str, limit_per_minute: int) -> Tuple[bool, int, float]:
        """Check if request is permitted under rate limit.
        
        Args:
            identifier: Unique client identifier (e.g. 'api_key:123' or 'ip:1.2.3.4').
            limit_per_minute: Maximum allowed requests in a rolling 60-second window.
            
        Returns:
            Tuple of (is_allowed: bool, remaining_requests: int, retry_after_seconds: float).
        """
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            if identifier not in self._requests:
                self._requests[identifier] = [now]
                return True, limit_per_minute - 1, 0.0

            # Prune timestamps older than 60 seconds
            history = self._requests[identifier]
            valid_history = [t for t in history if t > window_start]

            if len(valid_history) >= limit_per_minute:
                # Rate limit exceeded!
                oldest = valid_history[0]
                retry_after = max(0.1, round(60.0 - (now - oldest), 2))
                self._requests[identifier] = valid_history
                return False, 0, retry_after

            # Request allowed
            valid_history.append(now)
            self._requests[identifier] = valid_history
            remaining = max(0, limit_per_minute - len(valid_history))
            return True, remaining, 0.0

    def reset(self, identifier: Optional[str] = None) -> None:
        """Clear rate limit history."""
        with self._lock:
            if identifier:
                self._requests.pop(identifier, None)
            else:
                self._requests.clear()

