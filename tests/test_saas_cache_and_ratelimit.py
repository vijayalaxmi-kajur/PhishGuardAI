"""Unit tests for URLReputationCache and SlidingWindowRateLimiter."""

import unittest
import time
from src.saas.cache import URLReputationCache, SlidingWindowRateLimiter


class TestCacheAndRateLimiter(unittest.TestCase):
    """Test suite for URL reputation LRU caching and token bucket rate limiting."""

    def test_cache_set_get_and_expiration(self):
        """Verify LRU cache stores results and respects TTL expiration."""
        cache = URLReputationCache(ttl=1)  # 1 second TTL

        cache.set("https://example.com/test", {"verdict": "legitimate", "risk": "low"})
        res = cache.get("https://example.com/test")
        self.assertIsNotNone(res)
        self.assertEqual(res["verdict"], "legitimate")

        # Wait for TTL expiration
        time.sleep(1.1)
        self.assertIsNone(cache.get("https://example.com/test"))

    def test_cache_lru_eviction(self):
        """Verify LRU eviction when capacity is reached."""
        cache = URLReputationCache(ttl=60, max_capacity=2)

        cache.set("url1", {"v": 1})
        cache.set("url2", {"v": 2})
        cache.set("url3", {"v": 3})  # Should evict url1

        self.assertIsNone(cache.get("url1"))
        self.assertIsNotNone(cache.get("url2"))
        self.assertIsNotNone(cache.get("url3"))

    def test_sliding_window_rate_limiter(self):
        """Verify sliding window token bucket blocks requests exceeding limit."""
        limiter = SlidingWindowRateLimiter()

        # Allow 3 requests per minute
        allowed1, rem1, retry1 = limiter.check_rate_limit("client:1", limit_per_minute=3)
        self.assertTrue(allowed1)
        self.assertEqual(rem1, 2)

        allowed2, rem2, retry2 = limiter.check_rate_limit("client:1", limit_per_minute=3)
        self.assertTrue(allowed2)
        self.assertEqual(rem2, 1)

        allowed3, rem3, retry3 = limiter.check_rate_limit("client:1", limit_per_minute=3)
        self.assertTrue(allowed3)
        self.assertEqual(rem3, 0)

        # 4th request must be blocked!
        allowed4, rem4, retry4 = limiter.check_rate_limit("client:1", limit_per_minute=3)
        self.assertFalse(allowed4)
        self.assertGreater(retry4, 0.0)

        # Different client should be unaffected
        allowed_other, _, _ = limiter.check_rate_limit("client:2", limit_per_minute=3)
        self.assertTrue(allowed_other)


if __name__ == "__main__":
    unittest.main()

