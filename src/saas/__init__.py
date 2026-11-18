"""PhishGuardAI - Multi-Tenant SaaS & Commercial Infrastructure Subsystem

Exports cryptographic authentication, database management, high-performance caching,
sliding-window rate limiting, and endpoint security middleware.
"""

from src.saas.auth import SecurityManager
from src.saas.database import SaaSDataManager
from src.saas.cache import URLReputationCache, SlidingWindowRateLimiter
from src.saas.middleware import require_api_key, require_session_token

__all__ = [
    "SecurityManager",
    "SaaSDataManager",
    "URLReputationCache",
    "SlidingWindowRateLimiter",
    "require_api_key",
    "require_session_token",
]

