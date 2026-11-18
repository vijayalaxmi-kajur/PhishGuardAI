"""
PhishGuardAI Official Python SDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Zero-day phishing detection and threat intelligence client.
"""

from .client import PhishGuardClient
from .exceptions import (
    PhishGuardError,
    AuthenticationError,
    RateLimitError,
    InvalidURLError,
    APIConnectionError,
)

__version__ = "1.0.0"
__all__ = [
    "PhishGuardClient",
    "PhishGuardError",
    "AuthenticationError",
    "RateLimitError",
    "InvalidURLError",
    "APIConnectionError",
]

