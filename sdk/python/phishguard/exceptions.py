"""
PhishGuardAI SDK Exceptions
"""

class PhishGuardError(Exception):
    """Base exception for all PhishGuard SDK errors."""
    def __init__(self, message: str, status_code: int = None, response_body: dict = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body or {}

    def __str__(self):
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(PhishGuardError):
    """Raised when API key or session token is invalid or missing."""
    pass


class RateLimitError(PhishGuardError):
    """Raised when request quota or rate limit (RPM) is exceeded."""
    pass


class InvalidURLError(PhishGuardError):
    """Raised when submitted URL fails RFC validation."""
    pass


class APIConnectionError(PhishGuardError):
    """Raised when server cannot be reached or connection times out."""
    pass

