"""PhishGuardAI - SaaS Authentication & Rate Limiting Middleware

Provides decorators for securing REST endpoints with API keys and session tokens,
enforcing tiered rate limits, and attaching tenant metadata to requests.
"""

from functools import wraps
from typing import Callable, Optional, Dict, Any
from flask import request, jsonify, g, make_response

from src.saas.database import SaaSDataManager
from src.saas.cache import SlidingWindowRateLimiter
from src.saas.auth import SecurityManager


def require_api_key(
    data_manager: SaaSDataManager,
    rate_limiter: SlidingWindowRateLimiter
) -> Callable:
    """Decorator requiring a valid active API key with tiered rate-limiting."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Extract API Key from headers
            auth_header = request.headers.get("Authorization", "").strip()
            api_key = request.headers.get("X-API-Key", "").strip()

            if not api_key and auth_header.startswith("Bearer "):
                candidate = auth_header[7:].strip()
                if candidate.startswith("pg_live_") or candidate.startswith("pg_test_"):
                    api_key = candidate

            if not api_key:
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Please provide a valid API key via 'X-API-Key' or 'Authorization: Bearer pg_...'"
                }), 401

            # 2. Validate API Key in Database
            key_info = data_manager.validate_api_key(api_key)
            if not key_info:
                return jsonify({
                    "success": False,
                    "error": "Invalid or revoked API key."
                }), 401

            # 3. Check Monthly Scan Quota
            if key_info["scans_used_this_month"] >= key_info["monthly_scan_quota"]:
                return jsonify({
                    "success": False,
                    "error": f"Monthly scan quota ({key_info['monthly_scan_quota']:,} scans) exceeded for plan '{key_info['plan_tier']}'. Please upgrade your subscription tier."
                }), 429

            # 4. Enforce Token Bucket Rate Limiting
            key_id = key_info["key_id"]
            limit = key_info["rate_limit_per_minute"]
            is_allowed, remaining, retry_after = rate_limiter.check_rate_limit(f"key:{key_id}", limit)

            if not is_allowed:
                response = jsonify({
                    "success": False,
                    "error": f"Rate limit exceeded ({limit} requests/minute).",
                    "retry_after_seconds": retry_after
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(int(retry_after) + 1)
                response.headers["X-RateLimit-Limit"] = str(limit)
                response.headers["X-RateLimit-Remaining"] = "0"
                return response

            # Attach tenant info to Flask request global
            g.tenant = key_info

            # Execute endpoint handler
            res = f(*args, **kwargs)
            response = make_response(res)
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            return response
        return decorated_function
    return decorator


def require_session_token(
    security_manager: SecurityManager
) -> Callable:
    """Decorator requiring a valid signed session bearer token."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "").strip()
            if not auth_header.startswith("Bearer "):
                return jsonify({
                    "success": False,
                    "error": "Bearer token required in 'Authorization' header."
                }), 401

            token = auth_header[7:].strip()
            payload = security_manager.verify_session_token(token)
            if not payload:
                return jsonify({
                    "success": False,
                    "error": "Session token is invalid or expired. Please log in again."
                }), 401

            g.user = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator
