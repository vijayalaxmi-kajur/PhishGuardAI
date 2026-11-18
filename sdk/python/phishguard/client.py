"""
PhishGuardAI Official Python SDK Client
High-throughput threat intelligence and real-time phishing detection.
"""

import json
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

from .exceptions import (
    PhishGuardError,
    AuthenticationError,
    RateLimitError,
    InvalidURLError,
    APIConnectionError,
)


class PhishGuardClient:
    """Official client for the PhishGuardAI Threat Intelligence & Phishing Detection API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://127.0.0.1:5000",
        timeout: float = 10.0,
        session_token: Optional[str] = None,
    ):
        """
        Initialize PhishGuardClient.

        :param api_key: PhishGuard API key (starts with pg_live_... or pg_test_...).
        :param base_url: Host URL of the PhishGuardAI instance.
        :param timeout: Network timeout in seconds (default: 10.0s).
        :param session_token: Signed developer session token for management APIs.
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_token = session_token

    def _request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
        auth_type: str = "api_key",
    ) -> Dict[str, Any]:
        """Perform internal HTTP request using standard library urllib."""
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PhishGuardAI-Python-SDK/1.0",
        }

        if auth_type == "api_key" and self.api_key:
            headers["X-API-Key"] = self.api_key
        elif auth_type == "session" and self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"

        data_bytes = None
        if payload is not None:
            data_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_data = resp.read().decode("utf-8")
                return json.loads(resp_data)
        except urllib.error.HTTPError as e:
            raw_err = e.read().decode("utf-8")
            try:
                err_body = json.loads(raw_err)
                err_msg = err_body.get("error", raw_err)
            except Exception:
                err_body = {"raw": raw_err}
                err_msg = raw_err

            if e.code == 401:
                raise AuthenticationError(err_msg, status_code=401, response_body=err_body)
            elif e.code == 429:
                raise RateLimitError(err_msg, status_code=429, response_body=err_body)
            elif e.code == 400:
                raise InvalidURLError(err_msg, status_code=400, response_body=err_body)
            else:
                raise PhishGuardError(err_msg, status_code=e.code, response_body=err_body)
        except urllib.error.URLError as e:
            raise APIConnectionError(f"Failed to connect to PhishGuard server at {self.base_url}: {e.reason}")
        except Exception as e:
            raise PhishGuardError(f"Unexpected request error: {str(e)}")

    def scan(self, url: str, check_presence: bool = True) -> Dict[str, Any]:
        """
        Scan a single URL for phishing indicators, domain telemetry, and malicious DOM patterns.

        :param url: Target URL to inspect (e.g. 'https://login-service-auth.xyz').
        :param check_presence: Whether to perform live DNS and SSL reachability check.
        :return: Structured scan dictionary containing verdict, risk_level, confidence, and telemetry.
        """
        # If API key is available, use enterprise v1 endpoint; otherwise fallback to open scan
        endpoint = "/api/v1/scan" if self.api_key else "/api/scan"
        payload = {"url": url, "check_presence": check_presence}
        return self._request(endpoint, method="POST", payload=payload, auth_type="api_key")

    def is_phishing(self, url: str) -> bool:
        """
        Convenience helper: returns True if URL is classified as phishing or confirmed malicious.
        """
        res = self.scan(url, check_presence=False)
        verdict = (res.get("verdict") or res.get("standardized_verdict") or "").lower()
        risk = (res.get("risk_level") or "").lower()
        return verdict in ("phishing", "confirmed_malicious") or risk in ("high", "critical")

    def get_risk_score(self, url: str) -> float:
        """
        Convenience helper: returns float risk probability [0.00, 1.00].
        """
        res = self.scan(url, check_presence=False)
        return float(res.get("phishing_probability", 0.0))

    def batch_scan(
        self, urls: List[str], max_workers: int = 5, check_presence: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs concurrently using a thread pool.

        :param urls: List of target URLs.
        :param max_workers: Number of concurrent threads.
        :param check_presence: Whether to test DNS/SSL reachability for each.
        :return: List of scan results matching input order.
        """
        results = [None] * len(urls)

        def _worker(idx, target_url):
            try:
                data = self.scan(target_url, check_presence=check_presence)
                return idx, data
            except Exception as e:
                return idx, {"url": target_url, "success": False, "error": str(e)}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_worker, i, u) for i, u in enumerate(urls)]
            for future in as_completed(futures):
                idx, data = future.result()
                results[idx] = data

        return results

    # =========================================================================
    # Management & Account Methods (Requires session_token)
    # =========================================================================

    def get_usage(self) -> Dict[str, Any]:
        """Fetch developer account usage and quota statistics."""
        return self._request("/api/v1/user/usage", method="GET", auth_type="session")

    def list_keys(self) -> List[Dict[str, Any]]:
        """List developer API keys."""
        res = self._request("/api/v1/keys", method="GET", auth_type="session")
        return res.get("keys", [])

    def create_key(self, label: str = "SDK Key", is_live: bool = True) -> Dict[str, Any]:
        """Generate a new cryptographic API key."""
        payload = {"label": label, "is_live": is_live}
        return self._request("/api/v1/keys", method="POST", payload=payload, auth_type="session")

    def revoke_key(self, key_id: int) -> bool:
        """Revoke an active API key."""
        res = self._request(f"/api/v1/keys/{key_id}", method="DELETE", auth_type="session")
        return res.get("success", False)

