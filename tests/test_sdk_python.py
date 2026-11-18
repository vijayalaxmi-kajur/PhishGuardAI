"""
Unit tests for PhishGuardAI Official Python SDK.
"""

import unittest
from unittest.mock import patch, MagicMock
import io
import json
import urllib.error

import sys
from pathlib import Path
SDK_DIR = Path(__file__).resolve().parent.parent / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from phishguard import PhishGuardClient
from phishguard.exceptions import (
    PhishGuardError,
    AuthenticationError,
    RateLimitError,
    InvalidURLError,
    APIConnectionError,
)


class TestPhishGuardPythonSDK(unittest.TestCase):

    def setUp(self):
        self.client = PhishGuardClient(
            api_key="pg_live_mocktestkey1234567890",
            base_url="http://127.0.0.1:5000",
            timeout=5.0
        )

    @patch("urllib.request.urlopen")
    def test_scan_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "success": True,
            "url": "https://google.com",
            "verdict": "legitimate",
            "risk_level": "low",
            "phishing_probability": 0.05,
            "confidence_percent": 95.0,
            "explanation": ["Domain is whitelisted."]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = self.client.scan("https://google.com")
        self.assertTrue(res["success"])
        self.assertEqual(res["verdict"], "legitimate")
        self.assertEqual(res["phishing_probability"], 0.05)

    @patch("urllib.request.urlopen")
    def test_is_phishing_helpers(self, mock_urlopen):
        # Case 1: Phishing
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "success": True,
            "verdict": "phishing",
            "risk_level": "high",
            "phishing_probability": 0.98
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        self.assertTrue(self.client.is_phishing("http://phish-site.com"))
        self.assertEqual(self.client.get_risk_score("http://phish-site.com"), 0.98)

        # Case 2: Legitimate
        mock_response2 = MagicMock()
        mock_response2.read.return_value = json.dumps({
            "success": True,
            "verdict": "legitimate",
            "risk_level": "low",
            "phishing_probability": 0.02
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response2

        self.assertFalse(self.client.is_phishing("https://google.com"))

    @patch("urllib.request.urlopen")
    def test_authentication_error(self, mock_urlopen):
        fp = io.BytesIO(json.dumps({"error": "Invalid API key"}).encode("utf-8"))
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:5000/api/v1/scan",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=fp
        )

        with self.assertRaises(AuthenticationError):
            self.client.scan("https://example.com")

    @patch("urllib.request.urlopen")
    def test_rate_limit_error(self, mock_urlopen):
        fp = io.BytesIO(json.dumps({"error": "Rate limit exceeded: 60 RPM"}).encode("utf-8"))
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:5000/api/v1/scan",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=fp
        )

        with self.assertRaises(RateLimitError):
            self.client.scan("https://example.com")

    @patch("urllib.request.urlopen")
    def test_invalid_url_error(self, mock_urlopen):
        fp = io.BytesIO(json.dumps({"error": "Invalid URL format"}).encode("utf-8"))
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:5000/api/v1/scan",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=fp
        )

        with self.assertRaises(InvalidURLError):
            self.client.scan("invalid-url")

    @patch("urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(APIConnectionError):
            self.client.scan("https://example.com")

    @patch.object(PhishGuardClient, "scan")
    def test_batch_scan(self, mock_scan):
        def _mock_scan_impl(url, check_presence=False):
            return {
                "url": url,
                "verdict": "phishing" if "bad" in url else "legitimate",
                "success": True
            }
        mock_scan.side_effect = _mock_scan_impl

        urls = ["https://good.com", "http://bad.com", "https://trusted.org"]
        results = self.client.batch_scan(urls, max_workers=2)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["url"], "https://good.com")
        self.assertEqual(results[0]["verdict"], "legitimate")
        self.assertEqual(results[1]["url"], "http://bad.com")
        self.assertEqual(results[1]["verdict"], "phishing")


if __name__ == "__main__":
    unittest.main()

