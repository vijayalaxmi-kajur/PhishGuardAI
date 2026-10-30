"""Unit tests for the Threat Intelligence Subsystem

Tests PhishTank and URLhaus providers, error handling, rate limiting, timeouts,
and multi-provider aggregation using strictly mocked HTTP calls (zero network traffic).
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from src.threat_intelligence.base import (
    ThreatStatus,
    ThreatCategory,
    ThreatLookupResult,
    MultiProviderLookupResult,
)
from src.threat_intelligence.phishtank import PhishTankProvider
from src.threat_intelligence.urlhaus import URLhausProvider
from src.threat_intelligence.manager import ThreatIntelligenceManager


class TestThreatIntelligence(unittest.TestCase):
    """Test suite for external threat intelligence providers and manager."""

    def setUp(self):
        self.mock_session = MagicMock(spec=requests.Session)

    # --- PHISHTANK PROVIDER TESTS ---

    def test_phishtank_verified_phishing_match(self):
        """Test PhishTank returns MATCHED for a verified phishing URL."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "in_database": True,
                "phish_id": "8912345",
                "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=8912345",
                "verified": True,
                "verified_at": "2026-10-28T10:00:00Z",
                "valid": True,
            }
        }
        self.mock_session.post.return_value = mock_resp

        provider = PhishTankProvider(api_key="test_key", session=self.mock_session)
        res = provider.check_url("http://verified-phish-domain.com/login")

        self.assertEqual(res.status, ThreatStatus.MATCHED)
        self.assertTrue(res.is_threat)
        self.assertTrue(res.verified)
        self.assertEqual(res.threat_category, ThreatCategory.PHISHING)
        self.assertEqual(res.confidence, 1.0)
        self.assertIn("8912345", res.reference_url)

    def test_phishtank_no_match(self):
        """Test PhishTank returns NO_MATCH when URL is not in database."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "in_database": False,
            }
        }
        self.mock_session.post.return_value = mock_resp

        provider = PhishTankProvider(session=self.mock_session)
        res = provider.check_url("https://www.wikipedia.org/wiki/Phishing")

        self.assertEqual(res.status, ThreatStatus.NO_MATCH)
        self.assertFalse(res.is_threat)
        self.assertFalse(res.verified)
        self.assertEqual(res.confidence, 0.0)

    def test_phishtank_timeout(self):
        """Test PhishTank handles request timeout gracefully without raising exceptions."""
        self.mock_session.post.side_effect = requests.exceptions.Timeout("Connection timed out")

        provider = PhishTankProvider(timeout=2.0, session=self.mock_session)
        res = provider.check_url("http://example-timeout.com")

        self.assertEqual(res.status, ThreatStatus.TIMEOUT)
        self.assertFalse(res.is_threat)
        self.assertTrue(res.is_degraded)
        self.assertIn("timed out", res.error_message)

    def test_phishtank_rate_limited(self):
        """Test PhishTank returns RATE_LIMITED on HTTP 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Too Many Requests"
        self.mock_session.post.return_value = mock_resp

        provider = PhishTankProvider(session=self.mock_session)
        res = provider.check_url("http://example-rate-limited.com")

        self.assertEqual(res.status, ThreatStatus.RATE_LIMITED)
        self.assertTrue(res.is_degraded)

    def test_phishtank_service_unavailable(self):
        """Test PhishTank returns UNAVAILABLE on HTTP 503."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        self.mock_session.post.return_value = mock_resp

        provider = PhishTankProvider(session=self.mock_session)
        res = provider.check_url("http://example-down.com")

        self.assertEqual(res.status, ThreatStatus.UNAVAILABLE)
        self.assertTrue(res.is_degraded)

    def test_phishtank_malformed_json(self):
        """Test PhishTank handles corrupted JSON payload."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON token")
        self.mock_session.post.return_value = mock_resp

        provider = PhishTankProvider(session=self.mock_session)
        res = provider.check_url("http://example-malformed.com")

        self.assertEqual(res.status, ThreatStatus.ERROR)
        self.assertTrue(res.is_degraded)

    # --- URLHAUS PROVIDER TESTS ---

    def test_urlhaus_verified_malware_match(self):
        """Test URLhaus returns MATCHED for an active malware URL."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "id": "278190",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["elf", "Mirai"],
            "reporter": "abuse_hunter",
            "date_added": "2026-10-28 08:30:00 UTC",
        }
        self.mock_session.post.return_value = mock_resp

        provider = URLhausProvider(api_key="test_auth_key", session=self.mock_session)
        res = provider.check_url("http://192.168.1.1/bins/mirai.arm7")

        self.assertEqual(res.status, ThreatStatus.MATCHED)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.threat_category, ThreatCategory.MALWARE)
        self.assertEqual(res.confidence, 1.0)
        self.assertIn("278190", res.reference_url)

    def test_urlhaus_no_results(self):
        """Test URLhaus returns NO_MATCH when query status is 'no_results'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "no_results"
        }
        self.mock_session.post.return_value = mock_resp

        provider = URLhausProvider(session=self.mock_session)
        res = provider.check_url("https://www.google.com")

        self.assertEqual(res.status, ThreatStatus.NO_MATCH)
        self.assertFalse(res.is_threat)

    def test_urlhaus_invalid_url(self):
        """Test URLhaus returns INVALID_INPUT when query status is 'invalid_url'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "invalid_url"
        }
        self.mock_session.post.return_value = mock_resp

        provider = URLhausProvider(session=self.mock_session)
        res = provider.check_url("not_a_valid_url")

        self.assertEqual(res.status, ThreatStatus.INVALID_INPUT)
        self.assertFalse(res.is_threat)

    def test_urlhaus_timeout(self):
        """Test URLhaus handles timeout gracefully."""
        self.mock_session.post.side_effect = requests.exceptions.Timeout("Read timeout")

        provider = URLhausProvider(session=self.mock_session)
        res = provider.check_url("http://example-urlhaus-timeout.com")

        self.assertEqual(res.status, ThreatStatus.TIMEOUT)
        self.assertTrue(res.is_degraded)

    # --- THREAT INTELLIGENCE MANAGER TESTS ---

    def test_manager_positive_threat_aggregation(self):
        """Test manager aggregates threat matches and records source metadata."""
        mock_pt = MagicMock(spec=PhishTankProvider)
        mock_pt.get_provider_name.return_value = "PhishTank"
        mock_pt.is_enabled.return_value = True
        mock_pt.check_url.return_value = ThreatLookupResult(
            provider_name="PhishTank",
            status=ThreatStatus.MATCHED,
            is_threat=True,
            threat_category=ThreatCategory.PHISHING,
            reference_url="http://phishtank.com/123",
        )

        mock_uh = MagicMock(spec=URLhausProvider)
        mock_uh.get_provider_name.return_value = "URLhaus"
        mock_uh.is_enabled.return_value = True
        mock_uh.check_url.return_value = ThreatLookupResult(
            provider_name="URLhaus",
            status=ThreatStatus.NO_MATCH,
            is_threat=False,
        )

        manager = ThreatIntelligenceManager(providers=[mock_pt, mock_uh])
        res = manager.check_url("http://malicious-test.com")

        self.assertTrue(res.is_any_threat)
        self.assertEqual(len(res.matched_sources), 1)
        self.assertIn("PhishTank", res.matched_sources[0])
        self.assertEqual(len(res.available_providers), 2)
        self.assertEqual(len(res.degraded_providers), 0)

    def test_manager_timeout_never_interpreted_as_clean(self):
        """Test that when feeds time out, manager marks them degraded and emits warnings."""
        mock_pt = MagicMock(spec=PhishTankProvider)
        mock_pt.get_provider_name.return_value = "PhishTank"
        mock_pt.is_enabled.return_value = True
        mock_pt.check_url.return_value = ThreatLookupResult(
            provider_name="PhishTank",
            status=ThreatStatus.TIMEOUT,
            error_message="Connection timed out after 3.0s",
        )

        mock_uh = MagicMock(spec=URLhausProvider)
        mock_uh.get_provider_name.return_value = "URLhaus"
        mock_uh.is_enabled.return_value = True
        mock_uh.check_url.return_value = ThreatLookupResult(
            provider_name="URLhaus",
            status=ThreatStatus.UNAVAILABLE,
            error_message="Host unreachable",
        )

        manager = ThreatIntelligenceManager(providers=[mock_pt, mock_uh])
        res = manager.check_url("http://suspicious-unknown.com")

        self.assertFalse(res.is_any_threat)
        self.assertTrue(res.has_degraded_providers)
        self.assertIn("PhishTank", res.degraded_providers)
        self.assertIn("URLhaus", res.degraded_providers)
        # Verify warning specifically emphasizes that missing match is NOT proof of clean
        has_warning = any("NOT be interpreted as proof that a URL is legitimate" in w for w in res.warnings)
        self.assertTrue(has_warning)


if __name__ == "__main__":
    unittest.main()
