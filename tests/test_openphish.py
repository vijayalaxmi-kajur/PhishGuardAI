"""Unit tests for OpenPhishProvider."""

import unittest
from unittest.mock import MagicMock
import requests

from src.threat_intelligence.openphish import OpenPhishProvider
from src.threat_intelligence.base import ThreatStatus, ThreatCategory


class TestOpenPhishProvider(unittest.TestCase):
    """Test suite for OpenPhish threat intelligence feed integration."""

    def test_exact_match(self):
        """Test URL present in active cache produces MATCHED verdict."""
        cached_phish = {"http://fake-banking-portal.xyz/login.php"}
        provider = OpenPhishProvider(initial_cache=cached_phish)

        res = provider.check_url("http://fake-banking-portal.xyz/login.php")
        self.assertEqual(res.status, ThreatStatus.MATCHED)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.threat_category, ThreatCategory.PHISHING)
        self.assertEqual(res.provider_name, "OpenPhish")

    def test_no_match(self):
        """Test clean URL produces NO_MATCH verdict."""
        cached_phish = {"http://known-malicious.com/"}
        provider = OpenPhishProvider(initial_cache=cached_phish)

        res = provider.check_url("https://clean-website.com/")
        self.assertEqual(res.status, ThreatStatus.NO_MATCH)
        self.assertFalse(res.is_threat)

    def test_disabled_provider(self):
        """Test disabled provider returns UNAVAILABLE without network calls."""
        provider = OpenPhishProvider(enabled=False)
        res = provider.check_url("http://example.com")
        self.assertEqual(res.status, ThreatStatus.UNAVAILABLE)

    def test_invalid_input(self):
        """Test empty or whitespace URL returns INVALID_INPUT."""
        provider = OpenPhishProvider()
        res = provider.check_url("   ")
        self.assertEqual(res.status, ThreatStatus.INVALID_INPUT)

    def test_sync_feed_mock(self):
        """Test sync_feed parses line-delimited URLs into memory."""
        mock_session = MagicMock(spec=requests.Session)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "# OpenPhish Feed\nhttp://phish1.com/a\nhttp://phish2.com/b\n\n"
        mock_session.get.return_value = mock_response

        provider = OpenPhishProvider(session=mock_session)
        success = provider.sync_feed()
        self.assertTrue(success)
        self.assertIn("http://phish1.com/a", provider._feed_cache)
        self.assertIn("http://phish2.com/b", provider._feed_cache)


if __name__ == "__main__":
    unittest.main()

