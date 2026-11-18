"""Unit tests for DomainAgeChecker (RDAP / WHOIS telemetry)."""

import unittest
from unittest.mock import MagicMock
import datetime

from src.threat_intelligence.whois_checker import DomainAgeChecker, DomainAgeResult


class TestDomainAgeChecker(unittest.TestCase):
    """Test suite for domain age extraction, caching, and fallback behavior."""

    def setUp(self):
        self.checker = DomainAgeChecker(timeout=1.0)

    def test_extract_registered_domain(self):
        """Test registered domain extraction across varied URL formats."""
        self.assertEqual(self.checker.extract_registered_domain("https://www.google.com/search?q=test"), "google.com")
        self.assertEqual(self.checker.extract_registered_domain("http://sub.domain.co.uk/path"), "domain.co.uk")
        self.assertEqual(self.checker.extract_registered_domain("github.com"), "github.com")
        self.assertEqual(self.checker.extract_registered_domain("https://deep.nested.sub.example.org:8080/"), "example.org")
        self.assertEqual(self.checker.extract_registered_domain(""), "")

    def test_calculate_age_days(self):
        """Test ISO timestamp parsing and age calculation."""
        # 10 days ago
        ten_days_ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        age = self.checker._calculate_age_days(ten_days_ago)
        self.assertIsNotNone(age)
        self.assertEqual(age, 10)

        # Old domain (365 days)
        one_year_ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)).isoformat()
        self.assertEqual(self.checker._calculate_age_days(one_year_ago), 365)

        # Invalid string
        self.assertIsNone(self.checker._calculate_age_days("invalid-date"))
        self.assertIsNone(self.checker._calculate_age_days(""))

    def test_parse_rdap_payload(self):
        """Test parsing of registration event and registrar name from RDAP JSON."""
        sample_payload = {
            "events": [
                {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2020-05-15T12:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "MarkMonitor Inc."],
                        ]
                    ]
                }
            ]
        }
        creation_date, registrar = self.checker._parse_rdap_payload(sample_payload)
        self.assertEqual(creation_date, "2020-05-15T12:00:00Z")
        self.assertEqual(registrar, "MarkMonitor Inc.")

    def test_mock_handler_new_domain(self):
        """Test mock handler correctly flags domain < 14 days old."""
        def mock_new(domain):
            return DomainAgeResult(
                domain=domain,
                registered_domain=domain,
                domain_age_days=5,
                is_new_domain=True,
                is_recent_domain=True,
                registrar="NameCheap",
                source="mock"
            )

        checker = DomainAgeChecker(mock_handler=mock_new)
        res = checker.get_domain_age("https://brand-new-phish.xyz/login")
        self.assertTrue(res.is_new_domain)
        self.assertTrue(res.is_recent_domain)
        self.assertEqual(res.domain_age_days, 5)
        self.assertEqual(res.registrar, "NameCheap")

    def test_cache_hits(self):
        """Test in-memory cache returns cached result on subsequent queries."""
        call_count = 0

        def counting_mock(domain):
            nonlocal call_count
            call_count += 1
            return DomainAgeResult(
                domain=domain,
                registered_domain=domain,
                domain_age_days=100,
                is_new_domain=False,
                is_recent_domain=False,
                source="mock"
            )

        checker = DomainAgeChecker(mock_handler=counting_mock)
        res1 = checker.get_domain_age("https://example.com/page1")
        self.assertFalse(res1.is_cached)
        self.assertEqual(call_count, 1)

        res2 = checker.get_domain_age("https://example.com/page2")
        self.assertTrue(res2.is_cached)
        self.assertEqual(call_count, 1)  # No second call to handler!


if __name__ == "__main__":
    unittest.main()

