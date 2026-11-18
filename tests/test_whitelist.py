"""Unit tests for VerifiedDomainWhitelist."""

import unittest
from src.threat_intelligence.whitelist import VerifiedDomainWhitelist


class TestVerifiedDomainWhitelist(unittest.TestCase):
    """Test suite for high-reputation domain whitelist and multi-tenant categorization."""

    def setUp(self):
        self.whitelist = VerifiedDomainWhitelist()

    def test_core_trusted_domains(self):
        """Verify core high-reputation platform domains are whitelisted."""
        urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PL123&index=5",
            "https://google.com/search?q=machine+learning+cybersecurity",
            "https://github.com/torvalds/linux",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://stackoverflow.com/questions/123456",
        ]
        for url in urls:
            res = self.whitelist.check_whitelist(url)
            self.assertTrue(res.is_whitelisted, f"Expected {url} to be whitelisted")
            self.assertFalse(res.is_multi_tenant)
            self.assertIsNotNone(res.category)

    def test_multi_tenant_user_hosts(self):
        """Verify user-content hosts are flagged multi-tenant and NOT blanket whitelisted."""
        multi_tenant_urls = [
            "https://my-phish-app.firebaseapp.com/login",
            "https://phish-form.forms.gle/xyz123",
            "https://worker-stealer.pages.dev/",
            "https://evil.github.io/fake-bank",
            "https://s3.amazonaws.com/bucket/malicious.exe",
        ]
        for url in multi_tenant_urls:
            res = self.whitelist.check_whitelist(url)
            self.assertFalse(res.is_whitelisted, f"Multi-tenant host {url} must not be whitelisted")
            self.assertTrue(res.is_multi_tenant)

    def test_unknown_domain(self):
        """Verify unknown or unlisted domain returns is_whitelisted=False."""
        res = self.whitelist.check_whitelist("https://suspicious-new-domain.top/auth")
        self.assertFalse(res.is_whitelisted)
        self.assertFalse(res.is_multi_tenant)

    def test_subdomain_spoofing_registered_domain(self):
        """Verify registered domain extraction prevents subdomains on attacker domains from masquerading as whitelisted."""
        res = self.whitelist.check_whitelist("https://google.com.attacker-controlled.net/login")
        self.assertFalse(res.is_whitelisted)
        self.assertEqual(res.registered_domain, "attacker-controlled.net")


if __name__ == "__main__":
    unittest.main()

