"""Unit tests for Phase 1 Integrated Decision Engine (Domain Age + Whitelist + Feeds)."""

import unittest
from unittest.mock import MagicMock

from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
)
from src.threat_intelligence.whois_checker import DomainAgeChecker, DomainAgeResult
from src.threat_intelligence.whitelist import VerifiedDomainWhitelist
from src.threat_intelligence.manager import ThreatIntelligenceManager


class TestPhase1Integration(unittest.TestCase):
    """Integration test suite for Phase 1 hardened decision engine."""

    def setUp(self):
        # Create offline domain age mock handler
        def mock_age(domain):
            if "new-phish" in domain:
                return DomainAgeResult(
                    domain=domain,
                    registered_domain=domain,
                    domain_age_days=3,
                    is_new_domain=True,
                    is_recent_domain=True,
                    registrar="Porkbun LLC",
                    source="mock"
                )
            return DomainAgeResult(
                domain=domain,
                registered_domain=domain,
                domain_age_days=500,
                is_new_domain=False,
                is_recent_domain=False,
                registrar="MarkMonitor",
                source="mock"
            )

        self.domain_age_checker = DomainAgeChecker(mock_handler=mock_age)
        self.whitelist = VerifiedDomainWhitelist()
        self.threat_mgr = ThreatIntelligenceManager(providers=[])  # Empty for offline determinism

        # Decision engine without ML model to isolate rule engine and telemetry
        self.engine = LayeredDecisionEngine(
            ml_model=None,
            threat_intel_manager=self.threat_mgr,
            domain_age_checker=self.domain_age_checker,
            whitelist_registry=self.whitelist,
        )

    def test_youtube_complex_query_whitelisted(self):
        """Verify YouTube URL with complex playlist parameters is whitelisted as NO_KNOWN_THREAT."""
        yt_url = "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4"
        res = self.engine.evaluate_url(yt_url)
        self.assertEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)
        self.assertEqual(res.risk_level, RiskLevel.LOW)
        self.assertTrue(res.structural_indicators.get("is_whitelisted"))
        self.assertIn("Verified Whitelist Match", " ".join(res.evidence_based_explanation))

    def test_newly_registered_domain_escalation(self):
        """Verify domain < 14 days old with auth path escalates to HIGH_RISK."""
        new_url = "https://new-phish-portal.xyz/login/verify-account"
        res = self.engine.evaluate_url(new_url)
        self.assertEqual(res.verdict, DecisionVerdict.HIGH_RISK)
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        self.assertTrue(res.structural_indicators.get("is_new_domain"))
        self.assertIn("High-Risk Infrastructure Telemetry", " ".join(res.evidence_based_explanation))

    def test_newly_registered_domain_clean_path_held_as_suspicious(self):
        """Verify clean-path domain < 14 days old is held as SUSPICIOUS and never marked safe."""
        clean_new_url = "https://new-phish-domain.com/"
        res = self.engine.evaluate_url(clean_new_url)
        self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)
        self.assertEqual(res.verdict, DecisionVerdict.SUSPICIOUS)
        self.assertEqual(res.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(res.structural_indicators.get("is_new_domain"))

    def test_brand_subdomain_spoofing_not_whitelisted(self):
        """Verify attacker using 'youtube.com' as subdomain of attacker domain is caught as HIGH_RISK."""
        spoofed_url = "https://youtube.com.attacker-controlled.net/watch"
        res = self.engine.evaluate_url(spoofed_url)
        self.assertEqual(res.verdict, DecisionVerdict.HIGH_RISK)
        self.assertFalse(res.structural_indicators.get("is_whitelisted"))


if __name__ == "__main__":
    unittest.main()

