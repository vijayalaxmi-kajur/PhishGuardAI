"""Unit tests for the Layered Phishing Decision Engine

Tests multi-tiered decision orchestration across:
- Confirmed threat-intelligence matches (PhishTank, URLhaus)
- No threat-intelligence matches
- Provider timeouts, rate limits, and outages
- Legitimate URLs with multiple query parameters
- Suspicious URLs on commonly used hosting platforms (firebaseapp, pages.dev, weebly)
- Direct IP addresses with authentication paths
- URLs with misleading subdomains (brand spoofing)
- Spectrum of low, medium, and high model scores
- Invalid inputs and malformed provider responses
"""

import unittest
from unittest.mock import MagicMock
import numpy as np

from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
    DecisionResult,
)
from src.threat_intelligence.base import (
    ThreatStatus,
    ThreatCategory,
    ThreatLookupResult,
    MultiProviderLookupResult,
)
from src.threat_intelligence.manager import ThreatIntelligenceManager


class TestDecisionEngine(unittest.TestCase):
    """Comprehensive test suite for LayeredDecisionEngine."""

    def setUp(self):
        self.mock_intel_mgr = MagicMock(spec=ThreatIntelligenceManager)
        self.mock_intel_mgr.get_configured_providers.return_value = ["PhishTank", "URLhaus"]

    def _create_clean_intel_result(self, url: str) -> MultiProviderLookupResult:
        """Helper to create clean (no threat) intelligence response."""
        return MultiProviderLookupResult(
            url=url,
            is_any_threat=False,
            matched_sources=[],
            results={
                "PhishTank": ThreatLookupResult(provider_name="PhishTank", status=ThreatStatus.NO_MATCH, is_threat=False),
                "URLhaus": ThreatLookupResult(provider_name="URLhaus", status=ThreatStatus.NO_MATCH, is_threat=False),
            },
            available_providers=["PhishTank", "URLhaus"],
            degraded_providers=[],
            warnings=[
                "No threat intelligence matches found. Note: Zero-day phishing campaigns and newly registered domains frequently evade active blocklist feeds during early attack hours."
            ],
        )

    # --- 1. THREAT INTELLIGENCE MATCH & OVERRIDE TESTS ---

    def test_confirmed_threat_intel_match_overrides_low_ml_score(self):
        """Tier 1: A verified threat-intelligence match forces CONFIRMED_MALICIOUS even if ML score is 0.05."""
        url = "http://evasive-phish-kit.com/secure"
        
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])

        matched_intel = MultiProviderLookupResult(
            url=url,
            is_any_threat=True,
            matched_sources=["PhishTank (Category: phishing, ref: http://phishtank.com/12345)"],
            results={},
            available_providers=["PhishTank", "URLhaus"],
            degraded_providers=[],
            warnings=[],
        )
        self.mock_intel_mgr.check_url.return_value = matched_intel

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertIn(res.verdict, {DecisionVerdict.CONFIRMED_MALICIOUS, DecisionVerdict.PHISHING})
        self.assertEqual(res.standardized_verdict, "CONFIRMED MALICIOUS")
        self.assertEqual(res.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(res.model_score, 0.05)
        self.assertEqual(len(res.matched_threat_intel_sources), 1)
        self.assertIn("PhishTank", res.matched_threat_intel_sources[0])
        self.assertTrue(any("Verified threat match confirmed" in exp for exp in res.evidence_based_explanation))

    def test_no_threat_intel_match_does_not_guarantee_safety(self):
        """Tier 1: Verify that when threat intel returns NO_MATCH, warning is appended that feed is not proof of clean."""
        url = "https://newly-registered-phish-portal.site/login"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.50, 0.50]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertFalse(res.threat_intel_summary["matched"])
        has_warning = any("Zero-day phishing campaigns and newly registered domains frequently evade" in w for w in res.uncertainty_or_warnings)
        self.assertTrue(has_warning)

    def test_threat_intel_provider_timeout_and_outage_handling(self):
        """Tier 1: When providers time out or suffer outages (HTTP 503), explicit degradation warnings are logged."""
        url = "https://example.com/check"
        degraded_intel = MultiProviderLookupResult(
            url=url,
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=[],
            degraded_providers=["PhishTank", "URLhaus"],
            warnings=[
                "PhishTank check was degraded (timeout: Request timed out after 3.0s). A missing intelligence match must NOT be interpreted as proof that a URL is legitimate.",
                "URLhaus check was degraded (unavailable: Service unavailable (HTTP 503)).",
            ],
        )
        self.mock_intel_mgr.check_url.return_value = degraded_intel

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.90, 0.10]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        has_degraded_warning = any("PhishTank check was degraded" in w for w in res.uncertainty_or_warnings)
        self.assertTrue(has_degraded_warning)

    def test_threat_intel_rate_limiting_propagation(self):
        """Tier 1: When provider returns rate-limiting (HTTP 429), degradation warning is captured."""
        url = "https://example.com/test-rate-limit"
        rate_limited_intel = MultiProviderLookupResult(
            url=url,
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["URLhaus"],
            degraded_providers=["PhishTank"],
            warnings=["PhishTank check was degraded (rate_limited: Rate limit exceeded (HTTP 429))."],
        )
        self.mock_intel_mgr.check_url.return_value = rate_limited_intel

        engine = LayeredDecisionEngine(threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertTrue(any("rate_limited" in w for w in res.uncertainty_or_warnings))

    # --- 2. STRUCTURAL HEURISTIC & ABUSE DETECTION TESTS ---

    def test_direct_ip_hostname_with_login_path(self):
        """Tier 2: Direct IP hostname hosting login portal flagged as HIGH_RISK regardless of ML calibration."""
        url = "http://192.241.220.14/portal/admin/login.php"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.60, 0.40]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertIn(res.verdict, {DecisionVerdict.HIGH_RISK, DecisionVerdict.PHISHING})
        self.assertEqual(res.standardized_verdict, "HIGH RISK")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        self.assertTrue(res.structural_indicators["is_ip"])
        self.assertTrue(res.structural_indicators["has_auth_path"])
        self.assertTrue(any("Direct IP address hostname hosting authentication" in exp for exp in res.evidence_based_explanation))

    def test_misleading_subdomains_brand_spoofing(self):
        """Tier 2: Misleading subdomain spoofing (e.g. paypal.com in subdomain of unrelated domain) triggers HIGH_RISK."""
        url = "https://paypal.com.account-verification-notice.org/login"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.70, 0.30]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertIn(res.verdict, {DecisionVerdict.HIGH_RISK, DecisionVerdict.PHISHING})
        self.assertEqual(res.standardized_verdict, "HIGH RISK")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        self.assertTrue(res.structural_indicators["has_misleading_subdomain"])
        self.assertTrue(any("Brand impersonation detected" in exp for exp in res.evidence_based_explanation))

    def test_suspicious_shared_hosting_abuse(self):
        """Tier 2: Phishing on commonly abused platforms (firebaseapp.com, pages.dev, weebly.com) triggers SUSPICIOUS."""
        urls = [
            "https://dhl-package-tracking-alert.firebaseapp.com/track",
            "https://office365-password-reset.pages.dev/auth/",
            "https://account-security-update.weebly.com/login",
        ]
        for url in urls:
            self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

            mock_model = MagicMock()
            mock_model.predict_proba.return_value = np.array([[0.50, 0.50]])

            engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
            res = engine.evaluate_url(url)

            self.assertIn(res.verdict, {DecisionVerdict.SUSPICIOUS, DecisionVerdict.HIGH_RISK})
            self.assertIn(res.standardized_verdict, {"SUSPICIOUS", "HIGH RISK"})
            self.assertTrue(res.structural_indicators["has_hosting_abuse"])
            self.assertTrue(any("public shared-hosting platform" in exp for exp in res.evidence_based_explanation))

    # --- 3. COMPLEX LEGITIMATE URLS & ENTROPY CONTRAST TESTS ---

    def test_youtube_video_url_entropy_contrast_prevents_false_positive(self):
        """Tier 3: Target YouTube lecture URL with high query entropy is NOT marked PHISHING/HIGH_RISK."""
        url = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.06, 0.94]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.standardized_verdict, "INCONCLUSIVE")
        self.assertEqual(res.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(res.structural_indicators["has_entropy_contrast"])
        self.assertTrue(any("over-penalizing legitimate dynamic parameter structures" in exp for exp in res.evidence_based_explanation))
        self.assertTrue(any("Query-domain entropy contrast" in w for w in res.uncertainty_or_warnings))

    def test_multi_parameter_legitimate_urls(self):
        """Tier 3: Complex legitimate URLs on other platforms (Amazon, Google Scholar) avoid false positive blocking."""
        test_urls = [
            "https://scholar.google.com/scholar?hl=en&as_sdt=0%2C5&q=cybersecurity+random+forest&btnG=",
            "https://www.amazon.com/dp/B08N5WRWNW?ref_=cm_sw_r_cp_ud_dp&th=1",
        ]
        for url in test_urls:
            self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

            # Simulate an elevated ML score (e.g. 0.80) due to parameter complexity
            mock_model = MagicMock()
            mock_model.predict_proba.return_value = np.array([[0.20, 0.80]])

            engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
            res = engine.evaluate_url(url)

            # Must NOT be marked as confirmed malicious
            self.assertNotEqual(res.verdict, DecisionVerdict.CONFIRMED_MALICIOUS)
            self.assertIn(res.verdict, {DecisionVerdict.INCONCLUSIVE, DecisionVerdict.SUSPICIOUS})

    # --- 4. MODEL SCORE SPECTRUM & DISCLAIMERS ---

    def test_high_model_score_with_structural_red_flags(self):
        """Tier 3: High model score (>= 0.75) on suspicious TLD without entropy contrast triggers HIGH_RISK."""
        url = "https://bank-security-verification-portal.xyz/login.php?client=9812"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.10, 0.90]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertIn(res.verdict, {DecisionVerdict.HIGH_RISK, DecisionVerdict.PHISHING})
        self.assertEqual(res.standardized_verdict, "HIGH RISK")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)

    def test_medium_model_score_ambiguous_zone(self):
        """Tier 3: URL in ambiguous zone [0.35 - 0.75] without red flags triggers INCONCLUSIVE."""
        url = "https://unfamiliar-domain-test.com/resources/article-3891"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.45, 0.55]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.standardized_verdict, "INCONCLUSIVE")
        self.assertEqual(res.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(any("ambiguous confidence zone" in exp for exp in res.evidence_based_explanation))

    def test_low_model_score_contains_mandatory_safety_disclaimer(self):
        """Tier 3: Low model score URL is marked NO_KNOWN_THREAT but mandatorily includes the safety disclaimer."""
        url = "https://www.rmit.edu.au/about"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)

        self.assertIn(res.verdict, {DecisionVerdict.NO_KNOWN_THREAT, DecisionVerdict.LEGITIMATE})
        self.assertEqual(res.standardized_verdict, "NO KNOWN THREAT DETECTED")
        self.assertEqual(res.risk_level, RiskLevel.LOW)
        self.assertEqual(res.model_score, 0.05)
        # Check mandatory safety disclaimer
        has_disclaimer = any("NOT proof that a URL is legitimate or safe" in w for w in res.uncertainty_or_warnings)
        self.assertTrue(has_disclaimer)

    # --- 5. INPUT VALIDATION & MALFORMED RESPONSES ---

    def test_invalid_and_empty_input(self):
        """Test validation handling of empty or whitespace URL strings."""
        engine = LayeredDecisionEngine(threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url("   ")

        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
        self.assertIsNone(res.model_score)
        self.assertTrue(any("Input validation failed" in w for w in res.uncertainty_or_warnings))

    def test_to_dict_schema_structure(self):
        """Verify to_dict serialization contains both verdict and standardized_verdict."""
        url = "https://example.com/test"
        self.mock_intel_mgr.check_url.return_value = self._create_clean_intel_result(url)
        engine = LayeredDecisionEngine(threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url(url)
        d = res.to_dict()

        self.assertIn("url", d)
        self.assertIn("verdict", d)
        self.assertIn("standardized_verdict", d)
        self.assertIn("risk_level", d)
        self.assertIn("matched_threat_intel_sources", d)
        self.assertIn("evidence_based_explanation", d)
        self.assertIn("uncertainty_or_warnings", d)
        self.assertIn("structural_indicators", d)
        self.assertIn("threat_intel_summary", d)


if __name__ == "__main__":
    unittest.main()
