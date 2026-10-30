"""Unit and regression tests for ModelInferenceAdapter and Pipeline Hardening

Verifies:
1. Feature Schema Compatibility:
   - 22-feature baseline schema vs 30-feature experimental schema
   - Named DataFrame formatting for models fitted with feature names
   - NumPy array formatting for models fitted without feature names
   - Zero scikit-learn warnings emitted during inference
2. Input Formatting & Validation:
   - Accepts URL strings, feature dictionaries, DataFrames, and NumPy vectors
   - Preserves exact feature order
   - Rejects missing features without silent zero substitution
   - Rejects non-numeric or non-finite values (NaN, Inf)
3. Dynamic Class Index Resolution:
   - Standard binary classes [0, 1]
   - Inverted binary classes [1, 0]
   - String class labels ['legitimate', 'phishing']
   - Rejects fitted models missing the positive phishing class
4. Standardized Threshold & Boundary Tie-Breaking Policy:
   - Strictly below threshold (prob < threshold -> Class 0)
   - Exactly at threshold (prob == threshold -> Class 1)
   - Strictly above threshold (prob > threshold -> Class 1)
   - Custom threshold configuration
5. Decision Engine Guardrails Hardening:
   - Brand names inside community platforms (apple.stackexchange.com -> NOT misleading)
   - Brand names inside regular words (pineapple-farms.com -> NOT misleading)
   - Deceptive brand spoofing (paypal.com.account-verification-notice.online -> MISLEADING)
   - Legitimate docs on shared hosting (myproject.github.io/docs/auth.html -> NOT abuse)
   - Credential harvesting on shared hosting (pages.dev/auth/login.php -> HOSTING ABUSE)
   - Entropy contrast guardrails blocking downgrade if login path or credentials present
"""

import unittest
import numpy as np
import pandas as pd
from unittest.mock import MagicMock
from sklearn.ensemble import RandomForestClassifier

from src.decision_engine.adapter import ModelInferenceAdapter
from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
)
from src.threat_intelligence.base import (
    MultiProviderLookupResult,
    ThreatLookupResult,
    ThreatStatus,
)
from src.threat_intelligence.manager import ThreatIntelligenceManager


class DummyEstimator:
    """Mock classifier implementing scikit-learn predict_proba interface."""
    def __init__(self, classes, proba_return, feature_names=None):
        self.classes_ = np.array(classes)
        self._proba_return = proba_return
        if feature_names is not None:
            self.feature_names_in_ = np.array(feature_names)

    def predict_proba(self, X):
        return np.array([self._proba_return])


class TestModelInferenceAdapter(unittest.TestCase):
    """Test suite for ModelInferenceAdapter feature validation, typing, and resolution."""

    def setUp(self):
        self.mock_intel_mgr = MagicMock(spec=ThreatIntelligenceManager)
        self.mock_intel_mgr.get_configured_providers.return_value = ["PhishTank", "URLhaus"]
        self.clean_intel = MultiProviderLookupResult(
            url="https://example.com",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["PhishTank", "URLhaus"],
            degraded_providers=[],
            warnings=[],
        )
        self.mock_intel_mgr.check_url.return_value = self.clean_intel

    # --- 1. FEATURE ORDERING & SCHEMA TESTS ---

    def test_preserves_exact_feature_ordering_baseline(self):
        """Adapter preserves the exact 22 baseline feature order."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.8, 0.2])
        adapter = ModelInferenceAdapter(dummy, feature_schema="baseline")
        self.assertEqual(adapter.feature_names, ModelInferenceAdapter.BASELINE_FEATURES)
        self.assertEqual(len(adapter.feature_names), 22)
        self.assertEqual(adapter.schema, "baseline")

    def test_preserves_exact_feature_ordering_experimental(self):
        """Adapter preserves the exact 30 experimental feature order."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.3, 0.7])
        adapter = ModelInferenceAdapter(dummy, feature_schema="experimental")
        self.assertEqual(adapter.feature_names, ModelInferenceAdapter.EXPERIMENTAL_FEATURES)
        self.assertEqual(len(adapter.feature_names), 30)
        self.assertEqual(adapter.schema, "experimental")

    def test_named_dataframe_formatting_when_fitted_with_feature_names(self):
        """When model has feature_names_in_, adapter formats input as named DataFrame."""
        dummy = DummyEstimator(
            classes=[0, 1],
            proba_return=[0.9, 0.1],
            feature_names=ModelInferenceAdapter.BASELINE_FEATURES,
        )
        adapter = ModelInferenceAdapter(dummy)
        formatted = adapter.extract_and_format_input("https://www.google.com/")
        self.assertIsInstance(formatted, pd.DataFrame)
        self.assertEqual(list(formatted.columns), ModelInferenceAdapter.BASELINE_FEATURES)

    def test_numpy_array_formatting_when_fitted_without_feature_names(self):
        """When model lacks feature_names_in_, adapter formats input as NumPy array."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.9, 0.1])
        adapter = ModelInferenceAdapter(dummy, feature_schema="baseline")
        formatted = adapter.extract_and_format_input("https://www.google.com/")
        self.assertIsInstance(formatted, np.ndarray)
        self.assertEqual(formatted.shape, (1, 22))

    def test_missing_feature_raises_error_without_silent_zero_substitution(self):
        """Missing feature in dict raises ValueError; zero is not silently substituted."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.5, 0.5])
        adapter = ModelInferenceAdapter(dummy, feature_schema="baseline")
        incomplete_dict = {"url_len": 25, "dom_len": 10}  # Missing 20 features
        with self.assertRaises(ValueError) as ctx:
            adapter.extract_and_format_input(incomplete_dict)
        self.assertIn("missing required feature", str(ctx.exception).lower())

    def test_non_finite_feature_raises_error(self):
        """NaN or infinite feature values raise ValueError."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.5, 0.5])
        adapter = ModelInferenceAdapter(dummy, feature_schema="baseline")
        bad_dict = {f: 1.0 for f in ModelInferenceAdapter.BASELINE_FEATURES}
        bad_dict["entropy"] = float("nan")
        with self.assertRaises(ValueError) as ctx:
            adapter.extract_and_format_input(bad_dict)
        self.assertIn("invalid non-numeric or non-finite", str(ctx.exception).lower())

    # --- 2. DYNAMIC CLASS INDEX RESOLUTION TESTS ---

    def test_class_index_standard_binary_classes(self):
        """Standard [0, 1] classes resolves phishing index to 1."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.8, 0.2])
        adapter = ModelInferenceAdapter(dummy)
        self.assertEqual(adapter.phishing_class_index, 1)
        self.assertAlmostEqual(adapter.predict_proba("https://example.com/"), 0.2)

    def test_class_index_inverted_binary_classes(self):
        """Inverted [1, 0] classes dynamically resolves phishing index to 0."""
        dummy = DummyEstimator(classes=[1, 0], proba_return=[0.85, 0.15])
        adapter = ModelInferenceAdapter(dummy)
        self.assertEqual(adapter.phishing_class_index, 0)
        self.assertAlmostEqual(adapter.predict_proba("https://example.com/"), 0.85)

    def test_class_index_string_labels(self):
        """String labels ['legitimate', 'phishing'] resolves phishing index to 1."""
        dummy = DummyEstimator(classes=["legitimate", "phishing"], proba_return=[0.4, 0.6])
        adapter = ModelInferenceAdapter(dummy)
        self.assertEqual(adapter.phishing_class_index, 1)
        self.assertAlmostEqual(adapter.predict_proba("https://example.com/"), 0.6)

    def test_missing_phishing_class_raises_error(self):
        """Model with classes lacking positive label (e.g. [0] only) raises explicit ValueError."""
        dummy = DummyEstimator(classes=[0], proba_return=[1.0])
        with self.assertRaises(ValueError) as ctx:
            ModelInferenceAdapter(dummy)
        self.assertIn("does not contain positive target label 1", str(ctx.exception))

    # --- 3. STANDARDIZED THRESHOLD & TIE-BREAKING TESTS ---

    def test_threshold_strictly_below(self):
        """Probability < threshold classifies as Legitimate (0)."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.51, 0.49])
        adapter = ModelInferenceAdapter(dummy, default_threshold=0.50)
        self.assertEqual(adapter.predict("https://example.com/"), 0)

    def test_threshold_exact_boundary_tie(self):
        """Probability == threshold boundary tie classifies as Phishing (1)."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.50, 0.50])
        adapter = ModelInferenceAdapter(dummy, default_threshold=0.50)
        self.assertEqual(adapter.predict("https://example.com/"), 1)

    def test_threshold_strictly_above(self):
        """Probability > threshold classifies as Phishing (1)."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.49, 0.51])
        adapter = ModelInferenceAdapter(dummy, default_threshold=0.50)
        self.assertEqual(adapter.predict("https://example.com/"), 1)

    def test_custom_threshold_configuration(self):
        """Custom threshold is respected at inference time."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.30, 0.70])
        adapter = ModelInferenceAdapter(dummy)
        # 0.70 is below a high 0.75 threshold
        self.assertEqual(adapter.predict("https://example.com/", threshold=0.75), 0)
        # 0.70 is equal or above 0.70 threshold
        self.assertEqual(adapter.predict("https://example.com/", threshold=0.70), 1)

    # --- 4. DECISION ENGINE GUARDRAILS HARDENING TESTS ---

    def test_brand_in_community_platform_not_misleading(self):
        """Apple in apple.stackexchange.com is recognized as community Q&A, NOT misleading spoofing."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.9, 0.1])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://apple.stackexchange.com/questions/12345/how-to-fix"
        res = engine.evaluate_url(url)
        self.assertFalse(res.structural_indicators["has_misleading_subdomain"])
        self.assertEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_brand_substring_inside_regular_word_not_misleading(self):
        """Pineapple in pineapple-farms.com is NOT flagged as Apple brand spoofing."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.9, 0.1])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://pineapple-farms.com/catalog"
        res = engine.evaluate_url(url)
        self.assertFalse(res.structural_indicators["has_misleading_subdomain"])
        self.assertEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_brand_subdomain_spoofing_flagged_as_high_risk(self):
        """paypal.com.account-verification-notice.online is flagged as brand spoofing HIGH_RISK."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.6, 0.4])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://paypal.com.account-verification-notice.online/webapps/mpp/home"
        res = engine.evaluate_url(url)
        self.assertTrue(res.structural_indicators["has_misleading_subdomain"])
        self.assertEqual(res.verdict, DecisionVerdict.HIGH_RISK)
        self.assertEqual(res.risk_level, RiskLevel.HIGH)

    def test_developer_docs_on_github_pages_not_hosting_abuse(self):
        """Technical documentation on github.io is NOT flagged as hosting abuse."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.9, 0.1])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://myproject.github.io/docs/authentication-overview.html"
        res = engine.evaluate_url(url)
        self.assertFalse(res.structural_indicators["has_hosting_abuse"])
        self.assertEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_active_credential_endpoint_on_free_hosting_flagged(self):
        """Active login path on cloud hosting pages.dev is flagged as hosting abuse SUSPICIOUS."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.6, 0.4])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://account-verify-portal.pages.dev/auth/login.php"
        res = engine.evaluate_url(url)
        self.assertTrue(res.structural_indicators["has_hosting_abuse"])
        self.assertEqual(res.verdict, DecisionVerdict.SUSPICIOUS)
        self.assertEqual(res.risk_level, RiskLevel.MEDIUM)

    def test_entropy_contrast_blocked_from_downgrade_when_auth_path_present(self):
        """Attacker cannot evade high-risk blocking by adding params to /login.php."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.1, 0.9])  # 90% phishing prob
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        # Contains 2 query params on a low entropy domain, BUT has /login.php
        url = "http://phish-portal.com/login.php?user=victim&lang=en"
        res = engine.evaluate_url(url)
        # Downgrade is blocked because has_auth_path is True!
        self.assertFalse(res.structural_indicators["has_entropy_contrast"])
        self.assertEqual(res.verdict, DecisionVerdict.HIGH_RISK)
        self.assertEqual(res.risk_level, RiskLevel.HIGH)

    def test_entropy_contrast_blocked_when_credentials_in_query(self):
        """URL with password/token parameter cannot trigger entropy contrast downgrade."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.1, 0.9])
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "http://phish-portal.com/view.php?email=victim@target.com&token=secret123"
        res = engine.evaluate_url(url)
        self.assertFalse(res.structural_indicators["has_entropy_contrast"])
        self.assertEqual(res.verdict, DecisionVerdict.HIGH_RISK)

    def test_benign_youtube_video_playlist_triggers_inconclusive_abstention(self):
        """Target YouTube educational video URL safely triggers INCONCLUSIVE abstention."""
        dummy = DummyEstimator(classes=[0, 1], proba_return=[0.1, 0.9])  # High ML score (90%)
        engine = LayeredDecisionEngine(ml_model=dummy, threat_intel_manager=self.mock_intel_mgr)
        url = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"
        res = engine.evaluate_url(url)
        self.assertTrue(res.structural_indicators["has_entropy_contrast"])
        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(any("Query-domain entropy contrast" in w for w in res.uncertainty_or_warnings))


if __name__ == "__main__":
    unittest.main()
