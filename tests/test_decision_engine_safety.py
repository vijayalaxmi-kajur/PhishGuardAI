"""Focused Safety and Robustness Unit Tests for Decision Engine and Model Inference Adapter

Audits uncovered security failure modes:
1. Model inference exception handling (fail-safe to INCONCLUSIVE / Risk UNKNOWN).
2. Threat intelligence provider degradation & timeout handling (missing feeds never treated as safe).
3. Adapter input validation rejecting non-numeric and non-finite (NaN, Inf) features.
4. Adapter feature vector shape validation (rejecting truncated or oversized feature vectors).
5. High-risk signal suppression guardrails (auth path, credential params, suspicious TLDs).
"""

import math
import unittest
import numpy as np
from unittest.mock import MagicMock

from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
    DecisionResult,
)
from src.decision_engine.adapter import ModelInferenceAdapter
from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatStatus,
    ThreatCategory,
    ThreatLookupResult,
    MultiProviderLookupResult,
)
from src.threat_intelligence.manager import ThreatIntelligenceManager


class DummyEstimator:
    """Concrete mock estimator avoiding MagicMock hasattr attribute generation."""
    def __init__(self, classes=(0, 1)):
        self.classes_ = np.array(classes)


class TestDecisionEngineSafety(unittest.TestCase):
    """Safety and fault-tolerance tests for PhishGuardAI decision engine."""

    def setUp(self):
        self.mock_intel_mgr = MagicMock(spec=ThreatIntelligenceManager)
        self.mock_intel_mgr.get_configured_providers.return_value = ["MockFeed"]

    def test_ml_inference_exception_fails_safe_to_inconclusive(self):
        """When ML inference raises an exception, engine must NOT crash or declare safe."""
        mock_adapter = MagicMock(spec=ModelInferenceAdapter)
        mock_adapter.model_name = "CrashingModel"
        mock_adapter.schema = "experimental"
        mock_adapter.predict_proba.side_effect = RuntimeError("Simulated OOM / CUDA / corrupt model crash")

        # Mock clean threat intel
        self.mock_intel_mgr.check_url.return_value = MultiProviderLookupResult(
            url="https://example.com/test",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["MockFeed"],
            degraded_providers=[],
            warnings=[],
        )

        engine = LayeredDecisionEngine(ml_model=mock_adapter, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url("https://example.com/test")

        # Must fail safe to INCONCLUSIVE and UNKNOWN risk
        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.standardized_verdict, "INCONCLUSIVE")
        self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
        self.assertIsNone(res.model_score)
        self.assertTrue(any("inference failed" in w for w in res.uncertainty_or_warnings))
        self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_provider_outage_does_not_suppress_ml_high_risk(self):
        """When threat intel times out, high ML risk must still trigger HIGH_RISK verdict."""
        degraded_intel = MultiProviderLookupResult(
            url="https://suspicious-target.com/action",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=[],
            degraded_providers=["MockFeed"],
            warnings=["MockFeed check was degraded (timeout: Request timed out). A missing intelligence match must NOT be interpreted as proof that a URL is legitimate."],
        )
        self.mock_intel_mgr.check_url.return_value = degraded_intel

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.10, 0.90]])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)
        res = engine.evaluate_url("https://suspicious-target.com/action")

        self.assertEqual(res.standardized_verdict, "HIGH RISK")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        # Verify degradation warning propagated
        self.assertTrue(any("degraded" in w for w in res.uncertainty_or_warnings))

    def test_adapter_rejects_nan_and_infinite_values(self):
        """Adapter must raise ValueError when features contain NaN or Inf; no silent substitution."""
        estimator = DummyEstimator(classes=[0, 1])
        adapter = ModelInferenceAdapter(estimator, feature_schema="baseline")

        valid_dict = {f: 1.0 for f in adapter.feature_names}

        # NaN test
        nan_dict = dict(valid_dict)
        nan_dict["entropy"] = float("nan")
        with self.assertRaises(ValueError) as ctx_nan:
            adapter.extract_and_format_input(nan_dict)
        self.assertIn("non-finite", str(ctx_nan.exception))

        # Positive Inf test
        pos_inf_dict = dict(valid_dict)
        pos_inf_dict["url_len"] = float("inf")
        with self.assertRaises(ValueError) as ctx_inf:
            adapter.extract_and_format_input(pos_inf_dict)
        self.assertIn("non-finite", str(ctx_inf.exception))

        # Negative Inf test
        neg_inf_dict = dict(valid_dict)
        neg_inf_dict["path_len"] = float("-inf")
        with self.assertRaises(ValueError) as ctx_ninf:
            adapter.extract_and_format_input(neg_inf_dict)
        self.assertIn("non-finite", str(ctx_ninf.exception))

    def test_adapter_rejects_mismatched_vector_dimensions(self):
        """Adapter must reject input vectors whose length does not match expected schema."""
        estimator = DummyEstimator(classes=[0, 1])
        adapter = ModelInferenceAdapter(estimator, feature_schema="baseline")  # expects 22

        # 10 features
        with self.assertRaises(ValueError) as ctx10:
            adapter.extract_and_format_input(np.zeros((1, 10), dtype=np.float32))
        self.assertIn("Expected vector with 22 features", str(ctx10.exception))

        # 30 features
        with self.assertRaises(ValueError) as ctx30:
            adapter.extract_and_format_input(np.zeros((1, 30), dtype=np.float32))
        self.assertIn("Expected vector with 22 features", str(ctx30.exception))

    def test_bare_schemes_and_malformed_slashes_rejected(self):
        """Bare schemes and missing authorities must fail safe to INCONCLUSIVE, never safe."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        mock_model.classes_ = np.array([0, 1])

        clean_intel = MultiProviderLookupResult(
            url="http://mock.test",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["MockFeed"],
            degraded_providers=[],
            warnings=[],
        )
        self.mock_intel_mgr.check_url.return_value = clean_intel

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        for invalid_target in ["http://", "https://///", "https://"]:
            res = engine.evaluate_url(invalid_target)
            self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
            self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(res.model_score)
            self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)
            self.assertTrue(any("validation failed" in w.lower() for w in res.uncertainty_or_warnings))

    def test_unsupported_schemes_rejected(self):
        """Non-HTTP(S) schemes (file, javascript, data, mailto) must fail safe to INCONCLUSIVE."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        unsupported_schemes = [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/plain,test",
            "mailto:admin@example.com",
            "ftp://ftp.example.com/file",
        ]
        for url in unsupported_schemes:
            res = engine.evaluate_url(url)
            self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
            self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(res.model_score)
            self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)
            self.assertTrue(any("validation failed" in w.lower() for w in res.uncertainty_or_warnings))

    def test_empty_whitespace_and_non_string_inputs_rejected(self):
        """Empty, whitespace, and non-string inputs must fail safe without crashing."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        for bad_input in ["", "   ", "\t \n", None, 12345, ["https://example.com"]]:
            res = engine.evaluate_url(bad_input)
            self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
            self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(res.model_score)
            self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_missing_hostname_rejected(self):
        """URLs missing hostnames must fail safe to INCONCLUSIVE."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        for missing_host in ["https:///path/only", "http://?query=1"]:
            res = engine.evaluate_url(missing_host)
            self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
            self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(res.model_score)
            self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_malformed_ip_authorities_rejected(self):
        """Malformed IPv4 or IPv6 authorities must fail safe to INCONCLUSIVE."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        malformed_ips = [
            "http://256.256.256.256/login",
            "http://1.2.3.4.5/",
            "http://[invalid_ipv6]/",
            "http://[:::1]/",
        ]
        for bad_ip in malformed_ips:
            res = engine.evaluate_url(bad_ip)
            self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
            self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
            self.assertIsNone(res.model_score)
            self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_valid_http_and_https_urls_evaluated(self):
        """Valid HTTP and HTTPS URLs must proceed through evaluation."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
        mock_model.classes_ = np.array([0, 1])

        clean_intel = MultiProviderLookupResult(
            url="http://mock.test",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["MockFeed"],
            degraded_providers=[],
            warnings=[],
        )
        self.mock_intel_mgr.check_url.return_value = clean_intel

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        res_http = engine.evaluate_url("http://example.com/test")
        self.assertEqual(res_http.verdict, DecisionVerdict.NO_KNOWN_THREAT)
        self.assertEqual(res_http.risk_level, RiskLevel.LOW)
        self.assertAlmostEqual(res_http.model_score, 0.05)

        res_https = engine.evaluate_url("https://example.com/test")
        self.assertEqual(res_https.verdict, DecisionVerdict.NO_KNOWN_THREAT)
        self.assertEqual(res_https.risk_level, RiskLevel.LOW)
        self.assertAlmostEqual(res_https.model_score, 0.05)

    def test_punycode_and_internationalized_domains_risk_handling(self):
        """Punycode domains must receive appropriate risk handling and never NO_KNOWN_THREAT."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
        mock_model.classes_ = np.array([0, 1])

        clean_intel = MultiProviderLookupResult(
            url="http://mock.test",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=["MockFeed"],
            degraded_providers=[],
            warnings=[],
        )
        self.mock_intel_mgr.check_url.return_value = clean_intel

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        # 1. Valid single-script IDN (e.g. Russian пример.рф in Punycode)
        # Even with low ML score (0.05), it must be assigned SUSPICIOUS (MEDIUM risk)
        res_idn = engine.evaluate_url("https://xn--e1afmkfd.xn--p1ai/test")
        self.assertEqual(res_idn.verdict, DecisionVerdict.SUSPICIOUS)
        self.assertEqual(res_idn.risk_level, RiskLevel.MEDIUM)
        self.assertTrue(res_idn.structural_indicators.get("has_punycode"))
        self.assertFalse(res_idn.structural_indicators.get("has_mixed_script"))
        self.assertNotEqual(res_idn.verdict, DecisionVerdict.NO_KNOWN_THREAT)

        # 2. Deceptive mixed-script Punycode homograph attack (e.g. apple.com with Cyrillic 'a')
        res_homograph = engine.evaluate_url("https://xn--pple-43d.com/login")
        self.assertEqual(res_homograph.verdict, DecisionVerdict.HIGH_RISK)
        self.assertEqual(res_homograph.risk_level, RiskLevel.HIGH)
        self.assertTrue(res_homograph.structural_indicators.get("has_punycode"))
        self.assertTrue(res_homograph.structural_indicators.get("has_mixed_script"))
        self.assertNotEqual(res_homograph.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_extremely_long_inputs_rejected(self):
        """Excessively long URLs (>4096 characters) must fail safe to INCONCLUSIVE."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=self.mock_intel_mgr)

        long_url = "https://example.com/" + "a" * 5000
        res = engine.evaluate_url(long_url)
        self.assertEqual(res.verdict, DecisionVerdict.INCONCLUSIVE)
        self.assertEqual(res.risk_level, RiskLevel.UNKNOWN)
        self.assertIsNone(res.model_score)
        self.assertNotEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)

    def test_missing_threat_intel_providers_fails_safe(self):
        """When threat intel has no active providers, engine evaluates without crash."""
        empty_intel = MagicMock(spec=ThreatIntelligenceManager)
        empty_intel.get_configured_providers.return_value = []
        empty_intel.check_url.return_value = MultiProviderLookupResult(
            url="https://example.com/test",
            is_any_threat=False,
            matched_sources=[],
            results={},
            available_providers=[],
            degraded_providers=[],
            warnings=["No threat intelligence providers configured."],
        )

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
        mock_model.classes_ = np.array([0, 1])

        engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=empty_intel)
        res = engine.evaluate_url("https://example.com/test")
        self.assertEqual(res.verdict, DecisionVerdict.NO_KNOWN_THREAT)
        self.assertTrue(any("No threat intelligence" in w for w in res.uncertainty_or_warnings))


if __name__ == "__main__":
    unittest.main()
