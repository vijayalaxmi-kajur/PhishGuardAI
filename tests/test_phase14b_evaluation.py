"""
PhishGuardAI - Phase 14B Independent Evaluation Automated Tests
Verifies evaluation matrix integrity, model inference reproducibility, offline decision engine
benchmarking, and statistical confidence calculations without modifying existing tests.
"""

import os
import unittest
import pandas as pd
import numpy as np
import joblib

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel
from src.decision_engine.adapter import ModelInferenceAdapter
from src.threat_intelligence.manager import ThreatIntelligenceManager

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_FILE = os.path.join(PROJECT_ROOT, "data", "phase14a", "phase14a_verified_evaluation_set.csv")
X_FILE = os.path.join(PROJECT_ROOT, "data", "phase14a", "X_eval_30f.csv")
Y_FILE = os.path.join(PROJECT_ROOT, "data", "phase14a", "y_eval.csv")
CAND04_PATH = os.path.join(PROJECT_ROOT, "models", "experiments", "phase13c2", "cand04_rf_regularized_30f.joblib")
CAND06_PATH = os.path.join(PROJECT_ROOT, "models", "experiments", "phase13c2", "cand06_hist_gbdt_30f.joblib")


class TestPhase14BEvaluation(unittest.TestCase):
    """Test suite for Phase 14B evaluation artifacts, models, and decision engine benchmarking."""

    def test_evaluation_dataset_integrity(self):
        """Verify that the locked evaluation dataset exists with exact expected counts."""
        self.assertTrue(os.path.exists(DATA_FILE), f"Dataset not found at {DATA_FILE}")
        df = pd.read_csv(DATA_FILE)
        self.assertEqual(len(df), 963, "Evaluation dataset must contain exactly 963 rows")
        counts = df["label"].value_counts().to_dict()
        self.assertEqual(counts.get(1), 800, "Must contain exactly 800 verified phishing URLs")
        self.assertEqual(counts.get(0), 163, "Must contain exactly 163 verified legitimate URLs")

    def test_feature_matrix_integrity(self):
        """Verify that X_eval_30f and y_eval match expected dimensions, types, and have no NaNs."""
        self.assertTrue(os.path.exists(X_FILE), "X_eval_30f.csv must exist")
        self.assertTrue(os.path.exists(Y_FILE), "y_eval.csv must exist")
        
        X = pd.read_csv(X_FILE)
        y = pd.read_csv(Y_FILE).squeeze()
        
        self.assertEqual(X.shape, (963, 30), "Feature matrix must have shape (963, 30)")
        self.assertEqual(len(y), 963, "Target labels must have length 963")
        self.assertFalse(X.isna().any().any(), "Feature matrix must contain zero NaN values")
        self.assertFalse(np.isinf(X.values).any(), "Feature matrix must contain zero infinite values")

    def test_candidate_models_loaded_and_predict(self):
        """Verify that Candidate 4 and Candidate 6 load and produce valid probabilities."""
        self.assertTrue(os.path.exists(CAND04_PATH), "Cand04 artifact must exist")
        self.assertTrue(os.path.exists(CAND06_PATH), "Cand06 artifact must exist")
        
        c04 = joblib.load(CAND04_PATH)
        c06 = joblib.load(CAND06_PATH)
        
        X_sample = pd.read_csv(X_FILE, nrows=10)
        p04 = c04.predict_proba(X_sample)[:, 1]
        p06 = c06.predict_proba(X_sample)[:, 1]
        
        self.assertEqual(len(p04), 10)
        self.assertEqual(len(p06), 10)
        self.assertTrue(np.all((p04 >= 0.0) & (p04 <= 1.0)), "Probabilities must be in [0, 1]")
        self.assertTrue(np.all((p06 >= 0.0) & (p06 <= 1.0)), "Probabilities must be in [0, 1]")

    def test_decision_engine_offline_mock_benchmarking(self):
        """Verify that LayeredDecisionEngine operates cleanly in offline mock mode without network calls."""
        c06 = joblib.load(CAND06_PATH)
        mock_intel = ThreatIntelligenceManager(providers=[])
        engine = LayeredDecisionEngine(
            ml_model=c06,
            feature_schema="experimental",
            threat_intel_manager=mock_intel,
            model_name="Cand06_HistGBDT_30f"
        )
        
        test_url = "https://doc.rust-lang.org/std/collections/struct.HashMap.html"
        result = engine.evaluate_url(test_url)
        
        self.assertIsNotNone(result.verdict)
        self.assertIsNotNone(result.risk_level)
        self.assertIsInstance(result.standardized_verdict, str)
        self.assertEqual(len(result.matched_threat_intel_sources), 0, "Mock mode must have 0 external threat matches")

    def test_wilson_confidence_interval_bounds(self):
        """Verify that the Wilson score interval produces valid mathematical bounds."""
        from scratch.phase14b_extract_and_evaluate import wilson_interval
        
        low, high = wilson_interval(800, 963, 0.95)
        self.assertTrue(0.0 <= low <= high <= 1.0)
        self.assertAlmostEqual(low, 0.8055, delta=0.01)
        self.assertAlmostEqual(high, 0.8527, delta=0.01)


if __name__ == "__main__":
    unittest.main()
