"""Unit & Integration Tests for Domain Generalization & Independent Validation

Tests domain-aware grouping, zero domain overlap verification, determinism,
feature schema compatibility, experimental artifact persistence, metric calculation,
and strict preservation of existing production artifacts.
"""

import os
import unittest
import json
import joblib
import pandas as pd
import numpy as np

from src.feature_extraction import URLFeatureExtractor
from src.domain_validation import (
    create_domain_aware_split,
    train_domain_experimental_model,
    evaluate_model_on_domain_split,
    FEATURE_NAMES,
    PROJECT_ROOT
)


class DummyMockClassifier:
    """Mock classifier for testing evaluation metric calculations deterministically."""
    def __init__(self):
        self.classes_ = [0, 1]

    def predict(self, X):
        return np.array([1 if i % 2 == 0 else 0 for i in range(len(X))])

    def predict_proba(self, X):
        probs = []
        for i in range(len(X)):
            p1 = 0.8 if i % 2 == 0 else 0.2
            probs.append([1.0 - p1, p1])
        return np.array(probs)


class TestDomainGeneralization(unittest.TestCase):
    """Test suite for Phase 8 Domain Generalization Analysis."""

    @classmethod
    def setUpClass(cls):
        """Prepare sample data for lightweight test execution."""
        cls.extractor = URLFeatureExtractor()
        cls.X_train, cls.y_train, cls.X_test, cls.y_test, cls.meta = create_domain_aware_split(random_state=42)

    def test_domain_grouping_and_zero_overlap(self):
        """Verify that training and evaluation partitions have strictly ZERO domain overlap."""
        self.assertEqual(self.meta["domain_overlap_count"], 0)
        self.assertGreater(self.meta["train_domains_count"], 50000)
        self.assertGreater(self.meta["test_domains_count"], 10000)

        # Confirm total samples equal clean dataset count
        self.assertEqual(self.meta["train_samples"] + self.meta["test_samples"], 115231)

    def test_deterministic_partitioning(self):
        """Verify that identical random seed produces identical domain splits."""
        X_tr2, y_tr2, X_te2, y_te2, meta2 = create_domain_aware_split(random_state=42)

        self.assertEqual(self.meta["train_samples"], meta2["train_samples"])
        self.assertEqual(self.meta["test_samples"], meta2["test_samples"])
        self.assertEqual(self.meta["train_phishing_count"], meta2["train_phishing_count"])
        self.assertEqual(self.meta["test_phishing_count"], meta2["test_phishing_count"])

    def test_class_proportions_preservation(self):
        """Verify that the domain split preserves authentic ~14.4% phishing representation."""
        train_phish_pct = self.meta["train_phishing_pct"]
        test_phish_pct = self.meta["test_phishing_pct"]

        # Check within 0.1% tolerance of 14.40%
        self.assertAlmostEqual(train_phish_pct, 14.40, delta=0.1)
        self.assertAlmostEqual(test_phish_pct, 14.40, delta=0.1)

    def test_feature_schema_compatibility(self):
        """Verify that the domain split features match the exact 22-feature schema order."""
        self.assertEqual(list(self.X_train.columns), FEATURE_NAMES)
        self.assertEqual(list(self.X_test.columns), FEATURE_NAMES)
        self.assertEqual(len(FEATURE_NAMES), 22)
        self.assertEqual(FEATURE_NAMES, self.extractor.FEATURE_NAMES)

    def test_evaluation_metric_calculation(self):
        """Verify that evaluate_model_on_domain_split computes all required valid metrics."""
        mock_model = DummyMockClassifier()
        dummy_X = pd.DataFrame(np.zeros((10, 22)), columns=FEATURE_NAMES)
        dummy_y = pd.Series([1, 0, 1, 0, 1, 0, 1, 0, 1, 0])

        metrics = evaluate_model_on_domain_split(mock_model, dummy_X, dummy_y)

        # Check all required keys exist
        required_keys = [
            "accuracy", "phishing_precision", "phishing_recall", "phishing_f1",
            "macro_f1", "weighted_f1", "confusion_matrix", "roc_auc",
            "pr_auc", "brier_score", "calibration_bins", "sample_size"
        ]
        for k in required_keys:
            self.assertIn(k, metrics)

        # Check metric ranges [0, 1]
        self.assertTrue(0.0 <= metrics["accuracy"] <= 1.0)
        self.assertTrue(0.0 <= metrics["phishing_precision"] <= 1.0)
        self.assertTrue(0.0 <= metrics["phishing_recall"] <= 1.0)
        self.assertTrue(0.0 <= metrics["phishing_f1"] <= 1.0)
        self.assertTrue(0.0 <= metrics["brier_score"] <= 1.0)

        # Check confusion matrix counts
        cm = metrics["confusion_matrix"]
        self.assertEqual(cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"], 10)

    def test_experimental_artifact_serialization_and_reload(self):
        """Verify that the experimental model artifact exists, loads, and predicts properly."""
        exp_artifact_path = os.path.join(PROJECT_ROOT, "models", "experiments", "domain_heldout_random_forest.joblib")
        self.assertTrue(os.path.exists(exp_artifact_path), "Experimental model artifact not found.")

        artifact = joblib.load(exp_artifact_path)
        self.assertIsInstance(artifact, dict)
        self.assertIn("model", artifact)
        self.assertIn("feature_names", artifact)
        self.assertIn("split_type", artifact)
        self.assertEqual(artifact["split_type"], "domain_held_out")

        model = artifact["model"]
        self.assertTrue(hasattr(model, "predict_proba"))
        self.assertEqual(len(artifact["feature_names"]), 22)

        # Test inference on dummy 22-feature vector
        sample_vec = pd.DataFrame([np.zeros(22)], columns=FEATURE_NAMES)
        probs = model.predict_proba(sample_vec)
        self.assertEqual(probs.shape, (1, 2))
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=4)

    def test_preservation_of_production_artifacts(self):
        """Verify that existing production models, processed datasets, and raw dataset are untouched."""
        prod_model_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib")
        self.assertTrue(os.path.exists(prod_model_path))

        raw_dataset_path = os.path.join(PROJECT_ROOT, "dataset", "Dataset.csv")
        self.assertTrue(os.path.exists(raw_dataset_path))

        # Check raw row count remains 116,600
        with open(raw_dataset_path, "r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f) - 1
        self.assertEqual(line_count, 116600)

        # Check processed splits remain intact
        for fname in ["train.csv", "test.csv", "X_train.csv", "X_test.csv", "y_train.csv", "y_test.csv"]:
            p = os.path.join(PROJECT_ROOT, "data", "processed", fname)
            self.assertTrue(os.path.exists(p), f"Missing processed file: {fname}")


if __name__ == "__main__":
    unittest.main()
