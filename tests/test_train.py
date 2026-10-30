"""Unit Tests for PhishGuardAI Model Training & Evaluation Engine

Tests feature ordering, shape compatibility, pipeline fitting, metric calculations,
joblib artifact serialization and deserialization, prediction on raw feature vectors,
data preservation, and seed reproducibility.
"""

import os
import unittest
import tempfile
import joblib
import pandas as pd
import numpy as np

from src.feature_extraction import URLFeatureExtractor
from src.train import (
    build_logistic_regression_pipeline,
    build_random_forest_model,
    evaluate_model,
    validate_training_inputs,
    save_model_artifacts
)


class TestModelTraining(unittest.TestCase):
    """Test suite for training and evaluation components."""

    def setUp(self):
        """Set up small synthetic fixtures for fast and deterministic unit tests."""
        self.feature_names = URLFeatureExtractor.FEATURE_NAMES
        np.random.seed(42)

        n_train = 100
        n_test = 30
        n_features = len(self.feature_names)  # 22

        # Synthetic feature matrix
        self.X_train = pd.DataFrame(
            np.random.randn(n_train, n_features),
            columns=self.feature_names
        )
        self.y_train = pd.Series(
            np.random.choice([0, 1], size=n_train, p=[0.8, 0.2]),
            name="label"
        )

        self.X_test = pd.DataFrame(
            np.random.randn(n_test, n_features),
            columns=self.feature_names
        )
        self.y_test = pd.Series(
            np.random.choice([0, 1], size=n_test, p=[0.8, 0.2]),
            name="label"
        )

    def test_feature_ordering_and_validation(self):
        """Verify that training input validation rejects misaligned features."""
        # Valid case
        validate_training_inputs(self.X_train, self.X_test, self.y_train, self.y_test, self.feature_names)

        # Misaligned columns case
        bad_cols = list(reversed(self.feature_names))
        bad_X = self.X_train[bad_cols]
        with self.assertRaises(ValueError) as ctx:
            validate_training_inputs(bad_X, self.X_test, self.y_train, self.y_test, self.feature_names)
        self.assertIn("columns do not match", str(ctx.exception))

    def test_shape_compatibility_validation(self):
        """Verify that mismatched row counts trigger a ValueError."""
        with self.assertRaises(ValueError) as ctx:
            validate_training_inputs(self.X_train.iloc[:-1], self.X_test, self.y_train, self.y_test, self.feature_names)
        self.assertIn("length", str(ctx.exception))

    def test_model_fitting_and_evaluation_metrics(self):
        """Verify that both Logistic Regression and Random Forest fit and evaluate correctly."""
        # Logistic Regression
        lr = build_logistic_regression_pipeline(random_state=42)
        lr.fit(self.X_train, self.y_train)
        eval_lr = evaluate_model(lr, self.X_test, self.y_test, "Logistic Regression")

        self.assertIn("accuracy", eval_lr)
        self.assertIn("phishing_precision", eval_lr)
        self.assertIn("phishing_recall", eval_lr)
        self.assertIn("phishing_f1", eval_lr)
        self.assertIn("roc_auc", eval_lr)
        self.assertIn("pr_auc", eval_lr)
        self.assertTrue(0.0 <= eval_lr["accuracy"] <= 1.0)
        self.assertTrue(0.0 <= eval_lr["roc_auc"] <= 1.0)

        # Random Forest
        rf = build_random_forest_model(random_state=42, n_jobs=1)
        rf.fit(self.X_train, self.y_train)
        eval_rf = evaluate_model(rf, self.X_test, self.y_test, "Random Forest")

        self.assertIn("accuracy", eval_rf)
        self.assertTrue(0.0 <= eval_rf["accuracy"] <= 1.0)

    def test_model_artifact_serialization_and_prediction(self):
        """Verify that saved artifacts can be reloaded and predict on raw 22-element vectors."""
        lr = build_logistic_regression_pipeline(random_state=42)
        lr.fit(self.X_train, self.y_train)
        eval_lr = evaluate_model(lr, self.X_test, self.y_test, "Logistic Regression")

        rf = build_random_forest_model(random_state=42, n_jobs=1)
        rf.fit(self.X_train, self.y_train)
        eval_rf = evaluate_model(rf, self.X_test, self.y_test, "Random Forest")

        models = {"logistic_regression": lr, "random_forest": rf}
        eval_results = {"logistic_regression": eval_lr, "random_forest": eval_rf}

        with tempfile.TemporaryDirectory() as temp_dir:
            saved_paths = save_model_artifacts(
                models=models,
                eval_results=eval_results,
                feature_names=self.feature_names,
                output_dir=temp_dir
            )

            # Check files exist
            self.assertTrue(os.path.exists(saved_paths["logistic_regression"]))
            self.assertTrue(os.path.exists(saved_paths["random_forest"]))
            self.assertTrue(os.path.exists(saved_paths["phishing_model"]))

            # Reload Random Forest artifact
            rf_artifact = joblib.load(saved_paths["random_forest"])
            self.assertIn("model", rf_artifact)
            self.assertIn("feature_names", rf_artifact)
            self.assertEqual(rf_artifact["feature_names"], self.feature_names)

            loaded_rf = rf_artifact["model"]

            # Test prediction on a sample 22-element vector with feature names
            sample_vector = pd.DataFrame(np.zeros((1, len(self.feature_names))), columns=self.feature_names)
            pred = loaded_rf.predict(sample_vector)
            prob = loaded_rf.predict_proba(sample_vector)

            self.assertIn(pred[0], [0, 1])
            self.assertEqual(prob.shape, (1, 2))
            self.assertAlmostEqual(prob[0].sum(), 1.0, places=5)

            # Reload Logistic Regression artifact and test prediction with pipeline scaler
            lr_artifact = joblib.load(saved_paths["logistic_regression"])
            loaded_lr_pipe = lr_artifact["model"]
            lr_pred = loaded_lr_pipe.predict(sample_vector)
            self.assertIn(lr_pred[0], [0, 1])

    def test_preservation_of_datasets_during_training(self):
        """Verify that training does not alter raw or processed CSV files on disk."""
        processed_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "processed"
        )
        test_csv_path = os.path.join(processed_dir, "X_test.csv")
        if not os.path.exists(test_csv_path):
            self.skipTest("data/processed/X_test.csv not found; skipping preservation test.")

        stat_before = os.stat(test_csv_path)

        # Run model fit and evaluation
        lr = build_logistic_regression_pipeline(random_state=42)
        lr.fit(self.X_train, self.y_train)
        _ = evaluate_model(lr, self.X_test, self.y_test, "Logistic Regression")

        stat_after = os.stat(test_csv_path)
        self.assertEqual(stat_before.st_size, stat_after.st_size)
        self.assertEqual(stat_before.st_mtime, stat_after.st_mtime)

    def test_reproducibility_with_fixed_seed(self):
        """Verify that identical models and predictions are produced across runs with seed 42."""
        rf1 = build_random_forest_model(random_state=42, n_jobs=1)
        rf1.fit(self.X_train, self.y_train)
        pred1 = rf1.predict_proba(self.X_test)

        rf2 = build_random_forest_model(random_state=42, n_jobs=1)
        rf2.fit(self.X_train, self.y_train)
        pred2 = rf2.predict_proba(self.X_test)

        np.testing.assert_array_almost_equal(pred1, pred2)


if __name__ == "__main__":
    unittest.main()
