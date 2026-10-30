"""Unit Tests for PhishGuardAI Preprocessing Pipeline

Tests schema validation, duplicate detection, conflicting label prevention,
feature isolation, train/test leakage prevention, stratification ratios,
and split reproducibility.
"""

import os
import unittest
import tempfile
import pandas as pd
import numpy as np
from src.preprocess import DataPreprocessor
from src.feature_extraction import URLFeatureExtractor


class TestDataPreprocessor(unittest.TestCase):
    """Test suite for DataPreprocessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.preprocessor = DataPreprocessor(random_state=42, test_size=0.20)
        self.feature_names = URLFeatureExtractor.FEATURE_NAMES

        # Create a small synthetic mock DataFrame for unit testing logic
        self.mock_data = {
            "url": [
                "https://legit1.com",
                "https://legit2.com",
                "https://legit3.com",
                "https://legit4.com",
                "https://legit5.com",
                "https://phish1.com",
                "https://phish2.com",
                "https://phish3.com",
                "https://legit1.com",  # Exact duplicate URL with same label & features
            ],
            "dom": [
                "legit1.com", "legit2.com", "legit3.com", "legit4.com", "legit5.com",
                "phish1.com", "phish2.com", "phish3.com", "legit1.com"
            ],
            "tld": ["com"] * 9,
            "label": [0, 0, 0, 0, 0, 1, 1, 1, 0]
        }
        # Populate the 22 numerical features with deterministic dummy floats
        for feat in self.feature_names:
            self.mock_data[feat] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1.0]

        self.mock_df = pd.DataFrame(self.mock_data)

    def test_feature_selection_and_ordering(self):
        """Verify that isolate_features_and_target extracts exactly the 22 features in schema order."""
        X, y = self.preprocessor.isolate_features_and_target(self.mock_df)

        self.assertEqual(list(X.columns), self.feature_names)
        self.assertEqual(len(X.columns), 22)
        self.assertNotIn("url", X.columns)
        self.assertNotIn("dom", X.columns)
        self.assertNotIn("tld", X.columns)
        self.assertNotIn("label", X.columns)
        self.assertEqual(len(y), len(self.mock_df))

    def test_binary_labels_validation(self):
        """Verify that non-binary target labels trigger a ValueError."""
        bad_df = self.mock_df.copy()
        bad_df.loc[0, "label"] = 2  # Non-binary label
        with self.assertRaises(ValueError) as ctx:
            self.preprocessor.validate_schema(bad_df)
        self.assertIn("strictly binary", str(ctx.exception))

    def test_single_class_validation(self):
        """Verify that a dataset containing only one class triggers a ValueError."""
        single_class_df = self.mock_df.copy()
        single_class_df["label"] = 0  # Only legitimate
        with self.assertRaises(ValueError) as ctx:
            self.preprocessor.validate_schema(single_class_df)
        self.assertIn("must contain both legitimate (0) and phishing (1) classes", str(ctx.exception))

    def test_duplicate_url_handling(self):
        """Verify that deduplicate removes duplicate URL rows deterministically."""
        audit = self.preprocessor.audit_duplicates(self.mock_df)
        self.assertEqual(audit["duplicate_url_instances"], 1)

        clean_df = self.preprocessor.deduplicate(self.mock_df, keep="first")
        self.assertEqual(len(clean_df), 8)
        self.assertEqual(clean_df["url"].nunique(), 8)

    def test_detection_of_conflicting_url_labels(self):
        """Verify that conflicting labels for the same URL raise a ValueError."""
        conflicting_df = self.mock_df.copy()
        # Make the duplicate 'https://legit1.com' have label 1 instead of 0
        conflicting_df.loc[8, "label"] = 1

        with self.assertRaises(ValueError) as ctx:
            self.preprocessor.audit_duplicates(conflicting_df)
        self.assertIn("conflicting labels", str(ctx.exception).lower())

    def test_no_url_overlap_between_train_and_test(self):
        """Verify that no URL in the test set exists in the training set."""
        dataset_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dataset",
            "Dataset.csv"
        )
        if not os.path.exists(dataset_path):
            self.skipTest("dataset/Dataset.csv not found; skipping large data test.")

        df = self.preprocessor.load_dataset(dataset_path)
        df_clean = self.preprocessor.deduplicate(df, keep="first")
        X, y = self.preprocessor.isolate_features_and_target(df_clean)
        X_train, X_test, _, _ = self.preprocessor.split_data(X, y)

        clean_urls = df_clean["url"].values
        train_urls = set(clean_urls[X_train.index])
        test_urls = set(clean_urls[X_test.index])

        overlap = train_urls.intersection(test_urls)
        self.assertEqual(len(overlap), 0, "Data Leakage detected! URLs overlap between train and test.")

    def test_stratified_split_sizes_and_proportions(self):
        """Verify that the 80/20 stratified split preserves class proportions."""
        dataset_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dataset",
            "Dataset.csv"
        )
        if not os.path.exists(dataset_path):
            self.skipTest("dataset/Dataset.csv not found; skipping large data test.")

        df = self.preprocessor.load_dataset(dataset_path)
        df_clean = self.preprocessor.deduplicate(df, keep="first")
        X, y = self.preprocessor.isolate_features_and_target(df_clean)
        X_train, X_test, y_train, y_test = self.preprocessor.split_data(X, y)

        total_clean = len(df_clean)  # 115,231
        self.assertEqual(len(X_train), 92184)
        self.assertEqual(len(X_test), 23047)
        self.assertEqual(len(X_train) + len(X_test), total_clean)

        # Proportions check (within 0.05% tolerance)
        clean_prop_1 = (y == 1).mean()
        train_prop_1 = (y_train == 1).mean()
        test_prop_1 = (y_test == 1).mean()

        self.assertAlmostEqual(train_prop_1, clean_prop_1, places=3)
        self.assertAlmostEqual(test_prop_1, clean_prop_1, places=3)

    def test_preservation_of_original_dataset(self):
        """Verify that the original Dataset.csv file on disk is strictly unmodified."""
        dataset_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dataset",
            "Dataset.csv"
        )
        if not os.path.exists(dataset_path):
            self.skipTest("dataset/Dataset.csv not found; skipping test.")

        # Read mtime and size before operation
        stat_before = os.stat(dataset_path)

        # Run pipeline in a temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_report = os.path.join(temp_dir, "report.md")
            self.preprocessor.run_pipeline(
                dataset_path=dataset_path,
                output_dir=temp_dir,
                report_path=temp_report
            )

        # Verify mtime and size after operation
        stat_after = os.stat(dataset_path)
        self.assertEqual(stat_before.st_size, stat_after.st_size)
        self.assertEqual(stat_before.st_mtime, stat_after.st_mtime)

    def test_reproducibility_with_same_seed(self):
        """Verify that identical splits are produced across separate runs with random_state=42."""
        prep1 = DataPreprocessor(random_state=42, test_size=0.20)
        prep2 = DataPreprocessor(random_state=42, test_size=0.20)

        clean_df = self.mock_df.drop_duplicates(subset=["url"]).reset_index(drop=True)
        X, y = clean_df[self.feature_names], clean_df["label"]

        X_tr1, X_te1, y_tr1, y_te1 = prep1.split_data(X, y)
        X_tr2, X_te2, y_tr2, y_te2 = prep2.split_data(X, y)

        pd.testing.assert_frame_equal(X_tr1, X_tr2)
        pd.testing.assert_frame_equal(X_te1, X_te2)
        pd.testing.assert_series_equal(y_tr1, y_tr2)
        pd.testing.assert_series_equal(y_te1, y_te2)


if __name__ == "__main__":
    unittest.main()
