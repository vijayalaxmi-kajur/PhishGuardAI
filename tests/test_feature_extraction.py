"""Unit Tests for PhishGuardAI URL Feature Extraction Engine

Tests the URLFeatureExtractor across diverse scenarios including legitimate sites,
IP addresses, subdomains, special character combinations, schemeless inputs,
malformed inputs, and directly compares extractions against ground-truth
records from dataset/Dataset.csv.
"""

import os
import math
import unittest
import pandas as pd
from src.feature_extraction import URLFeatureExtractor


class TestURLFeatureExtraction(unittest.TestCase):
    """Test suite for URLFeatureExtractor class."""

    @classmethod
    def setUpClass(cls):
        """Initialize the extractor once for the test suite."""
        cls.extractor = URLFeatureExtractor()
        cls.expected_features = [
            "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt",
            "letter_cnt", "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt",
            "amp_cnt", "dot_cnt", "dash_cnt", "under_cnt", "letter_ratio",
            "digit_ratio", "spec_ratio", "is_https", "slash_cnt", "entropy",
            "path_len", "query_len"
        ]

    def _assert_valid_vector(self, vector):
        """Helper to verify vector shape, types, and finiteness."""
        self.assertEqual(len(vector), 22, "Extracted feature vector must contain exactly 22 features.")
        for idx, val in enumerate(vector):
            self.assertIsInstance(
                val, (int, float),
                f"Feature at index {idx} ({self.expected_features[idx]}) must be numeric."
            )
            self.assertTrue(
                math.isfinite(val),
                f"Feature at index {idx} ({self.expected_features[idx]}) must be finite (not NaN or Inf)."
            )

    def test_feature_names_order(self):
        """Verify that FEATURE_NAMES matches the exact required dataset schema order."""
        self.assertEqual(self.extractor.FEATURE_NAMES, self.expected_features)

    def test_scenario_1_legitimate_https_university(self):
        """Scenario 1: Legitimate HTTPS university URL."""
        url = "https://www.rmit.edu.au/"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["is_https"], 1)
        self.assertEqual(features["is_ip"], 0)
        self.assertEqual(features["url_len"], 24)
        self.assertEqual(features["dom_len"], 11)  # rmit.edu.au
        self.assertEqual(features["tld_len"], 6)   # edu.au
        self.assertEqual(features["subdom_cnt"], 1) # www

    def test_scenario_2_http_url(self):
        """Scenario 2: Plain HTTP URL."""
        url = "http://www.latrobe.edu.au/"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["is_https"], 0)
        self.assertEqual(features["is_ip"], 0)
        self.assertEqual(features["url_len"], 26)

    def test_scenario_3_multiple_subdomains(self):
        """Scenario 3: URL with nested/multiple subdomains."""
        url = "http://deep.sub1.sub2.example.co.uk/portal"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["subdom_cnt"], 3)  # deep.sub1.sub2
        self.assertEqual(features["tld_len"], 5)    # co.uk
        self.assertEqual(features["dom_len"], 13)   # example.co.uk

    def test_scenario_4_digits_and_special_characters(self):
        """Scenario 4: URL containing digits, hyphens, and underscores."""
        url = "https://secure-login_99.bank.com/session_id=12345"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertGreater(features["digit_cnt"], 0)
        self.assertGreater(features["dash_cnt"], 0)
        self.assertGreater(features["under_cnt"], 0)
        self.assertGreater(features["eq_cnt"], 0)
        # Verify ratio consistency
        total_ratio = features["letter_ratio"] + features["digit_ratio"] + features["spec_ratio"]
        self.assertAlmostEqual(total_ratio, 1.0, places=5)

    def test_scenario_5_path_and_query_parameters(self):
        """Scenario 5: URL containing explicit path and multi-parameter query."""
        url = "https://example.com/checkout/pay?item=book&qty=2&ref=partner_link"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["path_len"], len("/checkout/pay"))
        self.assertEqual(features["query_len"], len("item=book&qty=2&ref=partner_link"))
        self.assertEqual(features["qm_cnt"], 1)
        self.assertEqual(features["amp_cnt"], 2)
        self.assertEqual(features["eq_cnt"], 3)

    def test_scenario_6_ip_address_host(self):
        """Scenario 6: URL using an IP address instead of domain name."""
        url = "http://202.194.232.100:8005/english/index.asp"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["is_ip"], 1)
        self.assertEqual(features["tld_len"], 0)
        self.assertEqual(features["subdom_cnt"], 0)
        self.assertEqual(features["dom_len"], 15)  # len("202.194.232.100")

    def test_scenario_7_schemeless_url(self):
        """Scenario 7: URL without an explicit http/https scheme."""
        url = "www.google.com/search?q=phishing+detection"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertEqual(features["is_https"], 0)
        self.assertEqual(features["subdom_cnt"], 1)
        self.assertEqual(features["dom_len"], 10)  # google.com
        self.assertEqual(features["tld_len"], 3)   # com
        self.assertEqual(features["path_len"], len("/search"))
        self.assertEqual(features["query_len"], len("q=phishing+detection"))

    def test_scenario_8_empty_string(self):
        """Scenario 8: Empty or whitespace-only input."""
        features_empty = self.extractor.extract_features("")
        vector_empty = self.extractor.extract_vector("")
        self._assert_valid_vector(vector_empty)

        self.assertEqual(features_empty["url_len"], 0)
        self.assertEqual(features_empty["entropy"], 0.0)
        self.assertEqual(features_empty["letter_ratio"], 0.0)

        # None input handling
        vector_none = self.extractor.extract_vector(None)
        self._assert_valid_vector(vector_none)
        self.assertEqual(vector_none, vector_empty)

    def test_scenario_9_malformed_url(self):
        """Scenario 9: Highly malformed or syntactically invalid input."""
        malformed_inputs = [
            ":///?&#!@#",
            "http://",
            "https://///...",
            "???&&&===",
            "ftp://host"
        ]
        for bad_url in malformed_inputs:
            vector = self.extractor.extract_vector(bad_url)
            self._assert_valid_vector(vector)

    def test_scenario_10_unicode_characters(self):
        """Scenario 10: URL with internationalized / Unicode characters."""
        url = "https://example.com/café/résumé?user=αβγ"
        features = self.extractor.extract_features(url)
        vector = self.extractor.extract_vector(url)
        self._assert_valid_vector(vector)

        self.assertGreater(features["entropy"], 0.0)
        self.assertEqual(features["url_len"], len(url))

    def test_ground_truth_comparison_against_dataset(self):
        """Compare extracted features against actual records from dataset/Dataset.csv."""
        dataset_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dataset",
            "Dataset.csv"
        )
        if not os.path.exists(dataset_path):
            self.skipTest("dataset/Dataset.csv not found; skipping ground-truth comparison.")

        df = pd.read_csv(dataset_path, low_memory=False)

        # Test first 5 rows (benign), 5 IP rows, and 5 phishing rows
        sample_indices = [0, 1, 2, 3, 4, 1460, 25127, 100000, 100001, 107812, 116599]

        for idx in sample_indices:
            row = df.iloc[idx]
            url = row["url"]
            features = self.extractor.extract_features(url)

            for feat in self.expected_features:
                expected_val = row[feat]
                actual_val = features[feat]
                if isinstance(expected_val, float):
                    self.assertAlmostEqual(
                        actual_val, expected_val, places=4,
                        msg=f"Mismatch at index {idx} for feature '{feat}' on URL '{url}'."
                    )
                else:
                    self.assertEqual(
                        actual_val, expected_val,
                        msg=f"Mismatch at index {idx} for feature '{feat}' on URL '{url}'."
                    )


if __name__ == "__main__":
    unittest.main()
