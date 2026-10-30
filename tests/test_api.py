"""Unit Tests for PhishGuardAI REST API & SQLite Scan History

Tests database initialization, scan URL validation, scheme restrictions,
feature ordering, class 1 probability mapping, pagination, history deletion,
health checks, error handling, and confirms zero network calls are made.
"""

import os
import unittest
import tempfile
import json
from unittest.mock import patch

from app import create_app
from src.database import (
    initialize_database,
    save_scan,
    get_scan_history,
    delete_scan_history,
    get_scan_count
)
from src.feature_extraction import URLFeatureExtractor


class DummyMockModel:
    """Mock ML model for testing probability extraction and class index mapping."""
    def __init__(self, classes=(0, 1), phishing_prob=0.85):
        self.classes_ = np_classes = [c for c in classes]
        self.phishing_prob = phishing_prob
        self.n_features_in_ = 22

    def predict_proba(self, X):
        # Determine index of class 1
        idx_1 = self.classes_.index(1)
        prob_1 = self.phishing_prob
        prob_0 = 1.0 - prob_1
        if idx_1 == 1:
            return [[prob_0, prob_1]]
        else:
            return [[prob_1, prob_0]]


class TestAPIAndDatabase(unittest.TestCase):
    """Test suite for Flask API endpoints and SQLite database operations."""

    def setUp(self):
        """Set up an isolated temporary database and test Flask client."""
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.test_db_path = os.path.join(self.temp_dir.name, "test_scans.db")

        # Initialize the app with test configuration
        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path
        })
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up temporary directory and database."""
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # --- 1. Database Operations Tests ---

    def test_database_initialization(self):
        """Verify successful database file and table creation."""
        success = initialize_database(self.test_db_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.test_db_path))

    def test_database_save_and_retrieve(self):
        """Verify saving and retrieving records from SQLite."""
        scan_id = save_scan(
            url="https://legitimate-test.com",
            verdict="legitimate",
            phishing_probability=0.04,
            confidence_percent=96.0,
            db_path=self.test_db_path
        )
        self.assertGreater(scan_id, 0)

        history = get_scan_history(limit=10, db_path=self.test_db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "https://legitimate-test.com")
        self.assertEqual(history[0]["verdict"], "legitimate")
        self.assertAlmostEqual(history[0]["phishing_probability"], 0.04)

    def test_database_delete_history(self):
        """Verify that delete_scan_history clears records while preserving the DB file."""
        save_scan("https://site1.com", "legitimate", 0.1, 90.0, db_path=self.test_db_path)
        save_scan("https://site2.com", "phishing", 0.9, 90.0, db_path=self.test_db_path)
        self.assertEqual(get_scan_count(self.test_db_path), 2)

        deleted = delete_scan_history(self.test_db_path)
        self.assertEqual(deleted, 2)
        self.assertEqual(get_scan_count(self.test_db_path), 0)
        self.assertTrue(os.path.exists(self.test_db_path))

    # --- 2. API Health Endpoint Tests ---

    def test_api_health_status(self):
        """Verify that GET /api/health returns valid operational status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("status", data)
        self.assertIn("model_loaded", data)
        self.assertIn("database_ready", data)
        self.assertTrue(data["model_loaded"])
        self.assertTrue(data["database_ready"])

    def test_api_health_degraded_when_model_missing(self):
        """Verify that GET /api/health returns degraded status if model fails to load."""
        app_no_model = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path,
            "MODEL_PATH": os.path.join(self.temp_dir.name, "non_existent_model.joblib")
        })
        client_no_model = app_no_model.test_client()

        response = client_no_model.get("/api/health")
        self.assertEqual(response.status_code, 503)
        data = response.get_json()
        self.assertEqual(data["status"], "degraded")
        self.assertFalse(data["model_loaded"])

    # --- 3. POST /api/scan Validation & Prediction Tests ---

    def test_scan_successful_valid_url(self):
        """Verify successful scan of a legitimate URL."""
        payload = {"url": "https://www.rmit.edu.au/"}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["url"], "https://www.rmit.edu.au/")
        self.assertIn(data["verdict"], ("legitimate", "phishing"))
        self.assertTrue(0.0 <= data["phishing_probability"] <= 1.0)
        self.assertTrue(0.0 <= data["confidence_percent"] <= 100.0)
        self.assertEqual(data["threshold"], 0.5)
        self.assertIn("scanned_at", data)
        self.assertIn("feature_breakdown", data)
        self.assertIn(len(data["feature_breakdown"]), (22, 30))

        # Confirm persisted in DB
        history = get_scan_history(limit=1, db_path=self.test_db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["url"], "https://www.rmit.edu.au/")

    def test_scan_rejection_missing_body_or_invalid_json(self):
        """Verify rejection of non-JSON requests."""
        response = self.client.post("/api/scan", data="not json", content_type="text/plain")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])

    def test_scan_rejection_missing_url_field(self):
        """Verify rejection when 'url' key is missing."""
        response = self.client.post("/api/scan", json={"target": "https://example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Field 'url' is required", response.get_json()["error"])

    def test_scan_rejection_empty_url(self):
        """Verify rejection of empty or whitespace URL."""
        for empty_val in ["", "   ", "\t\n"]:
            response = self.client.post("/api/scan", json={"url": empty_val})
            self.assertEqual(response.status_code, 400)
            self.assertIn("cannot be empty", response.get_json()["error"])

    def test_scan_rejection_non_string_url(self):
        """Verify rejection when URL is not a string."""
        for non_str in [12345, True, ["https://example.com"], {"url": "nested"}]:
            response = self.client.post("/api/scan", json={"url": non_str})
            self.assertEqual(response.status_code, 400)
            self.assertIn("must be a string", response.get_json()["error"])

    def test_scan_rejection_unsupported_schemes(self):
        """Verify rejection of schemes other than http and https."""
        forbidden_schemes = [
            "ftp://ftp.example.com/file.zip",
            "javascript:alert('xss')",
            "file:///etc/passwd",
            "data:text/html;base64,PHNjcmlwdD4=",
            "mailto:admin@example.com",
            "tel:+123456789"
        ]
        for bad_url in forbidden_schemes:
            response = self.client.post("/api/scan", json={"url": bad_url})
            self.assertEqual(response.status_code, 400)
            self.assertIn("Unsupported URL scheme", response.get_json()["error"])

    def test_scan_rejection_missing_hostname(self):
        """Verify rejection of URLs lacking a hostname or domain."""
        bad_urls = ["https://", "http://", "https:///path/only"]
        for bad_url in bad_urls:
            response = self.client.post("/api/scan", json={"url": bad_url})
            self.assertEqual(response.status_code, 400)
            self.assertIn("missing domain or host", response.get_json()["error"].lower())

    def test_scan_rejection_excessive_url_length(self):
        """Verify rejection of URLs exceeding 2048 characters."""
        oversized_url = "https://example.com/" + ("a" * 2050)
        response = self.client.post("/api/scan", json={"url": oversized_url})
        self.assertEqual(response.status_code, 400)
        self.assertIn("maximum allowed length", response.get_json()["error"])

    def test_scan_probability_mapping_with_reversed_classes(self):
        """Verify correct class 1 probability mapping regardless of model.classes_ ordering."""
        # Test mock with classes_ = [1, 0] (reversed order)
        mock_reversed = DummyMockModel(classes=[1, 0], phishing_prob=0.88)
        app_mock = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path,
            "MOCK_MODEL": mock_reversed
        })
        client_mock = app_mock.test_client()

        response = client_mock.post("/api/scan", json={"url": "https://test-phishing-url.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["verdict"], "phishing")
        self.assertAlmostEqual(data["phishing_probability"], 0.88)
        self.assertEqual(data["confidence_percent"], 88.0)

    def test_scan_model_unavailable_returns_503(self):
        """Verify that /api/scan returns 503 if the model is not loaded."""
        app_no_model = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path,
            "MODEL_PATH": os.path.join(self.temp_dir.name, "missing.joblib")
        })
        client_no_model = app_no_model.test_client()

        response = client_no_model.post("/api/scan", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("not loaded", response.get_json()["error"])

    def test_scan_never_makes_external_network_requests(self):
        """Verify that processing a URL scan performs zero external network calls."""
        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("socket.socket") as mock_socket:
            response = self.client.post("/api/scan", json={"url": "https://suspicious-test-domain-12345.com/login"})
            self.assertEqual(response.status_code, 200)
            mock_urlopen.assert_not_called()

    # --- 4. History Endpoints Tests ---

    def test_get_history_empty(self):
        """Verify GET /api/history returns empty list when no records exist."""
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["history"], [])

    def test_get_history_pagination_and_validation(self):
        """Verify pagination parameters (limit and offset) and error validation."""
        # Insert 5 test records
        for i in range(5):
            save_scan(f"https://site{i}.com", "legitimate", 0.05, 95.0, db_path=self.test_db_path)

        # Test limit=2, offset=0
        resp = self.client.get("/api/history?limit=2&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["total"], 5)
        self.assertEqual(data["history"][0]["url"], "https://site4.com")  # Newest first

        # Test offset=3
        resp_off = self.client.get("/api/history?limit=2&offset=3")
        self.assertEqual(resp_off.status_code, 200)
        data_off = resp_off.get_json()
        self.assertEqual(data_off["count"], 2)
        self.assertEqual(data_off["history"][0]["url"], "https://site1.com")

        # Invalid parameters
        self.assertEqual(self.client.get("/api/history?limit=0").status_code, 400)
        self.assertEqual(self.client.get("/api/history?limit=abc").status_code, 400)
        self.assertEqual(self.client.get("/api/history?offset=-1").status_code, 400)

    def test_delete_history(self):
        """Verify DELETE /api/history clears all scan history."""
        save_scan("https://site1.com", "legitimate", 0.05, 95.0, db_path=self.test_db_path)
        save_scan("https://site2.com", "phishing", 0.95, 95.0, db_path=self.test_db_path)

        response = self.client.delete("/api/history")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["deleted_records"], 2)

        # Confirm history is now empty
        resp_check = self.client.get("/api/history")
        self.assertEqual(resp_check.get_json()["count"], 0)

    def test_scan_decision_engine_inconclusive_verdict(self):
        """Verify that dynamic query contrast produces an INCONCLUSIVE verdict rather than a false positive."""
        mock_model = DummyMockModel(classes=[0, 1], phishing_prob=0.92)
        app_mock = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path,
            "MOCK_MODEL": mock_model
        })
        client_mock = app_mock.test_client()
        payload = {"url": "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4"}
        response = client_mock.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["verdict"], "inconclusive")
        self.assertEqual(data["standardized_verdict"], "INCONCLUSIVE")
        self.assertEqual(data["risk_level"], "medium")
        self.assertIn("explanation", data)
        self.assertIn("warnings", data)
        self.assertTrue(len(data["explanation"]) > 0)

    def test_scan_explainability_payload(self):
        """Verify that scan responses include structured explanation, warnings, and risk level."""
        payload = {"url": "https://unstop.com/blog/infosys-aptitude-questions"}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["verdict"], "legitimate")
        self.assertEqual(data["risk_level"], "low")
        self.assertEqual(data["standardized_verdict"], "NO KNOWN THREAT DETECTED")
        self.assertIn("feature_breakdown", data)
        self.assertEqual(len(data["feature_breakdown"]), 30)

    @patch("app.check_website_presence")
    def test_scan_website_not_present_halts_and_reports_clean_status(self, mock_presence):
        """Verify that when a website is not present on the internet, analysis halts and reports WEBSITE NOT PRESENT."""
        mock_presence.return_value = (
            False,
            "Domain 'fake-nonexistent-domain-999.com' does not exist in DNS (NXDOMAIN / Name Not Resolved).",
            {"dns_resolved": False, "resolved_ip": None, "http_status": None, "reason": "dns_nxdomain"}
        )
        app_with_check = create_app({
            "TESTING": True,
            "CHECK_WEBSITE_PRESENCE": True,
            "DATABASE_PATH": self.test_db_path
        })
        client = app_with_check.test_client()

        response = client.post("/api/scan", json={"url": "https://fake-nonexistent-domain-999.com/login"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertFalse(data["website_present"])
        self.assertEqual(data["verdict"], "website_not_present")
        self.assertEqual(data["standardized_verdict"], "WEBSITE NOT PRESENT")
        self.assertEqual(data["risk_level"], "unknown")
        self.assertEqual(data["phishing_probability"], 0.0)
        self.assertEqual(data["confidence_percent"], 0.0)
        self.assertEqual(data["feature_breakdown"], {})
        self.assertTrue(len(data["explanation"]) > 0)
        self.assertIn("Live Presence Check", data["explanation"][0])
        self.assertIn("NXDOMAIN", data["presence_message"])

    @patch("app.check_website_presence")
    def test_scan_website_present_proceeds_to_ml_inference(self, mock_presence):
        """Verify that when a website is verified present, normal ML inference proceeds."""
        mock_presence.return_value = (
            True,
            "Website is online and reachable (HTTP 200).",
            {"dns_resolved": True, "resolved_ip": "142.250.190.46", "http_status": 200, "reason": "reachable"}
        )
        app_with_check = create_app({
            "TESTING": True,
            "CHECK_WEBSITE_PRESENCE": True,
            "DATABASE_PATH": self.test_db_path
        })
        client = app_with_check.test_client()

        response = client.post("/api/scan", json={"url": "https://www.google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertTrue(data["success"])
        self.assertTrue(data["website_present"])
        self.assertEqual(data["verdict"], "legitimate")
        self.assertIn("Website is online", data["presence_message"])


if __name__ == "__main__":
    unittest.main()
