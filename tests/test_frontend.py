"""Integration and Frontend Tests for PhishGuardAI Web Dashboard

Validates that:
1. GET / serves the HTML5 dashboard with HTTP 200.
2. The dashboard template contains the URL scanner, summary metrics,
   result presentation, 22-feature analysis, and scan history table.
3. Static assets (/static/css/style.css and /static/js/app.js) are accessible.
4. Content negotiation serves JSON sitemap when explicitly requested.
5. End-to-end integration across health, scan, history, and deletion endpoints.
"""

import os
import unittest
import tempfile
import gc

from app import create_app
from src.database import initialize_database, save_scan, get_scan_history


class TestFrontendDashboard(unittest.TestCase):
    """Test suite for the PhishGuardAI HTML5/CSS3/JS Web Dashboard."""

    def setUp(self):
        """Set up an isolated temporary database and Flask test client."""
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.test_db_path = os.path.join(self.temp_dir.name, "frontend_test.db")

        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.test_db_path
        })
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up test resources and temporary files safely."""
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_root_route_serves_html_dashboard(self):
        """Verify that GET / returns HTTP 200 and text/html."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        html = response.get_data(as_text=True)
        self.assertIn("PhishGuardAI", html)
        self.assertIn("Intelligent Phishing URL Detection", html)

    def test_homepage_contains_url_scanner_elements(self):
        """Verify the presence of URL input form, scan button, and helper text."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertIn('id="scan-form"', html)
        self.assertIn('id="url-input"', html)
        self.assertIn('id="btn-scan"', html)
        self.assertIn('maxlength="2048"', html)
        self.assertIn('placeholder="Enter full URL', html)
        self.assertIn('Supported schemes: <code>http://</code> and <code>https://</code>', html)

    def test_homepage_contains_summary_cards(self):
        """Verify that summary metric cards for health and scan counts exist."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertIn('id="stat-health-status"', html)
        self.assertIn('id="stat-total-scans"', html)
        self.assertIn('id="stat-legit-scans"', html)
        self.assertIn('id="stat-phish-scans"', html)

    def test_homepage_contains_prediction_and_meter_containers(self):
        """Verify that the prediction result, probability meter, and disclaimer exist."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertIn('id="prediction-section"', html)
        self.assertIn('id="verdict-title"', html)
        self.assertIn('id="result-prob-value"', html)
        self.assertIn('id="result-confidence-value"', html)
        self.assertIn('id="result-threshold-value"', html)
        self.assertIn('id="meter-progressbar"', html)
        self.assertIn('id="meter-fill"', html)
        # Verify required safety disclaimer
        self.assertIn("This result is a machine-learning prediction based exclusively on 22 passive", html)
        self.assertIn("It does not guarantee that a website is safe or malicious", html)

    def test_homepage_contains_feature_analysis_section(self):
        """Verify the 22-feature analysis breakdown container and search filter exist."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertIn('id="feature-section"', html)
        self.assertIn('id="features-grid"', html)
        self.assertIn('id="feature-search"', html)
        self.assertIn("22-Feature Classifier Input Breakdown", html)

    def test_homepage_contains_scan_history_and_modal(self):
        """Verify that scan history table, controls, and confirmation modal exist."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertIn('id="history-table"', html)
        self.assertIn('id="history-tbody"', html)
        self.assertIn('id="btn-refresh-history"', html)
        self.assertIn('id="btn-clear-history"', html)
        self.assertIn('id="modal-clear-history"', html)
        self.assertIn('id="btn-confirm-clear"', html)
        self.assertIn('id="btn-cancel-clear"', html)

    def test_static_css_stylesheet_available(self):
        """Verify that static/css/style.css is served with HTTP 200 and valid CSS."""
        response = self.client.get("/static/css/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/css", response.content_type)
        css = response.get_data(as_text=True)
        response.close()
        self.assertIn("--bg-primary", css)
        self.assertIn(".dashboard-main", css)
        self.assertIn(".verdict-hero", css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)

    def test_static_javascript_controller_available(self):
        """Verify that static/js/app.js is served with HTTP 200 and contains required logic."""
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        js = response.get_data(as_text=True)
        response.close()
        self.assertIn("FEATURE_METADATA", js)
        self.assertIn("/api/health", js)
        self.assertIn("/api/scan", js)
        self.assertIn("/api/history", js)
        self.assertIn("url_len", js)
        self.assertIn("entropy", js)

    def test_root_content_negotiation_json(self):
        """Verify that GET / returns JSON sitemap when client strictly requests JSON."""
        response = self.client.get("/", headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        data = response.get_json()
        self.assertEqual(data["project"], "PhishGuardAI")
        self.assertIn("endpoints", data)

    def test_end_to_end_dashboard_api_flow(self):
        """Verify end-to-end integration: health -> scan -> history -> delete."""
        # 1. Health check
        health_resp = self.client.get("/api/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertTrue(health_resp.get_json()["database_ready"])

        # 2. Perform scan
        scan_resp = self.client.post("/api/scan", json={"url": "https://www.rmit.edu.au/"})
        self.assertEqual(scan_resp.status_code, 200)
        scan_data = scan_resp.get_json()
        self.assertTrue(scan_data["success"])
        self.assertIn(len(scan_data["feature_breakdown"]), (22, 30))
        self.assertIn(scan_data["verdict"], ("legitimate", "phishing"))

        # 3. Retrieve history
        history_resp = self.client.get("/api/history?limit=10")
        self.assertEqual(history_resp.status_code, 200)
        history_data = history_resp.get_json()
        self.assertEqual(history_data["count"], 1)
        self.assertEqual(history_data["history"][0]["url"], "https://www.rmit.edu.au/")

        # 4. Clear history
        delete_resp = self.client.delete("/api/history")
        self.assertEqual(delete_resp.status_code, 200)
        self.assertEqual(delete_resp.get_json()["deleted_records"], 1)

        # 5. Confirm history is empty
        empty_resp = self.client.get("/api/history")
        self.assertEqual(empty_resp.get_json()["count"], 0)


if __name__ == "__main__":
    unittest.main()
