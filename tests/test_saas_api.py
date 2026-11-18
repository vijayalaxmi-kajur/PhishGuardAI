"""Integration tests for Enterprise SaaS API Endpoints (v1)."""

import unittest
import tempfile
import os
import json

from app import create_app


class TestSaaSAPIEndpoints(unittest.TestCase):
    """End-to-end test suite for SaaS multi-tenant REST API."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.saas_db_path = os.path.join(self.temp_dir.name, "saas_test.db")
        self.legacy_db_path = os.path.join(self.temp_dir.name, "legacy_test.db")

        self.app = create_app({
            "TESTING": True,
            "CHECK_WEBSITE_PRESENCE": False,
            "DATABASE_PATH": self.legacy_db_path,
            "SAAS_DATABASE_PATH": self.saas_db_path,
            "SECRET_KEY": "saas-test-secret-key-2026",
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_full_saas_developer_workflow(self):
        """Test user registration, key issuance, authentication, and cached scanning."""
        # 1. Register User
        reg_payload = {
            "email": "saas_dev@enterprise.com",
            "password": "SecurePassword2026!",
            "full_name": "SaaS Developer",
            "plan_tier": "developer_pro"
        }
        reg_resp = self.client.post("/api/v1/auth/register", json=reg_payload)
        self.assertEqual(reg_resp.status_code, 201)
        reg_data = reg_resp.get_json()
        self.assertTrue(reg_data["success"])

        api_key = reg_data["api_key"]["raw_key"]
        session_token = reg_data["session_token"]
        self.assertTrue(api_key.startswith("pg_live_"))

        # 2. Login
        login_resp = self.client.post("/api/v1/auth/login", json={
            "email": "saas_dev@enterprise.com",
            "password": "SecurePassword2026!"
        })
        self.assertEqual(login_resp.status_code, 200)

        # 3. Create Additional Key via Session Token
        new_key_resp = self.client.post(
            "/api/v1/keys",
            headers={"Authorization": f"Bearer {session_token}"},
            json={"label": "Secondary Backend Worker Key"}
        )
        self.assertEqual(new_key_resp.status_code, 201)
        new_key_data = new_key_resp.get_json()
        self.assertTrue(new_key_data["success"])

        # 4. List Keys
        list_resp = self.client.get(
            "/api/v1/keys",
            headers={"Authorization": f"Bearer {session_token}"}
        )
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(len(list_resp.get_json()["keys"]), 2)

        # 5. Execute Authenticated Scan
        scan_payload = {"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PL123"}
        scan_resp = self.client.post(
            "/api/v1/scan",
            headers={"X-API-Key": api_key},
            json=scan_payload
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan_data = scan_resp.get_json()
        self.assertTrue(scan_data["success"])
        self.assertEqual(scan_data["verdict"], "legitimate")
        self.assertFalse(scan_data["cached"])
        self.assertIn("X-RateLimit-Limit", scan_resp.headers)

        # 6. Second Scan Hits In-Memory Cache (cached = True)
        cached_resp = self.client.post(
            "/api/v1/scan",
            headers={"X-API-Key": api_key},
            json=scan_payload
        )
        self.assertEqual(cached_resp.status_code, 200)
        cached_data = cached_resp.get_json()
        self.assertTrue(cached_data["cached"])

        # 7. Unauthenticated Scan Rejected with 401
        unauth_resp = self.client.post("/api/v1/scan", json=scan_payload)
        self.assertEqual(unauth_resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()

