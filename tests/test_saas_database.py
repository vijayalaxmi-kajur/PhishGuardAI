"""Unit tests for SaaSDataManager (Users, API Keys, Quota, Scan Audit Logs)."""

import unittest
import tempfile
import os
from src.saas.database import SaaSDataManager


class TestSaaSDataManager(unittest.TestCase):
    """Test suite for multi-tenant database operations and API key management."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.temp_dir.name, "test_saas.db")
        self.db = SaaSDataManager(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_user_registration_and_authentication(self):
        """Verify user registration, password hashing, and authentication."""
        user = self.db.register_user(
            email="developer@company.com",
            password="StrongPassword2026!",
            full_name="Jane Doe",
            plan_tier="developer_pro"
        )
        self.assertEqual(user["email"], "developer@company.com")
        self.assertEqual(user["plan_tier"], "developer_pro")
        self.assertEqual(user["monthly_scan_quota"], 50_000)

        # Successful authentication
        auth_user = self.db.authenticate_user("developer@company.com", "StrongPassword2026!")
        self.assertIsNotNone(auth_user)
        self.assertEqual(auth_user["id"], user["id"])

        # Failed authentication
        self.assertIsNone(self.db.authenticate_user("developer@company.com", "WrongPassword!"))
        self.assertIsNone(self.db.authenticate_user("nonexistent@company.com", "Pass!"))

    def test_api_key_lifecycle(self):
        """Verify API key generation, validation, usage increment, and revocation."""
        user = self.db.register_user(email="api_test@dev.com", password="Pass1234Password!")
        key_data = self.db.create_api_key(user["id"], label="Primary CLI Key", is_live=True)

        raw_key = key_data["raw_key"]
        self.assertTrue(raw_key.startswith("pg_live_"))

        # Key validation
        validated = self.db.validate_api_key(raw_key)
        self.assertIsNotNone(validated)
        self.assertEqual(validated["user_id"], user["id"])
        self.assertEqual(validated["email"], "api_test@dev.com")

        # Second validation should increment usage
        validated2 = self.db.validate_api_key(raw_key)
        self.assertEqual(validated2["scans_used_this_month"], 1)

        # Key revocation
        self.assertTrue(self.db.revoke_api_key(user["id"], key_data["key_id"]))
        self.assertIsNone(self.db.validate_api_key(raw_key))

    def test_scan_event_logging(self):
        """Verify tenant scan audit logging."""
        user = self.db.register_user(email="logger@dev.com", password="Password12345!")
        key_data = self.db.create_api_key(user["id"])

        log_id = self.db.log_scan_event(
            url="https://example.com/login",
            domain="example.com",
            verdict="legitimate",
            standardized_verdict="NO KNOWN THREAT DETECTED",
            risk_level="low",
            phishing_probability=0.04,
            confidence_percent=96.0,
            latency_ms=12.5,
            user_id=user["id"],
            api_key_id=key_data["key_id"],
        )
        self.assertGreater(log_id, 0)


if __name__ == "__main__":
    unittest.main()

