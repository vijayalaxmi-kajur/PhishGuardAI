"""
Unit and integration tests for Phase 5 endpoints (Billing, Swagger Docs, Legal).
"""

import json
import unittest
import tempfile
import os

from app import create_app


class TestPhase5API(unittest.TestCase):

    def setUp(self):
        self.saas_db_fd, self.saas_db_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app(test_config={
            "TESTING": True,
            "SAAS_DATABASE_PATH": self.saas_db_path,
            "CHECK_WEBSITE_PRESENCE": False,
            "SECRET_KEY": "phase5_test_secret_key"
        })
        self.client = self.app.test_client()

        # Register developer and get session token
        reg_resp = self.client.post("/api/v1/auth/register", json={
            "email": "phase5_dev@test.com",
            "password": "Password123!",
            "full_name": "Phase 5 Tester",
            "plan_tier": "free"
        })
        reg_data = json.loads(reg_resp.data)
        self.session_token = reg_data["session_token"]
        self.user_id = reg_data["user"]["id"]

    def tearDown(self):
        os.close(self.saas_db_fd)
        try:
            os.remove(self.saas_db_path)
        except OSError:
            pass

    def test_get_billing_plans(self):
        resp = self.client.get("/api/v1/billing/plans")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["plans"]), 4)

    def test_razorpay_create_order_and_verify(self):
        headers = {"Authorization": f"Bearer {self.session_token}"}
        # 1. Create Order
        resp = self.client.post(
            "/api/v1/billing/razorpay/create-order",
            headers=headers,
            json={"plan_tier": "developer_pro", "currency": "INR"}
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertIn("order_id", data)
        self.assertEqual(data["amount"], 199900)

        # 2. Verify Payment & Activate
        v_resp = self.client.post(
            "/api/v1/billing/razorpay/verify-payment",
            headers=headers,
            json={
                "plan_tier": "developer_pro",
                "razorpay_order_id": data["order_id"],
                "razorpay_payment_id": "pay_test_rzp_12345",
                "razorpay_signature": "mock_sig"
            }
        )
        self.assertEqual(v_resp.status_code, 200)
        v_data = json.loads(v_resp.data)
        self.assertTrue(v_data["success"])
        self.assertEqual(v_data["user"]["plan_tier"], "developer_pro")
        self.assertEqual(v_data["user"]["monthly_scan_quota"], 50_000)

    def test_create_checkout_session(self):
        headers = {"Authorization": f"Bearer {self.session_token}"}
        resp = self.client.post(
            "/api/v1/billing/checkout",
            headers=headers,
            json={"plan_tier": "developer_pro"}
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertIn("checkout_url", data)

    def test_create_checkout_unauthorized(self):
        resp = self.client.post(
            "/api/v1/billing/checkout",
            json={"plan_tier": "developer_pro"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_billing_webhook_upgrade(self):
        payload = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": "cus_phase5_test",
                    "subscription": "sub_phase5_test",
                    "metadata": {
                        "user_id": str(self.user_id),
                        "plan_tier": "business"
                    }
                }
            }
        }
        resp = self.client.post(
            "/api/v1/billing/webhook",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "processed")
        self.assertEqual(data["plan_tier"], "business")

        # Verify usage returns upgraded tier
        headers = {"Authorization": f"Bearer {self.session_token}"}
        usage_resp = self.client.get("/api/v1/user/usage", headers=headers)
        usage_data = json.loads(usage_resp.data)
        self.assertEqual(usage_data["usage"]["plan_tier"], "business")
        self.assertEqual(usage_data["usage"]["monthly_scan_quota"], 300_000)

    def test_swagger_and_openapi_docs(self):
        # 1. OpenAPI JSON spec
        spec_resp = self.client.get("/api/v1/openapi.json")
        self.assertEqual(spec_resp.status_code, 200)
        spec = json.loads(spec_resp.data)
        self.assertEqual(spec["openapi"], "3.0.0")
        self.assertIn("/api/v1/scan", spec["paths"])

        # 2. Swagger HTML UI
        ui_resp = self.client.get("/docs")
        self.assertEqual(ui_resp.status_code, 200)
        self.assertIn(b"PhishGuardAI REST API Explorer", ui_resp.data)

    def test_legal_pages(self):
        # Terms of Service
        terms_resp = self.client.get("/terms")
        self.assertEqual(terms_resp.status_code, 200)
        self.assertIn(b"PhishGuardAI Terms of Service", terms_resp.data)
        self.assertIn(b"LIMITATION OF LIABILITY", terms_resp.data)

        # Privacy Policy
        privacy_resp = self.client.get("/privacy")
        self.assertEqual(privacy_resp.status_code, 200)
        self.assertIn(b"PhishGuardAI Privacy Policy", privacy_resp.data)
        self.assertIn(b"URL Scrubbing", privacy_resp.data)


if __name__ == "__main__":
    unittest.main()

