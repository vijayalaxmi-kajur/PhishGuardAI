"""
Unit tests for PhishGuardAI SaaS Billing & Subscription Management (Razorpay Integration).
"""

import json
import unittest
import tempfile
import os
import hmac
import hashlib

from src.saas.database import SaaSDataManager
from src.saas.billing import BillingManager, RazorpayClient, PlanTier, PRICING_CATALOG


class TestBillingManager(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = SaaSDataManager(db_path=self.temp_db_path)
        self.key_secret = "test_razorpay_secret_key_98765"
        self.billing = BillingManager(
            db_manager=self.db,
            razorpay_key_id="rzp_test_12345",
            razorpay_key_secret=self.key_secret
        )

        # Register a test developer
        self.user = self.db.register_user(
            email="developer@test.com",
            password="StrongPassword123!",
            full_name="Test Dev",
            plan_tier="free"
        )

    def tearDown(self):
        os.close(self.temp_db_fd)
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass

    def test_get_plans_catalog(self):
        plans = self.billing.get_plans()
        self.assertEqual(len(plans), 4)
        tier_ids = [p["id"] for p in plans]
        self.assertIn("free", tier_ids)
        self.assertIn("developer_pro", tier_ids)
        self.assertIn("business", tier_ids)
        self.assertIn("enterprise", tier_ids)

        # Verify INR pricing is present
        dev_pro = next(p for p in plans if p["id"] == "developer_pro")
        self.assertEqual(dev_pro["price_inr"], 1999)
        self.assertEqual(dev_pro["amount_paise"], 199900)

    def test_create_razorpay_order(self):
        res = self.billing.create_razorpay_order(
            user_id=self.user["id"],
            plan_tier=PlanTier.DEVELOPER_PRO
        )
        self.assertTrue(res["success"])
        self.assertIn("order_id", res)
        self.assertEqual(res["amount"], 199900)
        self.assertEqual(res["currency"], "INR")
        self.assertEqual(res["plan_tier"], "developer_pro")

    def test_verify_and_activate_payment_success(self):
        order_id = "order_test_abc123"
        payment_id = "pay_test_xyz789"

        # Generate valid HMAC signature
        msg = f"{order_id}|{payment_id}".encode("utf-8")
        valid_sig = hmac.new(self.key_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        # Execute verification and plan activation
        res = self.billing.verify_and_activate_payment(
            user_id=self.user["id"],
            plan_tier=PlanTier.BUSINESS,
            order_id=order_id,
            payment_id=payment_id,
            signature=valid_sig
        )
        self.assertTrue(res["success"])

        # Check DB updated
        user_after = self.db.get_user_by_id(self.user["id"])
        self.assertEqual(user_after["plan_tier"], "business")
        self.assertEqual(user_after["monthly_scan_quota"], 300_000)
        self.assertEqual(user_after["razorpay_payment_id"], payment_id)
        self.assertEqual(user_after["razorpay_order_id"], order_id)

    def test_verify_payment_invalid_signature_fails(self):
        with self.assertRaises(ValueError):
            self.billing.verify_and_activate_payment(
                user_id=self.user["id"],
                plan_tier=PlanTier.BUSINESS,
                order_id="order_1",
                payment_id="pay_1",
                signature="invalid_tampered_signature"
            )

    def test_webhook_razorpay_payment_captured(self):
        webhook_payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_live_capture_123",
                        "order_id": "order_live_999",
                        "notes": {
                            "user_id": str(self.user["id"]),
                            "plan_tier": "developer_pro"
                        }
                    }
                }
            }
        }
        res = self.billing.handle_webhook(json.dumps(webhook_payload).encode("utf-8"))
        self.assertEqual(res["status"], "processed")
        self.assertEqual(res["plan_tier"], "developer_pro")

        user_after = self.db.get_user_by_id(self.user["id"])
        self.assertEqual(user_after["plan_tier"], "developer_pro")
        self.assertEqual(user_after["monthly_scan_quota"], 50_000)

    def test_webhook_subscription_cancelled(self):
        # Set user as business first
        self.db.activate_razorpay_payment(
            user_id=self.user["id"],
            plan_tier="business",
            payment_id="pay_init",
            order_id="order_init",
            customer_id="cust_rzp_cancel_test"
        )

        webhook_payload = {
            "event": "subscription.cancelled",
            "payload": {
                "subscription": {
                    "entity": {
                        "id": "sub_rzp_123",
                        "customer_id": "cust_rzp_cancel_test"
                    }
                }
            }
        }
        res = self.billing.handle_webhook(json.dumps(webhook_payload).encode("utf-8"))
        self.assertEqual(res["action"], "downgrade_to_free")

        user_after = self.db.get_user_by_id(self.user["id"])
        self.assertEqual(user_after["plan_tier"], "free")
        self.assertEqual(user_after["monthly_scan_quota"], 1_000)


if __name__ == "__main__":
    unittest.main()
