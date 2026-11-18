"""Unit tests for SaaS SecurityManager (PBKDF2 password hashing, API keys, signed tokens)."""

import unittest
import time
from src.saas.auth import SecurityManager


class TestSaaSSecurity(unittest.TestCase):
    """Test suite for cryptographic primitives, API keys, and session tokens."""

    def setUp(self):
        self.mgr = SecurityManager(secret_key="test-secret-key-for-saas-audit-2026")

    def test_password_hashing_and_verification(self):
        """Verify PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""
        pw = "SuperSecurePassword123!"
        pw_hash, salt = SecurityManager.hash_password(pw)

        self.assertIsNotNone(pw_hash)
        self.assertIsNotNone(salt)
        self.assertEqual(len(pw_hash), 64)  # SHA-256 hex length
        self.assertEqual(len(salt), 32)      # 16 bytes in hex

        # Correct password
        self.assertTrue(SecurityManager.verify_password(pw, pw_hash, salt))

        # Incorrect password
        self.assertFalse(SecurityManager.verify_password("WrongPassword!", pw_hash, salt))
        self.assertFalse(SecurityManager.verify_password("", pw_hash, salt))

    def test_api_key_generation_and_hashing(self):
        """Verify API key formatting, prefix generation, and SHA-256 hashing."""
        raw_key, key_hash, key_prefix = SecurityManager.generate_api_key(is_live=True)

        self.assertTrue(raw_key.startswith("pg_live_"))
        self.assertEqual(len(raw_key), 51)  # pg_live_ + 43 base64 chars
        self.assertTrue(key_prefix.startswith("pg_live_"))
        self.assertTrue(key_prefix.endswith("..."))
        self.assertEqual(len(key_hash), 64)

        # Confirm hash is deterministic
        self.assertEqual(SecurityManager.hash_api_key(raw_key), key_hash)

        # Test key
        raw_test, hash_test, prefix_test = SecurityManager.generate_api_key(is_live=False)
        self.assertTrue(raw_test.startswith("pg_test_"))

    def test_session_token_creation_and_verification(self):
        """Verify HMAC-SHA256 session token generation, signature validation, and expiration."""
        token = self.mgr.create_session_token(user_id=42, email="dev@example.com", expires_in_sec=10)
        self.assertIn(".", token)

        payload = self.mgr.verify_session_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["uid"], 42)
        self.assertEqual(payload["email"], "dev@example.com")

        # Tampered token
        tampered = token[:-4] + "abcd"
        self.assertIsNone(self.mgr.verify_session_token(tampered))

        # Expired token
        expired_token = self.mgr.create_session_token(user_id=1, email="exp@test.com", expires_in_sec=-5)
        self.assertIsNone(self.mgr.verify_session_token(expired_token))


if __name__ == "__main__":
    unittest.main()

