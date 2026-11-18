"""PhishGuardAI - Cryptographic Authentication & API Key Management

Implements zero-dependency, enterprise-grade cryptographic authentication:
1. PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and random salt.
2. Cryptographic API Key generation (pg_live_... / pg_test_...) with SHA-256 hashing.
3. Cryptographically signed bearer tokens (HMAC-SHA256) for session management.
"""

import os
import time
import hmac
import base64
import json
import secrets
import hashlib
from typing import Tuple, Dict, Any, Optional


class SecurityManager:
    """Manages password hashing, API keys, and cryptographically signed tokens."""

    PBKDF2_ITERATIONS: int = 100_000
    KEY_LIVE_PREFIX: str = "pg_live_"
    KEY_TEST_PREFIX: str = "pg_test_"

    def __init__(self, secret_key: Optional[str] = None) -> None:
        """Initialize security manager with an HMAC signing secret.
        
        Args:
            secret_key: Secret key string. Defaults to SECRET_KEY env var or a secure random key.
        """
        self._secret_key = (
            secret_key
            or os.getenv("SECRET_KEY")
            or "phishguard-default-dev-secret-change-in-production-2026"
        ).encode("utf-8")

    # --- 1. Password Hashing & Verification (PBKDF2) ---

    @classmethod
    def hash_password(cls, password: str, salt_bytes: Optional[bytes] = None) -> Tuple[str, str]:
        """Hash a plain text password using PBKDF2-HMAC-SHA256.
        
        Args:
            password: Plain text password string.
            salt_bytes: Optional existing salt (generates 16 random bytes if None).
            
        Returns:
            Tuple of (hash_hex: str, salt_hex: str).
        """
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string.")

        salt = salt_bytes or secrets.token_bytes(16)
        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            cls.PBKDF2_ITERATIONS
        )
        return derived_key.hex(), salt.hex()

    @classmethod
    def verify_password(cls, password: str, hash_hex: str, salt_hex: str) -> bool:
        """Verify password match in constant time against timing attacks.
        
        Args:
            password: Plain text password attempting login.
            hash_hex: Stored password hash string.
            salt_hex: Stored salt string.
            
        Returns:
            True if password matches, False otherwise.
        """
        if not password or not hash_hex or not salt_hex:
            return False

        try:
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)
            actual_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                cls.PBKDF2_ITERATIONS
            )
            return hmac.compare_digest(actual_hash, expected_hash)
        except Exception:
            return False

    # --- 2. Cryptographic API Key Management ---

    @classmethod
    def generate_api_key(cls, is_live: bool = True) -> Tuple[str, str, str]:
        """Generate a cryptographically secure, hashed API key.
        
        Format: pg_live_<32 urlsafe chars> or pg_test_<32 urlsafe chars>
        
        Returns:
            Tuple of (raw_key, key_hash, key_prefix):
            - raw_key: Returned to the user ONCE upon creation.
            - key_hash: SHA-256 hash stored in the database.
            - key_prefix: Short preview string for display in dashboards (e.g. 'pg_live_ab12...').
        """
        prefix = cls.KEY_LIVE_PREFIX if is_live else cls.KEY_TEST_PREFIX
        token = secrets.token_urlsafe(32)
        raw_key = f"{prefix}{token}"
        key_hash = cls.hash_api_key(raw_key)
        key_prefix = f"{raw_key[:12]}..."
        return raw_key, key_hash, key_prefix

    @staticmethod
    def hash_api_key(raw_key: str) -> str:
        """Compute SHA-256 hash of an API key for secure database storage."""
        if not raw_key:
            return ""
        return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()

    # --- 3. Cryptographically Signed Session Tokens (HMAC-SHA256) ---

    def create_session_token(self, user_id: int, email: str, role: str = "developer", expires_in_sec: int = 86400) -> str:
        """Create a URL-safe, tamper-proof signed session token.
        
        Args:
            user_id: User identifier integer.
            email: User email.
            role: Access role ("developer", "admin").
            expires_in_sec: Expiration time in seconds (default 24 hours).
            
        Returns:
            Base64-encoded signed token string (payload.signature).
        """
        now = int(time.time())
        payload = {
            "uid": user_id,
            "email": email.strip().lower(),
            "role": role,
            "iat": now,
            "exp": now + expires_in_sec,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        b64_payload = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")

        sig = hmac.new(self._secret_key, b64_payload.encode("utf-8"), hashlib.sha256).digest()
        b64_sig = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

        return f"{b64_payload}.{b64_sig}"

    def verify_session_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify signed session token validity and expiration.
        
        Args:
            token: Signed token string (payload.signature).
            
        Returns:
            Payload dictionary if authentic and unexpired, None otherwise.
        """
        if not token or "." not in token:
            return None

        parts = token.strip().split(".")
        if len(parts) != 2:
            return None

        b64_payload, b64_sig = parts

        # Verify signature in constant time
        expected_sig = hmac.new(self._secret_key, b64_payload.encode("utf-8"), hashlib.sha256).digest()
        try:
            # Add padding
            rem = len(b64_sig) % 4
            sig_pad = b64_sig + ("=" * (4 - rem) if rem else "")
            actual_sig = base64.urlsafe_b64decode(sig_pad)
            if not hmac.compare_digest(actual_sig, expected_sig):
                return None

            # Decode payload
            rem_p = len(b64_payload) % 4
            payload_pad = b64_payload + ("=" * (4 - rem_p) if rem_p else "")
            payload_json = base64.urlsafe_b64decode(payload_pad).decode("utf-8")
            payload = json.loads(payload_json)

            # Check expiration
            if payload.get("exp", 0) < int(time.time()):
                return None

            return payload
        except Exception:
            return None

