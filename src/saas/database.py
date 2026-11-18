"""PhishGuardAI - Multi-Tenant SaaS Database & Account Management

Provides relational database management for users, API keys, usage tracking, and audit logs.
Works seamlessly on SQLite (local/testing) and PostgreSQL (cloud production via DATABASE_URL).
"""

import os
import sqlite3
import datetime
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager

from src.saas.auth import SecurityManager


class SaaSDataManager:
    """Manages multi-tenant accounts, API key validation, and quota enforcement."""

    PLAN_LIMITS: Dict[str, Dict[str, int]] = {
        "free": {"rate_limit_per_min": 20, "monthly_quota": 1_000},
        "developer_pro": {"rate_limit_per_min": 200, "monthly_quota": 50_000},
        "business": {"rate_limit_per_min": 1_000, "monthly_quota": 300_000},
        "enterprise": {"rate_limit_per_min": 5_000, "monthly_quota": 10_000_000},
    }

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file. Defaults to 'data/saas_production.db'.
        """
        if db_path is not None:
            self.db_path = db_path
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.db_path = os.path.join(base_dir, "data", "saas_production.db")

        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.initialize_schema()

    @contextmanager
    def get_connection(self):
        """Thread-safe connection context manager."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Create multi-tenant tables, indexes, and constraints."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Users & Accounts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                full_name TEXT,
                plan_tier TEXT DEFAULT 'free',
                monthly_scan_quota INTEGER DEFAULT 1000,
                scans_used_this_month INTEGER DEFAULT 0,
                quota_reset_date TEXT,
                created_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_status TEXT DEFAULT 'active'
            );
            """)

            # Safe column migration for existing databases
            for col_def in [
                ("stripe_customer_id", "TEXT"),
                ("stripe_subscription_id", "TEXT"),
                ("subscription_status", "TEXT DEFAULT 'active'"),
                ("razorpay_customer_id", "TEXT"),
                ("razorpay_subscription_id", "TEXT"),
                ("razorpay_payment_id", "TEXT"),
                ("razorpay_order_id", "TEXT")
            ]:
                try:
                    cursor.execute(f"ALTER TABLE users ADD COLUMN {col_def[0]} {col_def[1]};")
                except Exception:
                    pass

            # 2. API Keys Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                label TEXT DEFAULT 'Default Key',
                is_active INTEGER DEFAULT 1,
                rate_limit_per_minute INTEGER DEFAULT 20,
                total_requests INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """)

            # 3. Tenant Scan Logs Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tenant_scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                api_key_id INTEGER,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                verdict TEXT NOT NULL,
                standardized_verdict TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                phishing_probability REAL NOT NULL,
                confidence_percent REAL NOT NULL,
                latency_ms REAL DEFAULT 0.0,
                scanned_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
            );
            """)

            # 4. Audit Logs Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                timestamp TEXT NOT NULL
            );
            """)

            # Indexes for low-latency lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_scans_user ON tenant_scan_logs(user_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_scans_domain ON tenant_scan_logs(domain);")

    # --- User Management ---

    def register_user(self, email: str, password: str, full_name: Optional[str] = None, plan_tier: str = "free") -> Dict[str, Any]:
        """Register a new developer account.
        
        Args:
            email: Account email.
            password: Plain text password.
            full_name: Developer / organization name.
            plan_tier: Subscription tier ('free', 'developer_pro', 'business').
            
        Returns:
            Dictionary containing created user metadata.
        """
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            raise ValueError("Invalid email address format.")

        tier = plan_tier if plan_tier in self.PLAN_LIMITS else "free"
        quota = self.PLAN_LIMITS[tier]["monthly_quota"]

        pw_hash, salt = SecurityManager.hash_password(password)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Quota reset on the first of next month
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        reset_dt = (now_dt.replace(day=1) + datetime.timedelta(days=32)).replace(day=1)
        reset_iso = reset_dt.isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO users (email, password_hash, salt, full_name, plan_tier, monthly_scan_quota, scans_used_this_month, quota_reset_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?);
            """, (clean_email, pw_hash, salt, full_name or "", tier, quota, reset_iso, now_iso))
            user_id = cursor.lastrowid

        return {
            "id": user_id,
            "email": clean_email,
            "full_name": full_name or "",
            "plan_tier": tier,
            "monthly_scan_quota": quota,
            "scans_used_this_month": 0,
            "created_at": now_iso,
        }

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify user credentials and return user profile if authentic."""
        clean_email = email.strip().lower()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ? AND is_active = 1;", (clean_email,))
            row = cursor.fetchone()

            if not row:
                return None

            is_valid = SecurityManager.verify_password(password, row["password_hash"], row["salt"])
            if not is_valid:
                return None

            return {
                "id": row["id"],
                "email": row["email"],
                "full_name": row["full_name"],
                "plan_tier": row["plan_tier"],
                "monthly_scan_quota": row["monthly_scan_quota"],
                "scans_used_this_month": row["scans_used_this_month"],
                "created_at": row["created_at"],
            }

    # --- API Key Management ---

    def create_api_key(self, user_id: int, label: str = "Production API Key", is_live: bool = True) -> Dict[str, Any]:
        """Generate a new cryptographic API key for the user.
        
        Returns:
            Dict containing raw_key (displayed once!), prefix, label, and quota info.
        """
        # Determine rate limit based on user's subscription tier
        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User ID {user_id} does not exist.")

        tier = user.get("plan_tier", "free")
        rate_limit = self.PLAN_LIMITS.get(tier, self.PLAN_LIMITS["free"])["rate_limit_per_min"]

        raw_key, key_hash, key_prefix = SecurityManager.generate_api_key(is_live=is_live)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO api_keys (user_id, key_hash, key_prefix, label, rate_limit_per_minute, created_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """, (user_id, key_hash, key_prefix, label, rate_limit, now_iso))
            key_id = cursor.lastrowid

        return {
            "key_id": key_id,
            "raw_key": raw_key,  # Returned ONLY ONCE
            "key_prefix": key_prefix,
            "label": label,
            "rate_limit_per_minute": rate_limit,
            "created_at": now_iso,
        }

    def validate_api_key(self, raw_key: str) -> Optional[Dict[str, Any]]:
        """Validate raw API key string and retrieve user and rate-limit details.
        
        Performs SHA-256 hash lookup in the database.
        """
        if not raw_key or not isinstance(raw_key, str):
            return None

        key_hash = SecurityManager.hash_api_key(raw_key)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT k.id as key_id, k.user_id, k.rate_limit_per_minute, k.key_prefix, k.is_active as key_active,
                   u.email, u.plan_tier, u.monthly_scan_quota, u.scans_used_this_month, u.is_active as user_active
            FROM api_keys k
            JOIN users u ON k.user_id = u.id
            WHERE k.key_hash = ?;
            """, (key_hash,))
            row = cursor.fetchone()

            if not row:
                return None

            if not row["key_active"] or not row["user_active"]:
                return None

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
            UPDATE api_keys SET last_used_at = ?, total_requests = total_requests + 1 WHERE id = ?;
            """, (now_iso, row["key_id"]))
            cursor.execute("""
            UPDATE users SET scans_used_this_month = scans_used_this_month + 1 WHERE id = ?;
            """, (row["user_id"],))

            return dict(row)

    def list_api_keys(self, user_id: int) -> List[Dict[str, Any]]:
        """Retrieve list of active and historical API keys for a user (hashes omitted)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, key_prefix, label, is_active, rate_limit_per_minute, total_requests, created_at, last_used_at
            FROM api_keys
            WHERE user_id = ?
            ORDER BY created_at DESC;
            """, (user_id,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def revoke_api_key(self, user_id: int, key_id: int) -> bool:
        """Deactivate an API key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?;", (key_id, user_id))
            return cursor.rowcount > 0

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user details by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, email, full_name, plan_tier, monthly_scan_quota, scans_used_this_month,
                   created_at, stripe_customer_id, stripe_subscription_id, subscription_status,
                   razorpay_customer_id, razorpay_payment_id, razorpay_order_id, razorpay_subscription_id
            FROM users WHERE id = ?;
            """, (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_razorpay_customer_id(self, razorpay_customer_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user details by Razorpay customer ID."""
        if not razorpay_customer_id:
            return None
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, email, full_name, plan_tier, monthly_scan_quota, scans_used_this_month,
                   created_at, razorpay_customer_id, razorpay_payment_id, razorpay_order_id, razorpay_subscription_id
            FROM users WHERE razorpay_customer_id = ?;
            """, (razorpay_customer_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def activate_razorpay_payment(
        self,
        user_id: int,
        plan_tier: str,
        payment_id: str,
        order_id: str,
        customer_id: Optional[str] = None,
        subscription_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Activate or upgrade user subscription after successful Razorpay payment."""
        tier = plan_tier.lower()
        if tier not in self.PLAN_LIMITS:
            tier = "free"

        limits = self.PLAN_LIMITS[tier]
        monthly_quota = limits["monthly_quota"]
        rate_limit = limits["rate_limit_per_min"]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE users
            SET plan_tier = ?,
                monthly_scan_quota = ?,
                razorpay_payment_id = ?,
                razorpay_order_id = ?,
                razorpay_customer_id = COALESCE(?, razorpay_customer_id),
                razorpay_subscription_id = COALESCE(?, razorpay_subscription_id),
                subscription_status = 'active'
            WHERE id = ?;
            """, (tier, monthly_quota, payment_id, order_id, customer_id, subscription_id, user_id))

            # Update rate limits on user API keys
            cursor.execute("""
            UPDATE api_keys
            SET rate_limit_per_minute = ?
            WHERE user_id = ? AND is_active = 1;
            """, (rate_limit, user_id))

        return self.get_user_by_id(user_id)

    def get_user_by_stripe_customer_id(self, stripe_customer_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user details by Stripe customer ID."""
        if not stripe_customer_id:
            return None
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, email, full_name, plan_tier, monthly_scan_quota, scans_used_this_month,
                   created_at, stripe_customer_id, stripe_subscription_id, subscription_status
            FROM users WHERE stripe_customer_id = ?;
            """, (stripe_customer_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_user_plan(
        self,
        user_id: int,
        plan_tier: str,
        stripe_customer_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None,
        subscription_status: str = "active",
    ) -> Dict[str, Any]:
        """Update a user's subscription plan, quotas, and API key rate limits."""
        tier = plan_tier.lower()
        if tier not in self.PLAN_LIMITS:
            tier = "free"

        limits = self.PLAN_LIMITS[tier]
        monthly_quota = limits["monthly_quota"]
        rate_limit = limits["rate_limit_per_min"]

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE users
            SET plan_tier = ?,
                monthly_scan_quota = ?,
                stripe_customer_id = COALESCE(?, stripe_customer_id),
                stripe_subscription_id = COALESCE(?, stripe_subscription_id),
                subscription_status = ?
            WHERE id = ?;
            """, (tier, monthly_quota, stripe_customer_id, stripe_subscription_id, subscription_status, user_id))

            # Cascade updated rate limit to active API keys
            cursor.execute("""
            UPDATE api_keys
            SET rate_limit_per_minute = ?
            WHERE user_id = ? AND is_active = 1;
            """, (rate_limit, user_id))

        return self.get_user_by_id(user_id)

    def reset_monthly_scans(self, user_id: int) -> None:
        """Reset monthly scan counter on subscription renewal."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
            UPDATE users SET scans_used_this_month = 0, quota_reset_date = ? WHERE id = ?;
            """, (now_iso, user_id))

    def log_scan_event(
        self,
        url: str,
        domain: str,
        verdict: str,
        standardized_verdict: str,
        risk_level: str,
        phishing_probability: float,
        confidence_percent: float,
        latency_ms: float = 0.0,
        user_id: Optional[int] = None,
        api_key_id: Optional[int] = None,
    ) -> int:
        """Record an authenticated scan event for analytics and billing auditing."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO tenant_scan_logs (
                user_id, api_key_id, url, domain, verdict, standardized_verdict,
                risk_level, phishing_probability, confidence_percent, latency_ms, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                user_id, api_key_id, url, domain, verdict, standardized_verdict,
                risk_level, phishing_probability, confidence_percent, latency_ms, now_iso
            ))
            return cursor.lastrowid

