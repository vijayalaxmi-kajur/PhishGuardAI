"""
PhishGuardAI - Production Preflight Readiness Audit
Audits infrastructure, model artifacts, database connectivity, and security configuration.
"""

import os
import sys
import datetime
from pathlib import Path

# Resolve root directory
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))


def check_python_version():
    major, minor = sys.version_info.major, sys.version_info.minor
    ok = (major == 3 and minor >= 9)
    return {
        "item": "Python Runtime",
        "status": "PASS" if ok else "FAIL",
        "detail": f"Python {major}.{minor}.{sys.version_info.micro} (Requires >= 3.9)"
    }


def check_model_artifacts():
    candidate_paths = [
        ROOT_DIR / "models" / "retrained" / "cand12_calibrated_gbdt_retrained_30f.joblib",
        ROOT_DIR / "models" / "experiments" / "phase15c" / "cand10_calibrated_gbdt_phase15c_30f.joblib",
        ROOT_DIR / "models" / "phishing_model.joblib",
        ROOT_DIR / "models" / "random_forest.joblib",
    ]

    for p in candidate_paths:
        if p.exists():
            size_mb = p.stat().st_size / (1024 * 1024)
            return {
                "item": "ML Model Artifact",
                "status": "PASS",
                "detail": f"Active: {p.relative_to(ROOT_DIR)} ({size_mb:.2f} MB)"
            }

    return {
        "item": "ML Model Artifacts",
        "status": "FAIL",
        "detail": "No trained model artifacts found in models/ directory"
    }


def check_databases():
    try:
        from src.database import get_db_path, get_scan_count
        db_path = get_db_path()
        count = get_scan_count(db_path=db_path)
        return {
            "item": "Audit Scan Database",
            "status": "PASS",
            "detail": f"SQLite operational at {Path(db_path).name} ({count} historical records)"
        }
    except Exception as e:
        return {
            "item": "Audit Scan Database",
            "status": "FAIL",
            "detail": f"Connection error: {str(e)}"
        }


def check_saas_multi_tenant_db():
    try:
        from src.saas.database import SaaSDataManager
        saas_mgr = SaaSDataManager()
        with saas_mgr.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users;")
            user_count = cursor.fetchone()[0]
        return {
            "item": "Multi-Tenant SaaS DB",
            "status": "PASS",
            "detail": f"Operational with {user_count} registered accounts"
        }
    except Exception as e:
        return {
            "item": "Multi-Tenant SaaS DB",
            "status": "FAIL",
            "detail": f"SaaS schema error: {str(e)}"
        }


def check_dependencies():
    required_packages = [
        "flask", "sklearn", "joblib", "pandas", "numpy", "PIL", "tldextract"
    ]
    missing = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if not missing:
        return {
            "item": "Core Dependencies",
            "status": "PASS",
            "detail": "All critical dependencies installed (scikit-learn, Flask, Pillow, etc.)"
        }
    return {
        "item": "Core Dependencies",
        "status": "FAIL",
        "detail": f"Missing packages: {', '.join(missing)}"
    }


def check_security_configuration():
    secret_key = os.getenv("SECRET_KEY")
    razorpay_key = os.getenv("RAZORPAY_KEY_ID")
    stripe_key = os.getenv("STRIPE_SECRET_KEY")

    warnings = []
    if not secret_key:
        warnings.append("SECRET_KEY is using auto-generated ephemeral key (set for production)")
    if not razorpay_key and not stripe_key:
        warnings.append("RAZORPAY_KEY_ID unset (operating in simulated checkout mode)")

    if not warnings:
        return {
            "item": "Security & Secrets",
            "status": "PASS",
            "detail": "Production secrets configured"
        }
    return {
        "item": "Security & Secrets",
        "status": "WARN",
        "detail": " | ".join(warnings)
    }


def main():
    print("=" * 78)
    print("           PHISHGUARDAI — PRODUCTION PREFLIGHT READINESS AUDIT")
    print(f"           Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()} UTC")
    print("=" * 78)

    checks = [
        check_python_version(),
        check_dependencies(),
        check_model_artifacts(),
        check_databases(),
        check_saas_multi_tenant_db(),
        check_security_configuration(),
    ]

    all_passed = True
    for c in checks:
        status_icon = "✓ PASS" if c["status"] == "PASS" else ("⚠️ WARN" if c["status"] == "WARN" else "✗ FAIL")
        print(f"[{status_icon:^7}] {c['item']:<32} : {c['detail']}")
        if c["status"] == "FAIL":
            all_passed = False

    print("=" * 78)
    if all_passed:
        print("🎉 PREFLIGHT VERIFICATION COMPLETE: System is Production-Ready!")
    else:
        print("🚨 PREFLIGHT AUDIT FAILED: Address the critical failures above before deploying.")
    print("=" * 78)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
