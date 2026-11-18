"""PhishGuardAI - Flask Backend Application Entry Point

Exposes REST endpoints for phishing URL scanning, health status monitoring,
and scan-history management backed by an embedded SQLite database.
"""

import os
import sys
import time
import math
import json
import urllib.parse
import datetime
from typing import Optional, Dict, Any

import pandas as pd
import numpy as np
import joblib
from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS

# Project Root resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = CURRENT_DIR
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extraction import URLFeatureExtractor
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.engine import (
    LayeredDecisionEngine,
    DecisionVerdict,
    RiskLevel,
    DecisionResult,
)
from src.decision_engine.adapter import ModelInferenceAdapter
from src.threat_intelligence.manager import ThreatIntelligenceManager
from src.threat_intelligence.whois_checker import DomainAgeChecker
from src.threat_intelligence.whitelist import VerifiedDomainWhitelist
from src.sandbox import DeepSandboxCrawler
from src.decision_engine.url_validation import validate_url
from src.database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_count,
    delete_scan_history,
    get_db_path
)
from src.decision_engine.website_checker import check_website_presence
from src.saas import (
    SecurityManager,
    SaaSDataManager,
    URLReputationCache,
    SlidingWindowRateLimiter,
    require_api_key,
    require_session_token,
)
from src.saas.billing import BillingManager, PlanTier



# Type alias for model loader return type
Tuple_Model_Info = tuple[Optional[Any], Dict[str, Any], Optional[str]]


def load_model_artifact(model_path: Optional[str] = None) -> Tuple_Model_Info:
    """Safely load and validate the trained phishing detection model artifact.
    
    Args:
        model_path: Optional explicit path to joblib artifact.
        
    Returns:
        Tuple of (model_object, model_metadata_dict, error_message_or_None).
    """
    if model_path is None:
        retrained_path = os.path.join(
            PROJECT_ROOT, "models", "retrained", "cand12_calibrated_gbdt_retrained_30f.joblib"
        )
        candidate_10_path = os.path.join(
            PROJECT_ROOT, "models", "experiments", "phase15c", "cand10_calibrated_gbdt_phase15c_30f.joblib"
        )
        if os.path.exists(retrained_path):
            model_path = retrained_path
        elif os.path.exists(candidate_10_path):
            model_path = candidate_10_path
        else:
            model_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib")

    if not os.path.exists(model_path):
        return None, {}, "Model artifact not found at configured path."

    try:
        artifact = joblib.load(model_path)
    except Exception as e:
        return None, {}, "Failed to deserialize model artifact."

    # Handle dictionary wrapper vs direct estimator
    if isinstance(artifact, dict):
        model = artifact.get("model")
        feature_names = artifact.get("feature_names", artifact.get("features"))
        model_name = artifact.get("model_name", "Phishing Classifier")
        metrics = artifact.get("metrics", {})
    else:
        model = artifact
        model_name = getattr(model, "__class__", type(model)).__name__
        metrics = {}
        feature_names = None

    # Load external metadata if present
    meta_json_path = os.path.join(os.path.dirname(model_path), "retrained_model_metadata.json")
    if os.path.exists(meta_json_path):
        try:
            with open(meta_json_path, "r") as mf:
                retrained_meta = json.load(mf)
                metrics = retrained_meta.get("metrics", metrics)
                if not model_name or model_name == "CalibratedClassifierCV":
                    model_name = retrained_meta.get("model_name", model_name)
        except Exception:
            pass

    if model is None or not hasattr(model, "predict_proba"):
        return None, {}, "Loaded model artifact does not implement predict_proba."

    classes = getattr(model, "classes_", None)
    if classes is None and hasattr(model, "estimator") and hasattr(model.estimator, "classes_"):
        classes = model.estimator.classes_

    if classes is None:
        return None, {}, "Model does not define classes_ attribute."

    classes_list = list(classes)
    if 1 not in classes_list:
        return None, {}, "Model classes_ attribute does not contain target label 1 (phishing)."

    # Determine feature names and schema
    if feature_names is None:
        if hasattr(model, "feature_names_in_"):
            feature_names = list(model.feature_names_in_)
        elif hasattr(model, "estimator") and hasattr(model.estimator, "feature_names_in_"):
            feature_names = list(model.estimator.feature_names_in_)
        elif getattr(model, "n_features_in_", None) == 30:
            feature_names = list(ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES)
        elif hasattr(model, "estimator") and getattr(model.estimator, "n_features_in_", None) == 30:
            feature_names = list(ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES)
        else:
            feature_names = list(URLFeatureExtractor.FEATURE_NAMES)

    schema = "experimental" if len(feature_names) == 30 else "baseline"

    metadata = {
        "model_name": model_name,
        "feature_names": feature_names,
        "phishing_class_index": classes_list.index(1),
        "classes": [int(c) for c in classes_list],
        "n_features": len(feature_names),
        "schema": schema,
        "metrics": metrics
    }

    return model, metadata, None


# Define type alias for clarity
Tuple_Model_Info = tuple[Optional[Any], Dict[str, Any], Optional[str]]


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    """Application factory for PhishGuardAI."""
    templates_path = os.path.join(PROJECT_ROOT, "templates")
    static_path = os.path.join(PROJECT_ROOT, "static")
    app = Flask(
        __name__,
        template_folder=templates_path,
        static_folder=static_path
    )
    CORS(app)

    # Configure paths
    if test_config:
        db_path = test_config.get("DATABASE_PATH")
        model_path = test_config.get("MODEL_PATH")
        mock_model = test_config.get("MOCK_MODEL")
    else:
        db_path = None
        model_path = None
        mock_model = None

    # Initialize SQLite database
    db_initialized = initialize_database(db_path=db_path)

    # Load machine learning model
    if mock_model is not None:
        model = mock_model
        classes_list = list(getattr(model, "classes_", [0, 1]))
        model_meta = {
            "model_name": "Mock Test Model",
            "feature_names": URLFeatureExtractor.FEATURE_NAMES,
            "phishing_class_index": classes_list.index(1) if 1 in classes_list else 1,
            "classes": [int(c) for c in classes_list],
            "n_features": len(URLFeatureExtractor.FEATURE_NAMES),
            "schema": "baseline"
        }
        model_error = None
    else:
        model, model_meta, model_error = load_model_artifact(model_path)

    # Initialize Feature Extractor and Schema
    schema = model_meta.get("schema", "baseline")
    if schema == "experimental" or model_meta.get("n_features") == 30:
        extractor = ExperimentalURLFeatureExtractor()
        feature_names = ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES
        schema = "experimental"
    else:
        extractor = URLFeatureExtractor()
        feature_names = URLFeatureExtractor.FEATURE_NAMES
        schema = "baseline"

    # Threat Intelligence configuration (strictly offline by default unless explicit)
    enable_intel = False
    if test_config and "ENABLE_THREAT_INTEL" in test_config:
        enable_intel = test_config["ENABLE_THREAT_INTEL"]
    elif os.environ.get("ENABLE_THREAT_INTEL", "").lower() in ("1", "true", "yes"):
        enable_intel = True

    if test_config and "THREAT_INTEL_MANAGER" in test_config:
        threat_mgr = test_config["THREAT_INTEL_MANAGER"]
    elif enable_intel:
        threat_mgr = ThreatIntelligenceManager()
    else:
        threat_mgr = ThreatIntelligenceManager(providers=[])

    # Domain Age and Whitelist Registry configuration
    if test_config and "DOMAIN_AGE_CHECKER" in test_config:
        domain_age_checker = test_config["DOMAIN_AGE_CHECKER"]
    elif test_config and test_config.get("TESTING"):
        domain_age_checker = None
    else:
        domain_age_checker = DomainAgeChecker()

    if test_config and "WHITELIST_REGISTRY" in test_config:
        whitelist_registry = test_config["WHITELIST_REGISTRY"]
    elif test_config and test_config.get("TESTING"):
        whitelist_registry = None
    else:
        whitelist_registry = VerifiedDomainWhitelist()

    if test_config and "SANDBOX_CRAWLER" in test_config:
        sandbox_crawler = test_config["SANDBOX_CRAWLER"]
    elif test_config and test_config.get("TESTING"):
        sandbox_crawler = None
    else:
        sandbox_crawler = DeepSandboxCrawler()

    # Initialize Layered Decision Engine
    if model is not None:
        adapter = ModelInferenceAdapter(
            model=model,
            feature_schema=schema,
            feature_names=feature_names,
            model_name=model_meta.get("model_name", "Classifier"),
            default_threshold=0.50
        )
        decision_engine = LayeredDecisionEngine(
            ml_model=adapter,
            feature_schema=schema,
            threat_intel_manager=threat_mgr,
            model_name=model_meta.get("model_name", "Classifier"),
            domain_age_checker=domain_age_checker,
            whitelist_registry=whitelist_registry,
            sandbox_crawler=sandbox_crawler,
        )
    else:
        adapter = None
        decision_engine = LayeredDecisionEngine(
            ml_model=None,
            threat_intel_manager=threat_mgr,
            domain_age_checker=domain_age_checker,
            whitelist_registry=whitelist_registry,
            sandbox_crawler=sandbox_crawler,
        )

    # Website Presence Verification configuration (active in production, bypassed in test mode unless explicit)
    enable_presence_check = True
    if test_config and "CHECK_WEBSITE_PRESENCE" in test_config:
        enable_presence_check = bool(test_config["CHECK_WEBSITE_PRESENCE"])
    elif test_config and test_config.get("TESTING"):
        enable_presence_check = False
    elif os.environ.get("CHECK_WEBSITE_PRESENCE", "").lower() in ("0", "false", "no"):
        enable_presence_check = False

    decision_threshold = 0.5

    # Initialize Multi-Tenant SaaS Subsystems
    saas_db_path = test_config.get("SAAS_DATABASE_PATH") if test_config else None
    saas_data_mgr = SaaSDataManager(db_path=saas_db_path)
    security_mgr = SecurityManager(secret_key=test_config.get("SECRET_KEY") if test_config else None)
    url_reputation_cache = URLReputationCache()
    rate_limiter = SlidingWindowRateLimiter()
    billing_mgr = BillingManager(db_manager=saas_data_mgr)

    @app.route("/", methods=["GET"])
    def index():
        """Serve the PhishGuardAI Web Dashboard or API sitemap."""
        accept_header = request.headers.get("Accept", "")
        # Provide JSON sitemap if explicitly requested by client
        if "application/json" in accept_header and not (
            "text/html" in accept_header or "*/*" in accept_header
        ):
            return jsonify({
                "project": "PhishGuardAI",
                "version": "1.0.0",
                "status": "online",
                "phase": "Phase 15 - Integrated Decision Engine",
                "model_loaded": model is not None,
                "model_name": model_meta.get("model_name") if model else None,
                "endpoints": {
                    "health": "/api/health (GET)",
                    "scan": "/api/scan (POST)",
                    "history": "/api/history (GET, DELETE)"
                }
            }), 200

        return render_template("index.html")

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint reporting model and database operational status."""
        is_healthy = (model is not None) and db_initialized

        return jsonify({
            "status": "healthy" if is_healthy else "degraded",
            "model_loaded": model is not None,
            "model_name": model_meta.get("model_name") if model else None,
            "database_ready": db_initialized,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }), 200 if is_healthy else 503

    @app.route("/api/scan", methods=["POST"])
    def scan_url():
        """Inspect and predict whether a submitted URL is legitimate or phishing.
        
        Expected JSON Body:
            { "url": "https://example.com" }
        """
        # 1. Verify JSON payload
        if not request.is_json:
            return jsonify({"success": False, "error": "Request body must be valid JSON."}), 400

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid JSON structure. Object expected."}), 400

        raw_url = data.get("url")

        # 2. Validate URL input using centralized offline validation engine
        validation = validate_url(raw_url, max_length=2048)
        if not validation.is_valid:
            return jsonify({
                "success": False,
                "error": validation.error_message
            }), 400

        clean_url = validation.clean_url

        # 2b. Live Website Presence Check
        # Check whether website domain exists in DNS and responds over HTTP/HTTPS
        req_check_presence = data.get("check_presence", True)
        is_present = True
        presence_msg = "Presence check bypassed."
        presence_details = {"dns_resolved": True, "http_status": None}

        if enable_presence_check and req_check_presence:
            is_present, presence_msg, presence_details = check_website_presence(clean_url, timeout=3.5)
            if not is_present:
                scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                verdict = "website_not_present"
                try:
                    save_scan(
                        url=clean_url,
                        verdict=verdict,
                        phishing_probability=0.0,
                        confidence_percent=0.0,
                        scanned_at=scanned_at,
                        db_path=db_path
                    )
                except Exception:
                    pass

                return jsonify({
                    "success": True,
                    "url": clean_url,
                    "website_present": False,
                    "presence_message": presence_msg,
                    "presence_details": presence_details,
                    "live_telemetry": presence_details,
                    "verdict": verdict,
                    "standardized_verdict": "WEBSITE NOT PRESENT",
                    "risk_level": "unknown",
                    "phishing_probability": 0.0,
                    "confidence_percent": 0.0,
                    "threshold": decision_threshold,
                    "scanned_at": scanned_at,
                    "feature_breakdown": {},
                    "explanation": [
                        f"Live Presence Check: {presence_msg}",
                        "The domain does not exist in public DNS (NXDOMAIN) or the host server is completely offline.",
                        "Phishing risk scoring was halted because the website is not present on the internet."
                    ],
                    "warnings": [
                        "Website does not exist on the live internet. Please verify the URL spelling."
                    ],
                    "structural_indicators": [
                        "Non-Existent / Unreachable Domain"
                    ]
                }), 200

        # 3. Check model availability
        if model is None:
            return jsonify({
                "success": False,
                "error": "Phishing detection model is not loaded or unavailable."
            }), 503

        # 4. Feature Extraction (strictly offline)
        try:
            if schema == "experimental":
                feature_dict = extractor.extract_experimental_features(clean_url)
            else:
                feature_dict = extractor.extract_features(clean_url)
            feature_vector = [feature_dict[name] for name in feature_names]
        except Exception as e:
            return jsonify({"success": False, "error": "Feature extraction failed on submitted URL."}), 500

        # Verify all features are finite
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in feature_vector):
            return jsonify({"success": False, "error": "Extracted feature vector contains invalid values."}), 500

        # 5. Model Inference & Layered Decision Synthesis
        try:
            decision_result = decision_engine.evaluate_url(clean_url, live_telemetry=presence_details)
        except Exception as e:
            return jsonify({"success": False, "error": "Model prediction failed."}), 500

        # 6. Synthesize structured verdict and confidence
        raw_verdict = decision_result.verdict
        if raw_verdict in (DecisionVerdict.CONFIRMED_MALICIOUS, DecisionVerdict.HIGH_RISK, DecisionVerdict.PHISHING):
            verdict = "phishing"
        elif raw_verdict in (DecisionVerdict.NO_KNOWN_THREAT, DecisionVerdict.LEGITIMATE):
            verdict = "legitimate"
        elif raw_verdict == DecisionVerdict.INCONCLUSIVE:
            verdict = "inconclusive"
        elif raw_verdict == DecisionVerdict.SUSPICIOUS:
            verdict = "suspicious"
        else:
            verdict = "inconclusive"

        if decision_result.model_score is not None:
            phishing_prob = float(decision_result.model_score)
        else:
            phishing_prob = 0.50

        if verdict == "phishing":
            confidence_pct = round(phishing_prob * 100.0, 2)
        elif verdict == "legitimate":
            confidence_pct = round((1.0 - phishing_prob) * 100.0, 2)
        elif verdict == "inconclusive":
            confidence_pct = round(abs(phishing_prob - 0.5) * 200.0, 2)
        else:
            confidence_pct = round(phishing_prob * 100.0, 2)

        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 7. Persist to SQLite Database
        try:
            save_scan(
                url=clean_url,
                verdict=verdict,
                phishing_probability=round(phishing_prob, 5),
                confidence_percent=confidence_pct,
                scanned_at=scanned_at,
                db_path=db_path
            )
        except Exception as e:
            # Non-fatal to scan response, but log appropriately
            pass

        return jsonify({
            "success": True,
            "url": clean_url,
            "website_present": is_present,
            "presence_message": presence_msg,
            "presence_details": presence_details,
            "live_telemetry": presence_details,
            "verdict": verdict,
            "standardized_verdict": decision_result.standardized_verdict,
            "risk_level": decision_result.risk_level.value,
            "phishing_probability": round(phishing_prob, 5),
            "confidence_percent": confidence_pct,
            "threshold": decision_threshold,
            "scanned_at": scanned_at,
            "feature_breakdown": feature_dict,
            "explanation": decision_result.evidence_based_explanation,
            "warnings": decision_result.uncertainty_or_warnings,
            "structural_indicators": decision_result.structural_indicators
        }), 200

    @app.route("/api/history", methods=["GET"])
    def get_history():
        """Retrieve recent URL scan history with pagination."""
        # Parse query params
        limit_arg = request.args.get("limit", default=50)
        offset_arg = request.args.get("offset", default=0)

        try:
            limit = int(limit_arg)
            offset = int(offset_arg)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Parameters 'limit' and 'offset' must be integers."}), 400

        if limit < 1:
            return jsonify({"success": False, "error": "Parameter 'limit' must be >= 1."}), 400
        if offset < 0:
            return jsonify({"success": False, "error": "Parameter 'offset' must be >= 0."}), 400

        enforced_limit = min(limit, 100)

        try:
            history = get_scan_history(limit=enforced_limit, offset=offset, db_path=db_path)
            total_count = get_scan_count(db_path=db_path)
        except Exception as e:
            return jsonify({"success": False, "error": "Failed to query scan history from database."}), 500

        return jsonify({
            "success": True,
            "count": len(history),
            "total": total_count,
            "limit": enforced_limit,
            "offset": offset,
            "history": history
        }), 200

    @app.route("/api/history", methods=["DELETE"])
    def clear_history():
        """Clear all historical scan records from SQLite."""
        try:
            deleted_count = delete_scan_history(db_path=db_path)
        except Exception as e:
            return jsonify({"success": False, "error": "Failed to clear scan history from database."}), 500

        return jsonify({
            "success": True,
            "deleted_records": deleted_count,
            "message": "Scan history deleted successfully."
        }), 200

    # =========================================================================
    # MULTI-TENANT ENTERPRISE SAAS API (V1)
    # =========================================================================

    @app.route("/api/v1/auth/register", methods=["POST"])
    def saas_register():
        """Register a new developer account and issue initial live API key."""
        data = request.get_json(silent=True) or {}
        email = data.get("email")
        password = data.get("password")
        full_name = data.get("full_name", "")
        plan_tier = data.get("plan_tier", "free")

        if not email or not password:
            return jsonify({"success": False, "error": "Email and password are required."}), 400

        try:
            user = saas_data_mgr.register_user(
                email=email, password=password, full_name=full_name, plan_tier=plan_tier
            )
            key_data = saas_data_mgr.create_api_key(
                user_id=user["id"], label="Default Production Key", is_live=True
            )
            token = security_mgr.create_session_token(user_id=user["id"], email=user["email"])

            return jsonify({
                "success": True,
                "user": user,
                "api_key": key_data,
                "session_token": token,
                "message": "Developer account created successfully. Store your API key securely."
            }), 201
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/auth/login", methods=["POST"])
    def saas_login():
        """Sign in with email and password to receive a signed session token."""
        data = request.get_json(silent=True) or {}
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False, "error": "Email and password are required."}), 400

        user = saas_data_mgr.authenticate_user(email=email, password=password)
        if not user:
            return jsonify({"success": False, "error": "Invalid email or password."}), 401

        token = security_mgr.create_session_token(user_id=user["id"], email=user["email"])
        return jsonify({
            "success": True,
            "user": user,
            "session_token": token
        }), 200

    @app.route("/api/v1/keys", methods=["GET"])
    @require_session_token(security_mgr)
    def saas_list_keys():
        """List active and historical API keys for the authenticated developer."""
        user_id = g.user["uid"]
        keys = saas_data_mgr.list_api_keys(user_id)
        return jsonify({"success": True, "keys": keys}), 200

    @app.route("/api/v1/keys", methods=["POST"])
    @require_session_token(security_mgr)
    def saas_create_key():
        """Create a new API key."""
        user_id = g.user["uid"]
        data = request.get_json(silent=True) or {}
        label = data.get("label", "Production API Key")
        is_live = bool(data.get("is_live", True))

        try:
            key_data = saas_data_mgr.create_api_key(user_id=user_id, label=label, is_live=is_live)
            return jsonify({
                "success": True,
                "api_key": key_data,
                "message": "API key generated. Store this key securely; it will not be displayed again."
            }), 201
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/keys/<int:key_id>", methods=["DELETE"])
    @require_session_token(security_mgr)
    def saas_revoke_key(key_id: int):
        """Revoke an active API key."""
        user_id = g.user["uid"]
        success = saas_data_mgr.revoke_api_key(user_id=user_id, key_id=key_id)
        if not success:
            return jsonify({"success": False, "error": "API key not found or already revoked."}), 404
        return jsonify({"success": True, "message": "API key revoked successfully."}), 200

    @app.route("/api/v1/user/usage", methods=["GET"])
    @require_session_token(security_mgr)
    def saas_usage():
        """Get account quota and monthly scan consumption."""
        user = saas_data_mgr.get_user_by_id(g.user["uid"])
        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404
        return jsonify({"success": True, "usage": user}), 200

    @app.route("/api/v1/scan", methods=["POST"])
    @require_api_key(saas_data_mgr, rate_limiter)
    def saas_scan():
        """High-throughput authenticated scan endpoint with multi-tier caching."""
        data = request.get_json(silent=True) or {}
        target_url = data.get("url")

        if not target_url:
            return jsonify({"success": False, "error": "Missing 'url' parameter in request body."}), 400

        val = validate_url(target_url)
        if not val.is_valid:
            return jsonify({"success": False, "error": val.error_message}), 400

        clean_url = val.clean_url

        # Check Cache Layer (< 1ms lookup)
        cached_result = url_reputation_cache.get(clean_url)
        if cached_result:
            cached_result["cached"] = True
            return jsonify(cached_result), 200

        live_telemetry = None
        if enable_presence_check and data.get("check_presence", True):
            is_present, pres_msg, pres_details = check_website_presence(clean_url, timeout=2.5)
            live_telemetry = pres_details

        t0 = time.time()
        res = decision_engine.evaluate_url(clean_url, live_telemetry=live_telemetry)
        latency_ms = round((time.time() - t0) * 1000.0, 2)

        raw_verdict = res.verdict
        if raw_verdict in (DecisionVerdict.CONFIRMED_MALICIOUS, DecisionVerdict.HIGH_RISK, DecisionVerdict.PHISHING):
            verdict_str = "phishing"
        elif raw_verdict in (DecisionVerdict.NO_KNOWN_THREAT, DecisionVerdict.LEGITIMATE):
            verdict_str = "legitimate"
        else:
            verdict_str = raw_verdict.value

        phish_prob = float(res.model_score) if res.model_score is not None else 0.50
        conf_pct = round(phish_prob * 100.0, 2) if verdict_str == "phishing" else round((1.0 - phish_prob) * 100.0, 2)

        output_payload = {
            "success": True,
            "url": clean_url,
            "domain": res.structural_indicators.get("registered_domain", ""),
            "verdict": verdict_str,
            "standardized_verdict": res.standardized_verdict,
            "risk_level": res.risk_level.value,
            "phishing_probability": round(phish_prob, 5),
            "confidence_percent": conf_pct,
            "latency_ms": latency_ms,
            "cached": False,
            "explanation": res.evidence_based_explanation,
            "warnings": res.uncertainty_or_warnings,
            "threat_intelligence": res.threat_intel_summary,
            "structural_indicators": res.structural_indicators,
            "scanned_at": res.timestamp,
        }

        # Cache response
        url_reputation_cache.set(clean_url, output_payload)

        # Log to SaaS audit table
        tenant = getattr(g, "tenant", {})
        saas_data_mgr.log_scan_event(
            url=clean_url,
            domain=res.structural_indicators.get("registered_domain", ""),
            verdict=verdict_str,
            standardized_verdict=res.standardized_verdict,
            risk_level=res.risk_level.value,
            phishing_probability=phish_prob,
            confidence_percent=conf_pct,
            latency_ms=latency_ms,
            user_id=tenant.get("user_id"),
            api_key_id=tenant.get("key_id"),
        )

        return jsonify(output_payload), 200

    # =========================================================================
    # BILLING & SUBSCRIPTIONS (RAZORPAY INTEGRATION)
    # =========================================================================

    @app.route("/api/v1/billing/plans", methods=["GET"])
    def get_billing_plans():
        """Get public subscription plans catalog."""
        return jsonify({"success": True, "plans": billing_mgr.get_plans()}), 200

    @app.route("/api/v1/billing/razorpay/create-order", methods=["POST"])
    @require_session_token(security_mgr)
    def razorpay_create_order():
        """Create a Razorpay order for self-serve checkout."""
        user_id = g.user["uid"]
        data = request.get_json(silent=True) or {}
        tier = data.get("plan_tier", "developer_pro")
        currency = data.get("currency", "INR")

        try:
            res = billing_mgr.create_razorpay_order(user_id=user_id, plan_tier=tier, currency=currency)
            return jsonify(res), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/billing/razorpay/verify-payment", methods=["POST"])
    @require_session_token(security_mgr)
    def razorpay_verify_payment():
        """Verify Razorpay payment signature and activate plan."""
        user_id = g.user["uid"]
        data = request.get_json(silent=True) or {}
        tier = data.get("plan_tier", "developer_pro")
        order_id = data.get("razorpay_order_id")
        payment_id = data.get("razorpay_payment_id")
        signature = data.get("razorpay_signature", "")

        if not order_id or not payment_id:
            return jsonify({"success": False, "error": "Missing razorpay_order_id or razorpay_payment_id."}), 400

        try:
            res = billing_mgr.verify_and_activate_payment(
                user_id=user_id,
                plan_tier=tier,
                order_id=order_id,
                payment_id=payment_id,
                signature=signature
            )
            return jsonify(res), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/billing/checkout", methods=["POST"])
    @require_session_token(security_mgr)
    def create_checkout():
        """Generate a checkout session or Razorpay order for upgrading tier."""
        user_id = g.user["uid"]
        data = request.get_json(silent=True) or {}
        tier = data.get("plan_tier", "developer_pro")
        success_url = data.get("success_url", request.host_url.rstrip("/") + "/api/v1/billing/mock-activate")
        cancel_url = data.get("cancel_url", request.host_url.rstrip("/") + "/#developer")

        try:
            res = billing_mgr.create_checkout_session(
                user_id=user_id,
                plan_tier=tier,
                success_url=success_url,
                cancel_url=cancel_url
            )
            return jsonify(res), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/billing/portal", methods=["POST"])
    @require_session_token(security_mgr)
    def create_portal():
        """Generate a customer portal session URL."""
        user_id = g.user["uid"]
        data = request.get_json(silent=True) or {}
        return_url = data.get("return_url", request.host_url.rstrip("/"))
        try:
            res = billing_mgr.create_customer_portal_session(user_id=user_id, return_url=return_url)
            return jsonify(res), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/billing/webhook", methods=["POST"])
    def billing_webhook():
        """Receive Razorpay and payment lifecycle webhooks."""
        payload_bytes = request.get_data()
        sig_header = request.headers.get("X-Razorpay-Signature") or request.headers.get("Stripe-Signature")
        try:
            res = billing_mgr.handle_webhook(payload_bytes, sig_header=sig_header)
            return jsonify(res), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

    @app.route("/api/v1/billing/mock-activate", methods=["GET"])
    def mock_activate_plan():
        """Convenience browser activation for local development without live Razorpay keys."""
        tier = request.args.get("tier", "developer_pro")
        user_id = request.args.get("user_id")
        if user_id:
            try:
                saas_data_mgr.update_user_plan(int(user_id), tier, subscription_status="active")
            except Exception:
                pass
        return render_template("index.html")

    # =========================================================================
    # OPENAPI SPEC & INTERACTIVE SWAGGER UI
    # =========================================================================

    @app.route("/docs", methods=["GET"])
    def swagger_ui():
        """Interactive OpenAPI / Swagger 3.0 Documentation."""
        return render_template("swagger.html")

    @app.route("/api/v1/openapi.json", methods=["GET"])
    def openapi_spec():
        """OpenAPI 3.0 specification in JSON format."""
        swagger_path = os.path.join(CURRENT_DIR, "static", "swagger.json")
        try:
            with open(swagger_path, "r", encoding="utf-8") as f:
                spec = json.load(f)
            return jsonify(spec), 200
        except Exception as e:
            return jsonify({"error": f"Failed to load OpenAPI spec: {str(e)}"}), 500

    # =========================================================================
    # LEGAL, COMPLIANCE & CYBERSECURITY DISCLAIMERS
    # =========================================================================

    @app.route("/terms", methods=["GET"])
    def terms_of_service():
        """PhishGuardAI Terms of Service and Cybersecurity Disclaimers."""
        return render_template("terms.html")

    @app.route("/privacy", methods=["GET"])
    def privacy_policy():
        """PhishGuardAI Privacy Policy and Data Handling Disclosures."""
        return render_template("privacy.html")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
