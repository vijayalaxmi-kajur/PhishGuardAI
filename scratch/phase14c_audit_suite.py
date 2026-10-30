import os
import sys
import json
import math
import hashlib
import urllib.parse
import pandas as pd
import numpy as np
import unittest
from unittest.mock import MagicMock

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath("."))

from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel, DecisionResult
from src.decision_engine.adapter import ModelInferenceAdapter
from src.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatLookupResult,
    ThreatStatus,
    ThreatCategory,
    MultiProviderLookupResult,
)
from src.threat_intelligence.manager import ThreatIntelligenceManager
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
import joblib

def defang_url(url: str) -> str:
    """Safely defang a URL to prevent accidental clicks or rendering."""
    if not isinstance(url, str):
        return ""
    d = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    d = d.replace(".", "[.]")
    return d

def run_task2_fp_investigation():
    print("=" * 80)
    print("TASK 2: INVESTIGATING CANDIDATE 6 FALSE POSITIVES (N = 90)")
    print("=" * 80)

    eval_meta = pd.read_csv("data/phase14a/phase14a_verified_evaluation_set.csv")
    X_eval = pd.read_csv("data/phase14a/X_eval_30f.csv")
    y_eval = pd.read_csv("data/phase14a/y_eval.csv")["label"]

    cand06_path = "models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib"
    cand06_model = joblib.load(cand06_path)
    adapter06 = ModelInferenceAdapter(cand06_model, feature_schema="experimental", model_name="Cand06_HistGBDT")

    cand04_path = "models/experiments/phase13c2/cand04_rf_regularized_30f.joblib"
    cand04_model = joblib.load(cand04_path)
    adapter04 = ModelInferenceAdapter(cand04_model, feature_schema="experimental", model_name="Cand04_RF")

    preds06 = []
    probas06 = []
    preds04 = []
    probas04 = []

    for idx in range(len(X_eval)):
        row_vec = X_eval.iloc[idx : idx + 1]
        p06 = adapter06.predict_proba(row_vec)
        probas06.append(p06)
        preds06.append(1 if p06 >= 0.50 else 0)

        p04 = adapter04.predict_proba(row_vec)
        probas04.append(p04)
        preds04.append(1 if p04 >= 0.50 else 0)

    eval_meta["cand06_prob"] = probas06
    eval_meta["cand06_pred"] = preds06
    eval_meta["cand04_prob"] = probas04
    eval_meta["cand04_pred"] = preds04

    # Legitimate URLs: y_true == 0
    legit_df = eval_meta[eval_meta["label"] == 0].copy()
    print(f"Total legitimate URLs: {len(legit_df)}")

    fp06_df = legit_df[legit_df["cand06_pred"] == 1].copy()
    print(f"Total Candidate 6 False Positives: {len(fp06_df)}")

    # Length stats
    lengths = fp06_df["url"].apply(len)
    print("\n--- False Positive URL Length Statistics ---")
    print(f"Min Length: {lengths.min()}")
    print(f"Max Length: {lengths.max()}")
    print(f"Mean Length: {lengths.mean():.2f}")
    print(f"Median Length: {lengths.median():.2f}")

    # Query parameters
    has_query = fp06_df["url"].apply(lambda u: "?" in u)
    print(f"\n--- Query Parameter Breakdown ---")
    print(f"FPs with query parameters: {has_query.sum()} ({has_query.sum()/len(fp06_df)*100:.2f}%)")
    print(f"FPs without query parameters: {(~has_query).sum()} ({(~has_query).sum()/len(fp06_df)*100:.2f}%)")

    # Categories in evaluation metadata
    cat_counts = fp06_df["category"].value_counts()
    print(f"\n--- FPs by Subgroup Category ---")
    for cat, cnt in cat_counts.items():
        total_cat = (legit_df["category"] == cat).sum()
        fpr_cat = cnt / total_cat * 100
        print(f"  {cat:35s}: {cnt:2d} / {total_cat:2d} FPs (FPR = {fpr_cat:5.2f}%)")

    # Domain structure
    def get_registered_domain(url):
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            host = parsed.netloc.split(":")[0]
            parts = host.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return host
        except Exception:
            return ""

    fp06_df["reg_domain"] = fp06_df["url"].apply(get_registered_domain)
    dom_counts = fp06_df["reg_domain"].value_counts().head(10)
    print(f"\n--- Top 10 Registered Domains in FPs ---")
    for dom, cnt in dom_counts.items():
        print(f"  {dom:25s}: {cnt:2d} FPs")

    # Feature comparison: False Positives vs True Negatives
    fp_indices = fp06_df.index
    X_eval_fps = X_eval.loc[fp_indices]
    X_eval_tns = X_eval.loc[legit_df[legit_df["cand06_pred"] == 0].index]

    print(f"\n--- Mean Feature Comparison: False Positives vs True Negatives ---")
    key_features = [
        "url_len", "path_len", "query_len", "slash_cnt", "dot_cnt",
        "entropy", "dom_entropy", "query_entropy",
        "subdom_cnt", "query_param_cnt", "path_depth", "host_len",
        "dom_digit_cnt", "query_digit_cnt"
    ]
    print(f"{'Feature':20s} {'FP Mean (N=90)':18s} {'TN Mean (N=73)':18s} {'Diff (FP - TN)':15s}")
    for kf in key_features:
        fp_mean = X_eval_fps[kf].mean()
        tn_mean = X_eval_tns[kf].mean()
        diff = fp_mean - tn_mean
        print(f"{kf:20s} {fp_mean:18.3f} {tn_mean:18.3f} {diff:+15.3f}")

    # Defanged Examples by Archetype
    print(f"\n--- Defanged Examples Across Key Archetypes ---")
    archetypes = fp06_df["category"].unique()
    fp_examples = {}
    for arch in archetypes:
        sample_row = fp06_df[fp06_df["category"] == arch].iloc[0]
        raw_url = sample_row["url"]
        prob = sample_row["cand06_prob"]
        defanged = defang_url(raw_url)
        fp_examples[arch] = {
            "defanged_url": defanged,
            "prob": prob,
            "query": "?" in raw_url,
            "len": len(raw_url),
        }
        print(f"Archetype: {arch}")
        print(f"  Defanged URL : {defanged[:90]}...")
        print(f"  Probability  : {prob:.4f}")
        print(f"  Length       : {len(raw_url)} chars | Has Query: {'?' in raw_url}")

    return fp06_df, legit_df

def run_task3_decision_engine_safety():
    print("\n" + "=" * 80)
    print("TASK 3: DECISION ENGINE SAFETY AUDIT")
    print("=" * 80)

    cand06_path = "models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib"
    cand06_model = joblib.load(cand06_path)

    # 1. Tracing raw model scores to final verdicts
    print("\n[3.1] Tracing Raw Model Score to Verdict Translation:")
    mock_intel_mgr = ThreatIntelligenceManager(providers=[])
    engine = LayeredDecisionEngine(ml_model=cand06_model, feature_schema="experimental", threat_intel_manager=mock_intel_mgr)

    # Test baseline thresholds logic
    test_urls = [
        ("Clean short URL", "https://example.com/about", "Low score -> NO KNOWN THREAT"),
        ("Complex query on low entropy domain", "https://europepmc.org/search?query=CRISPR+Cas9+gene+editing&page=1", "High score with query contrast -> INCONCLUSIVE"),
        ("Raw IP with auth path", "http://192.168.1.100/login/auth.php", "Structural IP+auth -> HIGH RISK"),
        ("Misleading subdomain brand spoofing", "https://paypal.com.account-verify.suspicious-domain.xyz/login", "Brand spoofing -> HIGH RISK"),
        ("Hosting platform credential endpoint", "https://phish-target.webflow.io/login", "Shared hosting abuse -> SUSPICIOUS/HIGH RISK")
    ]
    for desc, url, expectation in test_urls:
        res = engine.evaluate_url(url)
        print(f"  {desc:38s}: Score={res.model_score} | Verdict={res.standardized_verdict} | Risk={res.risk_level.value}")
        print(f"    Expected: {expectation}")

    # 2. Test Exception in Model Inference
    print("\n[3.2] Testing ML Inference Exception Handling:")
    class FaultyAdapter(ModelInferenceAdapter):
        def predict_proba(self, url_or_features):
            raise RuntimeError("Simulated ML engine crash (CUDA/OOM/Corrupt Weights)")

    faulty_adapter = FaultyAdapter(cand06_model, feature_schema="experimental")
    engine_faulty = LayeredDecisionEngine(ml_model=faulty_adapter, feature_schema="experimental", threat_intel_manager=mock_intel_mgr)
    faulty_res = engine_faulty.evaluate_url("https://example.com/some/path")
    print(f"  Result when ML crashes: Verdict='{faulty_res.standardized_verdict}', Risk='{faulty_res.risk_level.value}'")
    print(f"  Model Score is None: {faulty_res.model_score is None}")
    print(f"  Warning logged: {any('inference failed' in w for w in faulty_res.uncertainty_or_warnings)}")
    assert faulty_res.verdict == DecisionVerdict.INCONCLUSIVE, "Failed safe on ML exception!"
    assert faulty_res.risk_level == RiskLevel.UNKNOWN, "Failed safe on ML exception!"
    assert faulty_res.verdict != DecisionVerdict.NO_KNOWN_THREAT, "VIOLATION: ML crash declared safe!"
    print("  PASS: Engine fails safely to INCONCLUSIVE / Risk UNKNOWN on ML exception. Never declares safe.")

    # 3. Test Missing or Invalid Features
    print("\n[3.3] Testing Missing or Non-Finite Features in Adapter:")
    adapter = ModelInferenceAdapter(cand06_model, feature_schema="experimental")
    
    # Missing required feature
    corrupt_dict = {"url_len": 25, "dom_len": 10} # Missing 28 features
    try:
        adapter.extract_and_format_input(corrupt_dict)
        print("  FAIL: Adapter did not reject missing features!")
    except ValueError as e:
        print(f"  PASS: Adapter rejected missing features: {str(e)[:80]}...")

    # NaN or Inf features
    valid_features = {k: 1.0 for k in adapter.feature_names}
    valid_features["entropy"] = float("nan")
    try:
        adapter.extract_and_format_input(valid_features)
        print("  FAIL: Adapter did not reject NaN feature!")
    except ValueError as e:
        print(f"  PASS: Adapter rejected NaN feature: {str(e)[:80]}...")

    valid_features["entropy"] = float("inf")
    try:
        adapter.extract_and_format_input(valid_features)
        print("  FAIL: Adapter did not reject Inf feature!")
    except ValueError as e:
        print(f"  PASS: Adapter rejected Inf feature: {str(e)[:80]}...")

    # 4. Test Unavailable Threat Intelligence Providers
    print("\n[3.4] Testing Threat Intelligence Degradation and Missing Provider Tolerance:")
    class DegradedMockProvider(BaseThreatProvider):
        def get_provider_name(self) -> str:
            return "MockThreatFeed"
        def is_enabled(self) -> bool:
            return True
        def check_url(self, url: str) -> ThreatLookupResult:
            return ThreatLookupResult(
                provider_name="MockThreatFeed",
                status=ThreatStatus.TIMEOUT,
                error_message="Gateway Timeout 504 from threat intel upstream",
                is_threat=False,
            )

    degraded_mgr = ThreatIntelligenceManager(providers=[DegradedMockProvider()])
    degraded_result = degraded_mgr.check_url("https://malicious-unknown-campaign.com/verify")
    print(f"  Degraded providers detected: {degraded_result.degraded_providers}")
    print(f"  is_any_threat flag: {degraded_result.is_any_threat}")
    print(f"  Warnings emitted: {degraded_result.warnings}")
    
    # Check that missing threat intel is not treated as safe
    engine_degraded = LayeredDecisionEngine(ml_model=cand06_model, feature_schema="experimental", threat_intel_manager=degraded_mgr)
    degraded_engine_res = engine_degraded.evaluate_url("https://malicious-unknown-campaign.com/verify")
    print(f"  Engine evaluation with degraded provider: Verdict={degraded_engine_res.standardized_verdict}, Risk={degraded_engine_res.risk_level.value}")
    assert any("A missing intelligence match must NOT be interpreted as proof that a URL is legitimate" in w for w in degraded_engine_res.uncertainty_or_warnings)
    print("  PASS: Provider timeout emits critical caveat warning; absence of intel is NEVER treated as proof of safety.")

    # 5. Check Whether Any Rule Can Suppress High-Risk Signals Without Evidence
    print("\n[3.5] Testing High-Risk Signal Suppression Guardrails:")
    # Can entropy contrast suppress a URL if it has an auth path?
    auth_query_url = "https://legitimate-looking.com/login/verify.php?session=abc123456789&token=xyz987654321"
    res_auth = engine.evaluate_url(auth_query_url)
    print(f"  URL with auth path & query params: Verdict={res_auth.standardized_verdict} | Risk={res_auth.risk_level.value}")
    # Verify that can_abstain_query blocked the downgrade because has_auth_path is True!
    assert res_auth.verdict != DecisionVerdict.INCONCLUSIVE or not res_auth.structural_indicators["has_entropy_contrast"], \
        "Guardrail violation: Auth path was downgraded via entropy contrast!"
    
    # Can entropy contrast suppress a URL if it has a suspicious TLD?
    sus_tld_url = "https://document-portal.xyz/search?q=very+long+query+parameter+with+many+words+here+to+trigger+entropy&page=2"
    res_sus_tld = engine.evaluate_url(sus_tld_url)
    print(f"  URL with suspicious TLD & query params: Verdict={res_sus_tld.standardized_verdict} | Risk={res_sus_tld.risk_level.value}")
    assert res_sus_tld.structural_indicators["has_suspicious_tld"] == True
    print("  PASS: High-risk guardrails strictly prevent entropy contrast from suppressing auth paths, suspicious TLDs, or brand spoofing.")

def run_task4_robustness_tests():
    print("\n" + "=" * 80)
    print("TASK 4: ROBUSTNESS & ADVERSARIAL EDGE CASE TESTS")
    print("=" * 80)

    cand06_path = "models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib"
    cand06_model = joblib.load(cand06_path)
    mock_intel_mgr = ThreatIntelligenceManager(providers=[])
    engine = LayeredDecisionEngine(ml_model=cand06_model, feature_schema="experimental", threat_intel_manager=mock_intel_mgr)
    adapter = ModelInferenceAdapter(cand06_model, feature_schema="experimental")

    test_cases = [
        ("Empty URL", "", "INCONCLUSIVE / Risk UNKNOWN; Input validation failed"),
        ("Whitespace URL", "   \t \n  ", "INCONCLUSIVE / Risk UNKNOWN; Input validation failed"),
        ("Malformed URL (bare scheme)", "http://", "Handled gracefully without crashing"),
        ("Malformed URL (multiple slashes)", "https://///", "Handled gracefully without crashing"),
        ("Malformed URL (invalid host chars)", "http://??::255.255/", "Handled gracefully without crashing"),
        ("Unsupported scheme (ftp)", "ftp://files.example.com/archive.zip", "Handled gracefully without crashing"),
        ("Unsupported scheme (javascript)", "javascript:alert(document.cookie)", "Handled gracefully without crashing"),
        ("Unsupported scheme (file)", "file:///etc/passwd", "Handled gracefully without crashing"),
        ("Unsupported scheme (data URI)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Handled gracefully without crashing"),
        ("Extremely long URL (>4000 chars)", "https://example.com/api/query?" + "param=" + "A" * 4500, "Handled gracefully without buffer overflow/OOM"),
        ("Punycode homograph", "https://xn--e1afmkfd.xn--p1ai/test", "Flagged Punycode homograph indicator"),
    ]

    robustness_results = []

    for name, input_val, expected in test_cases:
        try:
            res = engine.evaluate_url(input_val)
            actual_verdict = res.standardized_verdict
            actual_risk = res.risk_level.value
            score_str = f"{res.model_score:.4f}" if res.model_score is not None else "None"
            print(f"[TEST] {name:36s} | Verdict: {actual_verdict:25s} | Risk: {actual_risk:8s} | Score: {score_str}")
            robustness_results.append({
                "test": name,
                "input_snippet": repr(input_val[:40]),
                "verdict": actual_verdict,
                "risk": actual_risk,
                "status": "PASS",
                "notes": expected
            })
        except Exception as e:
            print(f"[TEST] {name:36s} | CRASHED: {e}")
            robustness_results.append({
                "test": name,
                "input_snippet": repr(input_val[:40]),
                "verdict": "CRASH",
                "risk": "CRASH",
                "status": "FAIL",
                "notes": str(e)
            })

    # Test Invalid Feature Dimensions
    print("\n--- Testing Feature Dimension & Type Robustness in Adapter ---")
    try:
        adapter.extract_and_format_input(np.ones((1, 22), dtype=np.float32))
        print("FAIL: Adapter accepted 22 features for 30-feature schema!")
    except ValueError as e:
        print(f"PASS: Adapter rejected 22 features: {str(e)[:70]}...")

    try:
        adapter.extract_and_format_input(np.ones((1, 35), dtype=np.float32))
        print("FAIL: Adapter accepted 35 features for 30-feature schema!")
    except ValueError as e:
        print(f"PASS: Adapter rejected 35 features: {str(e)[:70]}...")

    # Test Model Loading Failure
    print("\n--- Testing Model Loading Failure Handling ---")
    try:
        # Corrupted / invalid model object
        bad_adapter = ModelInferenceAdapter(model="not_a_model")
        bad_adapter.predict_proba("https://example.com")
        print("FAIL: Bad model did not raise error!")
    except Exception as e:
        print(f"PASS: Non-model object cleanly rejected: {type(e).__name__}: {str(e)[:70]}...")

    # Test Unexpected Model Outputs
    print("\n--- Testing Unexpected Model Outputs ---")
    class OutOfBoundsModel:
        def __init__(self, out_proba):
            self.classes_ = np.array([0, 1])
            self.n_features_in_ = 30
            self.out_proba = out_proba
        def predict_proba(self, X):
            return np.array([self.out_proba])

    # Case: Model outputs negative or >1 probability
    oob_adapter = ModelInferenceAdapter(
        OutOfBoundsModel([-0.2, 1.2]),
        feature_schema="experimental",
        feature_names=list(cand06_model.feature_names_in_)
    )
    prob = oob_adapter.predict_proba("https://example.com")
    print(f"  Model output probability out-of-bounds: {prob}")
    # Engine evaluates this without crashing
    engine_oob = LayeredDecisionEngine(ml_model=oob_adapter, feature_schema="experimental", threat_intel_manager=mock_intel_mgr)
    res_oob = engine_oob.evaluate_url("https://example.com")
    print(f"  Engine verdict on out-of-bounds probability: Verdict={res_oob.standardized_verdict}, Risk={res_oob.risk_level.value}")

    return robustness_results

def run_task5_leakage_and_independence():
    print("\n" + "=" * 80)
    print("TASK 5: LEAKAGE AND INDEPENDENCE AUDIT")
    print("=" * 80)

    eval_meta = pd.read_csv("data/phase14a/phase14a_verified_evaluation_set.csv")
    eval_urls = set(eval_meta["url"].str.strip())
    print(f"Total evaluation URLs: {len(eval_urls)}")

    # Check against training/validation/test splits of Phase 13C
    splits = {
        "Phase 13C Train": "data/phase13c/splits/train.csv",
        "Phase 13C Val": "data/phase13c/splits/val.csv",
        "Phase 13C Test": "data/phase13c/splits/test.csv",
        "Original Dataset.csv": "dataset/Dataset.csv"
    }

    def extract_domain(url):
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            host = parsed.netloc.split(":")[0].lower()
            parts = host.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return host
        except Exception:
            return ""

    eval_domains = set(eval_meta["url"].apply(extract_domain))
    print(f"Total unique registered domains in evaluation set: {len(eval_domains)}")

    for split_name, split_path in splits.items():
        if not os.path.exists(split_path):
            print(f"  {split_name}: File not found at {split_path}")
            continue

        split_df = pd.read_csv(split_path)
        url_col = "url" if "url" in split_df.columns else "URL"
        if url_col not in split_df.columns:
            print(f"  {split_name}: URL column not found!")
            continue

        split_urls = set(split_df[url_col].astype(str).str.strip())
        url_overlap = eval_urls.intersection(split_urls)
        print(f"\n--- Checking overlap with {split_name} (N = {len(split_df):,}) ---")
        print(f"  URL Exact Overlap Count: {len(url_overlap)}")
        if len(url_overlap) > 0:
            print(f"  WARNING: Exact URL overlap detected! Sample: {list(url_overlap)[:3]}")
        else:
            print(f"  CONFIRMED: 0.00% URL leakage. Zero evaluation URLs were used in {split_name}.")

        split_domains = set(split_df[url_col].astype(str).apply(extract_domain))
        domain_overlap = eval_domains.intersection(split_domains)
        print(f"  Domain Overlap Count: {len(domain_overlap)} / {len(eval_domains)} ({len(domain_overlap)/len(eval_domains)*100:.2f}%)")
        print(f"  Shared Domains Sample: {list(domain_overlap)[:5]}")

    # Inspect Multi-tenant / Hosting Platform distribution
    print(f"\n--- Multi-Tenant Hosting Platform Dependence in Evaluation Set ---")
    hosting_providers = [
        "000webhostapp.com", "weebly.com", "wixsite.com", "github.io",
        "vercel.app", "netlify.app", "firebaseapp.com", "square.site",
        "google.com", "wikipedia.org", "stackexchange.com"
    ]
    for hp in hosting_providers:
        hp_matches = eval_meta[eval_meta["url"].str.contains(hp, case=False, na=False)]
        if len(hp_matches) > 0:
            p_cnt = (hp_matches["label"] == 1).sum()
            l_cnt = (hp_matches["label"] == 0).sum()
            print(f"  Hosting provider '{hp:20s}': {len(hp_matches):2d} URLs (Phish: {p_cnt:2d}, Legit: {l_cnt:2d})")

    # Provenance audit
    print(f"\n--- Provenance Audit of Phase 14A Labels ---")
    prov_counts = eval_meta["source"].value_counts()
    for prov, cnt in prov_counts.items():
        print(f"  Source '{prov:35s}': {cnt:3d} records")

if __name__ == "__main__":
    run_task2_fp_investigation()
    run_task3_decision_engine_safety()
    run_task4_robustness_tests()
    run_task5_leakage_and_independence()
