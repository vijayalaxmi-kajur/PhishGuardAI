"""
PhishGuardAI - Phase 13D Independent Error Analysis & Model Selection Audit Engine
Executes complete independent reproduction and error analysis:
1. Independently recalculates validation metrics for Candidate 4 and Candidate 6
2. Independently recalculates test metrics for Candidate 4 and Candidate 6
3. Evaluates Candidate 4 and Candidate 6 on realistic benchmark (tri-partition)
4. Evaluates Layered Decision Engine interaction with both models
5. Detailed error analysis of False Positives and False Negatives
6. Generates supporting JSON and CSV audit tables
"""

import os
import sys
import json
import joblib
import urllib.parse
from typing import Dict, List, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, brier_score_loss
)

PROJECT_ROOT = r"c:\Users\yalla\OneDrive\Desktop\PhishGuardAI"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.engine import LayeredDecisionEngine
from src.decision_engine.adapter import ModelInferenceAdapter

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "experiments", "phase13c2")
SPLITS_DIR = os.path.join(PROJECT_ROOT, "data", "phase13c", "splits")
BENCH_PATH = os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "phase13", "phase13d")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def defang_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    u = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parsed = urllib.parse.urlsplit(url)
    if parsed.netloc:
        defanged_netloc = parsed.netloc.replace(".", "[.]")
        u = u.replace(parsed.netloc, defanged_netloc, 1)
    return u

print("Loading dataset splits...")
val_meta = pd.read_csv(os.path.join(SPLITS_DIR, "val.csv"))
test_meta = pd.read_csv(os.path.join(SPLITS_DIR, "test.csv"))
y_val = pd.read_csv(os.path.join(SPLITS_DIR, "y_val.csv")).squeeze()
y_test = pd.read_csv(os.path.join(SPLITS_DIR, "y_test.csv")).squeeze()

X_val_30 = pd.read_csv(os.path.join(SPLITS_DIR, "X_val_30f.csv"))
X_test_30 = pd.read_csv(os.path.join(SPLITS_DIR, "X_test_30f.csv"))

# Load candidate models
print("Loading model artifacts...")
cand04_path = os.path.join(MODELS_DIR, "cand04_rf_regularized_30f.joblib")
cand06_path = os.path.join(MODELS_DIR, "cand06_hist_gbdt_30f.joblib")

cand04_model = joblib.load(cand04_path)
cand06_model = joblib.load(cand06_path)

# Verify classes_
print(f"Cand04 classes: {getattr(cand04_model, 'classes_', None)}")
print(f"Cand06 classes: {getattr(cand06_model, 'classes_', None)}")

# Helper to compute comprehensive metrics
def evaluate_predictions(y_true, y_proba, threshold=0.50) -> Dict[str, Any]:
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    return {
        "total": int(len(y_true)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": fpr,
        "fnr": fnr,
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "pr_auc": float(average_precision_score(y_true, y_proba)),
        "brier_score": float(brier_score_loss(y_true, y_proba))
    }

# ==========================================
# 1. INDEPENDENT VALIDATION REPRODUCTION
# ==========================================
print("\n--- Reproducing Validation Metrics ---")
# Predict with joblib models
val_proba_c04 = cand04_model.predict_proba(X_val_30)[:, 1]
val_proba_c06 = cand06_model.predict_proba(X_val_30)[:, 1]

# Also load saved predictions from validation_predictions.csv to verify consistency
saved_preds = pd.read_csv(os.path.join(MODELS_DIR, "validation_predictions.csv"))
diff_c04 = np.max(np.abs(val_proba_c04 - saved_preds["cand04_rf_regularized_30f_proba"].values))
diff_c06 = np.max(np.abs(val_proba_c06 - saved_preds["cand06_hist_gbdt_30f_proba"].values))
print(f"Max proba delta vs saved CSV: Cand04 = {diff_c04:.2e}, Cand06 = {diff_c06:.2e}")

val_metrics_c04 = evaluate_predictions(y_val, val_proba_c04, threshold=0.50)
val_metrics_c06 = evaluate_predictions(y_val, val_proba_c06, threshold=0.50)

print("Cand04 Validation Metrics:", json.dumps(val_metrics_c04, indent=2))
print("Cand06 Validation Metrics:", json.dumps(val_metrics_c06, indent=2))

# ==========================================
# 2. INDEPENDENT TEST METRICS REPRODUCTION
# ==========================================
print("\n--- Reproducing Test Metrics ---")
test_proba_c04 = cand04_model.predict_proba(X_test_30)[:, 1]
test_proba_c06 = cand06_model.predict_proba(X_test_30)[:, 1]

test_metrics_c04 = evaluate_predictions(y_test, test_proba_c04, threshold=0.50)
test_metrics_c06 = evaluate_predictions(y_test, test_proba_c06, threshold=0.50)

print("Cand04 Test Metrics:", json.dumps(test_metrics_c04, indent=2))
print("Cand06 Test Metrics:", json.dumps(test_metrics_c06, indent=2))

# Sliced metrics on Test Set
def slice_metrics(meta_df, y_true, y_proba):
    lens = meta_df["url"].apply(len)
    https = meta_df["url"].apply(lambda u: 1 if u.lower().startswith("https://") else 0)
    query = meta_df["url"].apply(lambda u: 1 if "?" in u else 0)
    
    slices = {}
    for low, high in [(0, 50), (50, 90), (90, 150), (150, 10000)]:
        lbl = f"len_[{low},{high})" if high < 10000 else f"len_[{low}+)"
        m = (lens >= low) & (lens < high)
        if m.sum() > 0:
            slices[lbl] = evaluate_predictions(y_true[m], y_proba[m])
            
    slices["http"] = evaluate_predictions(y_true[https == 0], y_proba[https == 0])
    slices["https"] = evaluate_predictions(y_true[https == 1], y_proba[https == 1])
    slices["without_query"] = evaluate_predictions(y_true[query == 0], y_proba[query == 0])
    slices["with_query"] = evaluate_predictions(y_true[query == 1], y_proba[query == 1])
    return slices

cand04_test_slices = slice_metrics(test_meta, y_test, test_proba_c04)
cand06_test_slices = slice_metrics(test_meta, y_test, test_proba_c06)

# ==========================================
# 3. REALISTIC BENCHMARK EVALUATION
# ==========================================
print("\n--- Evaluating on Realistic Benchmark ---")
df_bench = pd.read_csv(BENCH_PATH)
ext30 = ExperimentalURLFeatureExtractor()
bench_feats = [ext30.extract_experimental_features(u) for u in df_bench["url"]]
X_bench = pd.DataFrame(bench_feats)

bench_proba_c04 = cand04_model.predict_proba(X_bench)[:, 1]
bench_proba_c06 = cand06_model.predict_proba(X_bench)[:, 1]

df_bench["proba_cand04"] = bench_proba_c04
df_bench["pred_cand04"] = (bench_proba_c04 >= 0.50).astype(int)
df_bench["proba_cand06"] = bench_proba_c06
df_bench["pred_cand06"] = (bench_proba_c06 >= 0.50).astype(int)

# Tri-Partition evaluation for Cand04 and Cand06
bench_eval = {}
for name, p_col, pred_col in [("cand04", "proba_cand04", "pred_cand04"), ("cand06", "proba_cand06", "pred_cand06")]:
    # Partition A: Verified (N=38)
    v_mask = df_bench["verification_status"].isin(["verified_legitimate", "verified_phishing"])
    df_v = df_bench[v_mask]
    v_metrics = evaluate_predictions(df_v["label"].values, df_v[p_col].values)
    
    # Partition B: Stress (N=3)
    s_mask = df_bench["verification_status"] == "unverified_stress_case"
    df_s = df_bench[s_mask]
    s_pred_phish_count = int(df_s[pred_col].sum())
    
    # Partition C: Combined (N=41)
    c_metrics = evaluate_predictions(df_bench["label"].values, df_bench[p_col].values)
    
    bench_eval[name] = {
        "verified_N38": v_metrics,
        "stress_N3_phish_count": s_pred_phish_count,
        "combined_N41": c_metrics
    }

print("Benchmark Eval Summary:", json.dumps(bench_eval, indent=2))

# ==========================================
# 4. DECISION ENGINE INTEGRATION AUDIT
# ==========================================
print("\n--- Auditing Decision Engine Integration ---")
# Evaluate how LayeredDecisionEngine behaves when paired with Cand04 vs Cand06
engine_c04 = LayeredDecisionEngine(ml_model=cand04_model, feature_schema="experimental", model_name="Cand04_RF_30f")
engine_c06 = LayeredDecisionEngine(ml_model=cand06_model, feature_schema="experimental", model_name="Cand06_HistGBDT_30f")

engine_results = []
for idx, row in df_bench.iterrows():
    u = row["url"]
    lbl = int(row["label"])
    
    res_c04 = engine_c04.evaluate_url(u)
    res_c06 = engine_c06.evaluate_url(u)
    
    engine_results.append({
        "index": idx,
        "url_defanged": defang_url(u),
        "actual_label": lbl,
        "status": row.get("verification_status", ""),
        "category": row.get("category", ""),
        "cand04_model_proba": float(row["proba_cand04"]),
        "cand04_verdict": res_c04.verdict.value,
        "cand04_risk_level": res_c04.risk_level.value,
        "cand04_standardized": res_c04.standardized_verdict,
        "cand04_explanation": res_c04.evidence_based_explanation,
        "cand06_model_proba": float(row["proba_cand06"]),
        "cand06_verdict": res_c06.verdict.value,
        "cand06_risk_level": res_c06.risk_level.value,
        "cand06_standardized": res_c06.standardized_verdict,
        "cand06_explanation": res_c06.evidence_based_explanation
    })

df_engine = pd.DataFrame(engine_results)
df_engine.to_csv(os.path.join(OUTPUT_DIR, "benchmark_decision_engine_comparison.csv"), index=False)
print(f"Saved Decision Engine comparison -> {os.path.join(OUTPUT_DIR, 'benchmark_decision_engine_comparison.csv')}")

# User Target URL check
target_url = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"
res_target_c04 = engine_c04.evaluate_url(target_url)
res_target_c06 = engine_c06.evaluate_url(target_url)
print("\nTARGET YOUTUBE LECTURE URL WITH DECISION ENGINE:")
print(f"  With Cand04: Model Score={res_target_c04.model_score:.4f}, Verdict={res_target_c04.verdict.value}, Standardized={res_target_c04.standardized_verdict}, Risk={res_target_c04.risk_level.value}")
print(f"  With Cand06: Model Score={res_target_c06.model_score:.4f}, Verdict={res_target_c06.verdict.value}, Standardized={res_target_c06.standardized_verdict}, Risk={res_target_c06.risk_level.value}")

# ==========================================
# 5. ERROR ANALYSIS: FALSE POSITIVES & FALSE NEGATIVES
# ==========================================
print("\n--- Extracting Detailed Error Logs ---")

# Benchmark Error Analysis (Candidate 4 and 6)
bench_errors = []
for idx, row in df_bench.iterrows():
    u = row["url"]
    lbl = int(row["label"])
    c04_pred = int(row["pred_cand04"])
    c06_pred = int(row["pred_cand06"])
    
    # Check if either model made an error
    is_c04_error = (c04_pred != lbl)
    is_c06_error = (c06_pred != lbl)
    
    if is_c04_error or is_c06_error:
        # Extract features for this URL
        feats = ext30.extract_experimental_features(u)
        bench_errors.append({
            "index": idx,
            "url_defanged": defang_url(u),
            "actual_label": lbl,
            "verification_status": row.get("verification_status", ""),
            "category": row.get("category", ""),
            "source": row.get("source", ""),
            "c04_prob": float(row["proba_cand04"]),
            "c04_pred": c04_pred,
            "c04_error_type": "FP" if (lbl == 0 and c04_pred == 1) else ("FN" if (lbl == 1 and c04_pred == 0) else "None"),
            "c06_prob": float(row["proba_cand06"]),
            "c06_pred": c06_pred,
            "c06_error_type": "FP" if (lbl == 0 and c06_pred == 1) else ("FN" if (lbl == 1 and c06_pred == 0) else "None"),
            "url_len": feats["url_len"],
            "path_len": feats["path_len"],
            "query_len": feats["query_len"],
            "query_param_cnt": feats["query_param_cnt"],
            "entropy": round(feats["entropy"], 3),
            "query_entropy": round(feats["query_entropy"], 3),
            "is_https": feats["is_https"]
        })

df_bench_errors = pd.DataFrame(bench_errors)
df_bench_errors.to_csv(os.path.join(OUTPUT_DIR, "benchmark_misclassifications.csv"), index=False)
print(f"Saved benchmark misclassifications ({len(df_bench_errors)} records) -> {os.path.join(OUTPUT_DIR, 'benchmark_misclassifications.csv')}")

# Test Set Error Analysis (Candidate 4)
test_pred_c04 = (test_proba_c04 >= 0.50).astype(int)
test_fp_mask = (y_test == 0) & (test_pred_c04 == 1)
test_fn_mask = (y_test == 1) & (test_pred_c04 == 0)

test_fps = test_meta[test_fp_mask].copy()
test_fps["proba"] = test_proba_c04[test_fp_mask]
test_fps["error_type"] = "FP"

test_fns = test_meta[test_fn_mask].copy()
test_fns["proba"] = test_proba_c04[test_fn_mask]
test_fns["error_type"] = "FN"

test_errors = pd.concat([test_fps, test_fns], ignore_index=True)
test_errors["url_defanged"] = test_errors["url"].apply(defang_url)
test_errors_csv = os.path.join(OUTPUT_DIR, "test_split_cand04_errors.csv")
test_errors.to_csv(test_errors_csv, index=False)
print(f"Saved test split errors ({len(test_errors)} records: {len(test_fps)} FP, {len(test_fns)} FN) -> {test_errors_csv}")

# Compile comprehensive audit JSON
independent_audit_data = {
    "validation_reproduction": {
        "candidate_04": val_metrics_c04,
        "candidate_06": val_metrics_c06,
        "reported_vs_reproduced_match": {
            "cand04_f1_match": abs(val_metrics_c04["f1"] - 0.911068) < 1e-5,
            "cand06_f1_match": abs(val_metrics_c06["f1"] - 0.913780) < 1e-5
        }
    },
    "test_reproduction": {
        "candidate_04": test_metrics_c04,
        "candidate_06": test_metrics_c06,
        "cand04_slices": cand04_test_slices,
        "cand06_slices": cand06_test_slices
    },
    "benchmark_reproduction": bench_eval,
    "model_size_comparison": {
        "cand04_bytes": os.path.getsize(cand04_path),
        "cand06_bytes": os.path.getsize(cand06_path),
        "size_ratio_cand04_to_cand06": float(os.path.getsize(cand04_path) / os.path.getsize(cand06_path))
    }
}

with open(os.path.join(OUTPUT_DIR, "independent_audit_summary.json"), "w") as f:
    json.dump(independent_audit_data, f, indent=2)

print(f"Saved independent audit summary -> {os.path.join(OUTPUT_DIR, 'independent_audit_summary.json')}")
print("PHASE 13D INDEPENDENT AUDIT CALCULATIONS COMPLETE!")
