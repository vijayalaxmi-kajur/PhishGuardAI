"""
PhishGuardAI - Phase 14B Independent Model Evaluation & Decision Engine Benchmarking Engine
Executes complete evaluation protocol on the locked Phase 14A dataset (N=963):
1. Verifies dataset integrity (800 Phish, 163 Legit).
2. Extracts 30-feature evaluation matrix using ExperimentalURLFeatureExtractor.
3. Saves data/phase14a/X_eval_30f.csv and data/phase14a/y_eval.csv.
4. Evaluates Candidate 4 and Candidate 6 at fixed threshold tau = 0.50.
5. Computes Confusion Matrices, Accuracy, Precision, Recall, F1, Macro F1, Balanced Accuracy,
   FPR, FNR, ROC-AUC, PR-AUC, Brier score, and Wilson 95% Confidence Intervals.
6. Conducts Subgroup & Error Analysis across Protocol, Length, Query, Category, and Host types.
7. Benchmarks LayeredDecisionEngine with offline mock providers (ThreatIntelligenceManager(providers=[])).
8. Exports comprehensive CSVs and JSON summary to reports/phase14/phase14b/.
"""

import os
import sys


import json
import time
import urllib.parse
from typing import Dict, List, Any, Tuple
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score,
    f1_score, balanced_accuracy_score, roc_auc_score, average_precision_score,
    brier_score_loss
)

PROJECT_ROOT = r"c:\Users\yalla\OneDrive\Desktop\PhishGuardAI"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.engine import LayeredDecisionEngine
from src.threat_intelligence.manager import ThreatIntelligenceManager

DATA_FILE = os.path.join(PROJECT_ROOT, "data", "phase14a", "phase14a_verified_evaluation_set.csv")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "experiments", "phase13c2")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "phase14", "phase14b")
PHASE14A_DIR = os.path.join(PROJECT_ROOT, "data", "phase14a")

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

def wilson_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = float(k / n)
    z = 1.95996  # 95%
    denom = 1 + (z**2 / n)
    center = (p + (z**2 / (2 * n))) / denom
    margin = (z * np.sqrt((p * (1 - p) / n) + (z**2 / (4 * (n**2))))) / denom
    return (max(0.0, float(center - margin)), min(1.0, float(center + margin)))

# ==========================================
# STEP 1: VERIFY EVALUATION ARTIFACTS
# ==========================================
print("--- Step 1: Verifying Evaluation Artifacts ---")
assert os.path.exists(DATA_FILE), f"Missing evaluation file: {DATA_FILE}"
df_eval = pd.read_csv(DATA_FILE)
total_count = len(df_eval)
assert total_count == 963, f"Expected 963 rows, got {total_count}"

counts = df_eval["label"].value_counts().to_dict()
phish_count = counts.get(1, 0)
legit_count = counts.get(0, 0)
assert phish_count == 800, f"Expected 800 phish, got {phish_count}"
assert legit_count == 163, f"Expected 163 legit, got {legit_count}"
print(f"Verified dataset: Total={total_count}, Phishing={phish_count}, Legitimate={legit_count}")

cand04_path = os.path.join(MODELS_DIR, "cand04_rf_regularized_30f.joblib")
cand06_path = os.path.join(MODELS_DIR, "cand06_hist_gbdt_30f.joblib")
assert os.path.exists(cand04_path), f"Missing Cand04: {cand04_path}"
assert os.path.exists(cand06_path), f"Missing Cand06: {cand06_path}"

cand04_model = joblib.load(cand04_path)
cand06_model = joblib.load(cand06_path)
print("Loaded trained model artifacts: Cand04 (Random Forest) and Cand06 (HistGBDT)")

# ==========================================
# STEP 2: EXTRACT FEATURES
# ==========================================
print("\n--- Step 2: Extracting 30-Feature Matrix ---")
extractor = ExperimentalURLFeatureExtractor()
ref_cols = pd.read_csv(os.path.join(PROJECT_ROOT, "data", "phase13c", "splits", "X_test_30f.csv"), nrows=1).columns.tolist()

feature_records = []
for idx, row in df_eval.iterrows():
    u = row["url"]
    feats = extractor.extract_experimental_features(u)
    feature_records.append(feats)

X_eval = pd.DataFrame(feature_records)[ref_cols]
y_eval = df_eval["label"].astype(int)

# Verifications
assert len(X_eval) == 963, f"Expected 963 feature rows, got {len(X_eval)}"
assert list(X_eval.columns) == ref_cols, "Feature columns do not match expected order"
assert not X_eval.isna().any().any(), "Found NaN in feature matrix"
assert not np.isinf(X_eval.values).any(), "Found Inf in feature matrix"
assert len(y_eval) == 963, "Label length mismatch"

x_eval_path = os.path.join(PHASE14A_DIR, "X_eval_30f.csv")
y_eval_path = os.path.join(PHASE14A_DIR, "y_eval.csv")
X_eval.to_csv(x_eval_path, index=False)
y_eval.to_csv(y_eval_path, index=False)
print(f"Saved feature matrix ({X_eval.shape}) -> {x_eval_path}")
print(f"Saved labels ({len(y_eval)}) -> {y_eval_path}")

# ==========================================
# STEP 3: EVALUATE CANDIDATE 4 AND CANDIDATE 6
# ==========================================
print("\n--- Step 3: Evaluating Candidate Models (Fixed Threshold tau = 0.50) ---")

def compute_comprehensive_metrics(y_true, y_proba, threshold=0.50) -> Dict[str, Any]:
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    n_total = len(y_true)
    n_neg = int(tn + fp)
    n_pos = int(fn + tp)
    
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    
    fpr = float(fp / n_neg) if n_neg > 0 else 0.0
    fnr = float(fn / n_pos) if n_pos > 0 else 0.0
    
    roc_auc = float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None
    pr_auc = float(average_precision_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None
    brier = float(brier_score_loss(y_true, y_proba))
    
    # Wilson Intervals
    acc_ci = wilson_interval(int(tp + tn), n_total)
    prec_ci = wilson_interval(int(tp), int(tp + fp)) if (tp + fp) > 0 else (0.0, 0.0)
    rec_ci = wilson_interval(int(tp), n_pos) if n_pos > 0 else (0.0, 0.0)
    fpr_ci = wilson_interval(int(fp), n_neg) if n_neg > 0 else (0.0, 0.0)
    
    return {
        "total": n_total,
        "n_legitimate": n_neg,
        "n_phishing": n_pos,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": acc,
        "accuracy_ci95": acc_ci,
        "precision": prec,
        "precision_ci95": prec_ci,
        "recall": rec,
        "recall_ci95": rec_ci,
        "f1_score": f1,
        "macro_f1": macro_f1,
        "balanced_accuracy": bal_acc,
        "fpr": fpr,
        "fpr_ci95": fpr_ci,
        "fnr": fnr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "brier_score": brier
    }

proba_c04 = cand04_model.predict_proba(X_eval)[:, 1]
proba_c06 = cand06_model.predict_proba(X_eval)[:, 1]

df_eval["c04_proba"] = proba_c04
df_eval["c04_pred"] = (proba_c04 >= 0.50).astype(int)
df_eval["c06_proba"] = proba_c06
df_eval["c06_pred"] = (proba_c06 >= 0.50).astype(int)

metrics_c04 = compute_comprehensive_metrics(y_eval.values, proba_c04, threshold=0.50)
metrics_c06 = compute_comprehensive_metrics(y_eval.values, proba_c06, threshold=0.50)

print("\nCANDIDATE 4 OVERALL METRICS:")
print(json.dumps(metrics_c04, indent=2))

print("\nCANDIDATE 6 OVERALL METRICS:")
print(json.dumps(metrics_c06, indent=2))

# ==========================================
# STEP 4: ERROR AND SUBGROUP ANALYSIS
# ==========================================
print("\n--- Step 4: Sliced Subgroup Analysis ---")

def evaluate_subgroups(df, y_true, y_proba):
    subgroups = {}
    
    # 1. Protocol: HTTPS vs HTTP
    for proto in ["https", "http"]:
        m = (df["is_https"] == 1) if proto == "https" else (df["is_https"] == 0)
        if m.sum() > 0:
            subgroups[f"protocol_{proto}"] = compute_comprehensive_metrics(y_true[m], y_proba[m])
            
    # 2. Query String Presence
    for q_lbl, q_val in [("with_query", 1), ("no_query", 0)]:
        m = (df["has_query"] == q_val)
        if m.sum() > 0:
            subgroups[f"query_{q_lbl}"] = compute_comprehensive_metrics(y_true[m], y_proba[m])
            
    # 3. URL Length Bins
    lens = df["url_len"]
    for low, high in [(0, 50), (50, 90), (90, 150), (150, 10000)]:
        lbl = f"len_[{low},{high})" if high < 10000 else f"len_[{low}+)"
        m = (lens >= low) & (lens < high)
        if m.sum() > 0:
            subgroups[lbl] = compute_comprehensive_metrics(y_true[m], y_proba[m])
            
    # 4. Categories
    for cat in df["category"].unique():
        m = (df["category"] == cat)
        if m.sum() > 0:
            subgroups[f"cat_{cat}"] = compute_comprehensive_metrics(y_true[m], y_proba[m])
            
    return subgroups

slices_c04 = evaluate_subgroups(df_eval, y_eval.values, proba_c04)
slices_c06 = evaluate_subgroups(df_eval, y_eval.values, proba_c06)

# Extract and Save Misclassifications
misclass_records = []
for idx, row in df_eval.iterrows():
    u = row["url"]
    lbl = int(row["label"])
    c04_p = int(row["c04_pred"])
    c06_p = int(row["c06_pred"])
    
    if (c04_p != lbl) or (c06_p != lbl):
        feats = extractor.extract_experimental_features(u)
        misclass_records.append({
            "index": idx,
            "url_defanged": defang_url(u),
            "actual_label": lbl,
            "category": row["category"],
            "source": row["source"],
            "registered_domain": row["registered_domain"],
            "c04_proba": float(row["c04_proba"]),
            "c04_pred": c04_p,
            "c04_error": "FP" if (lbl == 0 and c04_p == 1) else ("FN" if (lbl == 1 and c04_p == 0) else "None"),
            "c06_proba": float(row["c06_proba"]),
            "c06_pred": c06_p,
            "c06_error": "FP" if (lbl == 0 and c06_p == 1) else ("FN" if (lbl == 1 and c06_p == 0) else "None"),
            "url_len": feats["url_len"],
            "path_len": feats["path_len"],
            "query_len": feats["query_len"],
            "query_param_cnt": feats["query_param_cnt"],
            "entropy": round(feats["entropy"], 3),
            "query_entropy": round(feats["query_entropy"], 3),
            "is_https": feats["is_https"]
        })

df_misclass = pd.DataFrame(misclass_records)
misclass_csv_path = os.path.join(OUTPUT_DIR, "phase14b_misclassifications.csv")
df_misclass.to_csv(misclass_csv_path, index=False)
print(f"Saved misclassification audit ({len(df_misclass)} records) -> {misclass_csv_path}")

# ==========================================
# STEP 5: DECISION ENGINE BENCHMARKING
# ==========================================
print("\n--- Step 5: Benchmarking Layered Decision Engine (Offline Mock Mode) ---")

# Configure LayeredDecisionEngine with offline mock providers: ThreatIntelligenceManager(providers=[])
offline_intel_c04 = ThreatIntelligenceManager(providers=[])
offline_intel_c06 = ThreatIntelligenceManager(providers=[])

engine_c04 = LayeredDecisionEngine(
    ml_model=cand04_model,
    feature_schema="experimental",
    threat_intel_manager=offline_intel_c04,
    model_name="Cand04_RF_30f"
)
engine_c06 = LayeredDecisionEngine(
    ml_model=cand06_model,
    feature_schema="experimental",
    threat_intel_manager=offline_intel_c06,
    model_name="Cand06_HistGBDT_30f"
)

engine_eval_records = []
t0 = time.time()

for idx, row in df_eval.iterrows():
    u = row["url"]
    lbl = int(row["label"])
    
    res_c04 = engine_c04.evaluate_url(u)
    res_c06 = engine_c06.evaluate_url(u)
    
    engine_eval_records.append({
        "index": idx,
        "url_defanged": defang_url(u),
        "actual_label": lbl,
        "category": row["category"],
        "source": row["source"],
        "c04_model_proba": float(row["c04_proba"]),
        "c04_verdict": res_c04.verdict.value,
        "c04_risk_level": res_c04.risk_level.value,
        "c04_standardized": res_c04.standardized_verdict,
        "c04_explanation": res_c04.evidence_based_explanation,
        "c06_model_proba": float(row["c06_proba"]),
        "c06_verdict": res_c06.verdict.value,
        "c06_risk_level": res_c06.risk_level.value,
        "c06_standardized": res_c06.standardized_verdict,
        "c06_explanation": res_c06.evidence_based_explanation
    })

t1 = time.time()
print(f"Evaluated 963 URLs through both Layered Decision Engines in {t1 - t0:.2f} seconds ({((t1 - t0)/963)*1000:.2f} ms/URL).")

df_engine = pd.DataFrame(engine_eval_records)
engine_csv_path = os.path.join(OUTPUT_DIR, "phase14b_decision_engine_comparison.csv")
df_engine.to_csv(engine_csv_path, index=False)
print(f"Saved Decision Engine benchmark comparison -> {engine_csv_path}")

# Decision Engine Distribution Summaries
engine_summary_c04 = df_engine.groupby(["actual_label", "c04_standardized"]).size().unstack(fill_value=0).to_dict()
engine_summary_c06 = df_engine.groupby(["actual_label", "c06_standardized"]).size().unstack(fill_value=0).to_dict()

# Compile complete summary JSON
eval_summary = {
    "evaluation_phase": "Phase 14B",
    "dataset": "data/phase14a/phase14a_verified_evaluation_set.csv",
    "sample_count": 963,
    "phishing_count": 800,
    "legitimate_count": 163,
    "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "candidate_04": {
        "model_name": "cand04_rf_regularized_30f",
        "overall_metrics": metrics_c04,
        "slices": slices_c04,
        "engine_verdicts_by_label": engine_summary_c04
    },
    "candidate_06": {
        "model_name": "cand06_hist_gbdt_30f",
        "overall_metrics": metrics_c06,
        "slices": slices_c06,
        "engine_verdicts_by_label": engine_summary_c06
    },
    "misclassification_counts": {
        "c04_fp": metrics_c04["fp"],
        "c04_fn": metrics_c04["fn"],
        "c06_fp": metrics_c06["fp"],
        "c06_fn": metrics_c06["fn"]
    }
}

summary_json_path = os.path.join(OUTPUT_DIR, "phase14b_evaluation_summary.json")
with open(summary_json_path, "w") as f:
    json.dump(eval_summary, f, indent=2)

print(f"Saved Phase 14B evaluation summary JSON -> {summary_json_path}")
print("PHASE 14B EVALUATION ENGINE EXECUTION COMPLETE!")
