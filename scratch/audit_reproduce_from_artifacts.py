import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
)
import sys, os
sys.path.insert(0, os.path.abspath("."))
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

ext = ExperimentalURLFeatureExtractor()

with open("models/experiments/stage1/stage1_evaluation_results.json", "r") as f:
    saved_json = json.load(f)

# Models
prod_m = joblib.load("models/phishing_model.joblib")["model"]
c1_m = joblib.load("models/experiments/stage1/rf_baseline_22f.joblib")["model"]
c2_m = joblib.load("models/experiments/stage1/rf_regularized_22f.joblib")["model"]
c3_m = joblib.load("models/experiments/stage1/rf_experimental_30f.joblib")["model"]
c4_m = joblib.load("models/experiments/stage1/rf_calibrated_30f.joblib")["model"]

models = [
    ("Production RF (22f, Baseline)", prod_m, "baseline"),
    ("Candidate 1 (RF Baseline 22f)", c1_m, "baseline"),
    ("Candidate 2 (RF Regularized 22f)", c2_m, "baseline"),
    ("Candidate 3 (RF Experimental 30f)", c3_m, "experimental"),
    ("Candidate 4 (RF Calibrated 30f)", c4_m, "experimental"),
]

# Benchmark (N=41)
df_real = pd.read_csv("data/realistic_evaluation_set.csv")
y_real = df_real["label"].values.astype(int)
X_real_22 = np.array([ext.extract_vector(u, "baseline") for u in df_real["url"]], dtype=np.float32)
X_real_30 = np.array([ext.extract_vector(u, "experimental") for u in df_real["url"]], dtype=np.float32)

print("=== VERIFYING REALISTIC BENCHMARK (N=41) REPRODUCIBILITY ===")
for name, m, schema in models:
    X = X_real_22 if schema == "baseline" else X_real_30
    p = m.predict_proba(X)[:, 1]
    y_pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_real, y_pred, labels=[0, 1]).ravel()
    saved = saved_json["realistic_benchmark_metrics"][name]
    
    match = (tn == saved["tn"] and fp == saved["fp"] and fn == saved["fn"] and tp == saved["tp"])
    print(f"[{'PASS' if match else 'FAIL'}] {name:<35}: TN={tn}, FP={fp}, FN={fn}, TP={tp} (Saved TN={saved['tn']}, FP={saved['fp']}, FN={saved['fn']}, TP={saved['tp']})")
    if not match:
        print(f"   DISCREPANCY DETECTED FOR {name} on Benchmark!")
