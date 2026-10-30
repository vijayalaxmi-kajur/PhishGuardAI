"""
PhishGuardAI - Phase 15C Model Training, Calibration & Rigorous Evaluation
Trains improved experimental candidates on Phase 15C data:
1. cand08_rf_phase15c_30f: Regularized Random Forest (30f)
2. cand09_hist_gbdt_phase15c_30f: Regularized HistGradientBoosting (30f)
3. cand10_calibrated_gbdt_phase15c_30f: Isotonically Calibrated HistGBDT (30f)

Benchmarks on domain-disjoint Holdout set (7,687 samples) against:
- Candidate 4 (Phase 13C-2 RF)
- Candidate 6 (Phase 13C-2 HistGBDT)

Evaluates:
- Overall metrics: Acc, Prec, Rec, F1, Balanced Acc, FPR, FNR, ROC-AUC, PR-AUC, Brier
- Slices: Query URLs, Deep Path URLs, HTTPS URLs, Long URLs
- The 5 target false-positive URLs
- Layered Decision Engine integration and abstention rates
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))
import time
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score,
    f1_score, balanced_accuracy_score, roc_auc_score, average_precision_score,
    brier_score_loss
)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.adapter import ModelInferenceAdapter
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel
from src.threat_intelligence.manager import ThreatIntelligenceManager

PROJECT_ROOT = os.path.abspath(".")
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "phase15c")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "experiments", "phase15c")
os.makedirs(MODELS_DIR, exist_ok=True)

# 1. Load data
print("Loading Phase 15C dataset partitions...")
X_train = pd.read_csv(os.path.join(DATA_DIR, "X_train_30f.csv"))
y_train = pd.read_csv(os.path.join(DATA_DIR, "y_train.csv")).squeeze()

X_val = pd.read_csv(os.path.join(DATA_DIR, "X_val_30f.csv"))
y_val = pd.read_csv(os.path.join(DATA_DIR, "y_val.csv")).squeeze()

X_holdout = pd.read_csv(os.path.join(DATA_DIR, "X_holdout_30f.csv"))
y_holdout = pd.read_csv(os.path.join(DATA_DIR, "y_holdout.csv")).squeeze()
holdout_meta = pd.read_csv(os.path.join(DATA_DIR, "holdout.csv"))

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Holdout: {X_holdout.shape}")
print(f"Holdout Class Distribution: Legit={(y_holdout==0).sum()}, Phish={(y_holdout==1).sum()}")

# 2. Train Model A: Regularized Random Forest (30f)
print("\n--- Training Model A: cand08_rf_phase15c_30f ---")
t0 = time.time()
rf_15c = RandomForestClassifier(
    n_estimators=120,
    max_depth=16,
    min_samples_leaf=4,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf_15c.fit(X_train, y_train)
t_rf = time.time() - t0
print(f"Random Forest trained in {t_rf:.2f}s")
joblib.dump(rf_15c, os.path.join(MODELS_DIR, "cand08_rf_phase15c_30f.joblib"))

# 3. Train Model B: Regularized HistGradientBoosting (30f)
print("\n--- Training Model B: cand09_hist_gbdt_phase15c_30f ---")
t0 = time.time()
gbdt_15c = HistGradientBoostingClassifier(
    max_iter=120,
    max_depth=10,
    min_samples_leaf=15,
    l2_regularization=1.5,
    class_weight="balanced",
    random_state=42
)
gbdt_15c.fit(X_train, y_train)
t_gbdt = time.time() - t0
print(f"HistGradientBoosting trained in {t_gbdt:.2f}s")
joblib.dump(gbdt_15c, os.path.join(MODELS_DIR, "cand09_hist_gbdt_phase15c_30f.joblib"))

# 4. Train Model C: Calibrated HistGBDT (Platt / Isotonic on Val split)
print("\n--- Training Model C: cand10_calibrated_gbdt_phase15c_30f ---")
t0 = time.time()
try:
    from sklearn.frozen import FrozenEstimator
    cal_gbdt = CalibratedClassifierCV(estimator=FrozenEstimator(gbdt_15c), method="isotonic")
    cal_gbdt.fit(X_val, y_val)
except Exception:
    cal_gbdt = CalibratedClassifierCV(estimator=gbdt_15c, cv=5, method="isotonic")
    cal_gbdt.fit(X_train, y_train)

t_cal = time.time() - t0
print(f"Calibrated HistGBDT fitted in {t_cal:.2f}s")
joblib.dump(cal_gbdt, os.path.join(MODELS_DIR, "cand10_calibrated_gbdt_phase15c_30f.joblib"))

# 5. Load Existing Candidate 4 and Candidate 6
cand04 = joblib.load("models/experiments/phase13c2/cand04_rf_regularized_30f.joblib")
cand06 = joblib.load("models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib")

all_models = {
    "Candidate 4 (Phase 13C-2 RF)": cand04,
    "Candidate 6 (Phase 13C-2 GBDT)": cand06,
    "Cand 08 (Phase 15C RF)": rf_15c,
    "Cand 09 (Phase 15C GBDT)": gbdt_15c,
    "Cand 10 (Phase 15C Calibrated GBDT)": cal_gbdt
}

def compute_full_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    return {
        "n_samples": int(len(y_true)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": fpr,
        "fnr": fnr,
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier_score": float(brier_score_loss(y_true, y_prob))
    }

print("\n=======================================================")
print("EVALUATION ON DOMAIN-DISJOINT HOLDOUT SET (7,687 samples)")
print("=======================================================")

holdout_results = {}
for m_name, model in all_models.items():
    proba = model.predict_proba(X_holdout)[:, 1]
    m_dict = compute_full_metrics(y_holdout, proba)
    holdout_results[m_name] = m_dict
    print(f"\n[{m_name}]")
    print(f"  Accuracy: {m_dict['accuracy']:.2%}, Balanced Acc: {m_dict['balanced_accuracy']:.2%}")
    print(f"  Precision: {m_dict['precision']:.2%}, Recall: {m_dict['recall']:.2%}, F1: {m_dict['f1']:.2%}")
    print(f"  FPR: {m_dict['fpr']:.2%} (FP={m_dict['fp']}/{m_dict['fp']+m_dict['tn']}), FNR: {m_dict['fnr']:.2%} (FN={m_dict['fn']}/{m_dict['fn']+m_dict['tp']})")
    print(f"  ROC-AUC: {m_dict['roc_auc']:.4f}, PR-AUC: {m_dict['pr_auc']:.4f}, Brier Loss: {m_dict['brier_score']:.4f}")

# 6. Sliced Evaluation on Holdout Set: Dynamic & Long URLs
print("\n=======================================================")
print("SLICED EVALUATION ON HOLDOUT SET (CHALLENGING SUBGROUPS)")
print("=======================================================")

# Masks for slices
mask_query = holdout_meta["url"].str.contains(r"\?", regex=True)
mask_deep_path = X_holdout["path_depth"] >= 2
mask_https = X_holdout["is_https"] == 1
mask_long = X_holdout["url_len"] > 50

slices = [
    ("Legitimate URLs With Query String", (y_holdout == 0) & mask_query),
    ("Legitimate URLs With Deep Path (depth >= 2)", (y_holdout == 0) & mask_deep_path),
    ("Legitimate URLs With HTTPS", (y_holdout == 0) & mask_https),
    ("Legitimate URLs With Length > 50", (y_holdout == 0) & mask_long),
]

for slice_name, mask in slices:
    n_samples = mask.sum()
    print(f"\n--- Slice: {slice_name} ({n_samples} legitimate samples) ---")
    if n_samples == 0:
        continue
    X_sub = X_holdout[mask]
    for m_name, model in all_models.items():
        proba = model.predict_proba(X_sub)[:, 1]
        fp_count = (proba >= 0.5).sum()
        fpr = fp_count / n_samples
        print(f"  {m_name:36s}: FP={fp_count:3d}/{n_samples} (FPR={fpr:.2%}), Mean Prob={proba.mean():.2%}")

# 7. Evaluate the 5 Target Problematic URLs
print("\n=======================================================")
print("EVALUATING THE 5 TARGET PROBLEMATIC REAL-WORLD URLS")
print("=======================================================")

target_cases = [
    ("1. YouTube Playlist", "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4"),
    ("2. Skills Google", "https://www.skills.google/course_templates/702"),
    ("3. Unstop Blog", "https://unstop.com/blog/infosys-aptitude-questions"),
    ("4. Spring Evening PL", "https://springeveningpl.com/"),
    ("5. Edutainer Internship", "http://www.internship.edutainer.in/student/student-dashboard")
]

extractor = ExperimentalURLFeatureExtractor()
intel_mgr = ThreatIntelligenceManager()

target_rows = []
for label, url in target_cases:
    vec = extractor.extract_vector(url, schema="experimental")
    df_vec = pd.DataFrame([vec], columns=extractor.EXPERIMENTAL_FEATURE_NAMES)
    
    row = {"Case": label, "URL": url}
    for m_name, model in all_models.items():
        prob = float(model.predict_proba(df_vec)[0][1])
        row[m_name] = f"{prob:.2%}"
    
    # Layered Decision Engine evaluation with Cand 09 (Phase 15C GBDT) and Cand 10 (Calibrated GBDT)
    eng9 = LayeredDecisionEngine(ml_model=gbdt_15c, feature_schema="experimental", threat_intel_manager=intel_mgr, model_name="Cand 09 (Phase 15C GBDT)")
    eng10 = LayeredDecisionEngine(ml_model=cal_gbdt, feature_schema="experimental", threat_intel_manager=intel_mgr, model_name="Cand 10 (Phase 15C Calibrated GBDT)")
    
    res9 = eng9.evaluate_url(url)
    res10 = eng10.evaluate_url(url)
    
    row["DE + Cand 09 Verdict"] = f"{res9.verdict.value} ({res9.risk_level.value})"
    row["DE + Cand 10 Verdict"] = f"{res10.verdict.value} ({res10.risk_level.value})"
    target_rows.append(row)

df_targets = pd.DataFrame(target_rows)
print(df_targets[["Case", "Candidate 4 (Phase 13C-2 RF)", "Candidate 6 (Phase 13C-2 GBDT)", "Cand 09 (Phase 15C GBDT)", "Cand 10 (Phase 15C Calibrated GBDT)", "DE + Cand 10 Verdict"]].to_string(index=False))

with open("scratch/phase15c_benchmark_summary.json", "w") as f:
    json.dump({
        "holdout_results": holdout_results,
        "target_cases": target_rows
    }, f, indent=2)

print("\nBenchmark and evaluation complete! Summary saved to scratch/phase15c_benchmark_summary.json")
