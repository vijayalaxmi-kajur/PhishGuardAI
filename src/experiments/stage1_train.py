"""PhishGuardAI - Stage 1 Model Retraining & Comprehensive Evaluation Pipeline

Trains experimental models on stage1_training.csv with validation tuning,
evaluates on strictly held-out unseen domains (stage1_evaluation.csv),
the separate realistic benchmark (realistic_evaluation_set.csv), and individual test targets.

Saves all models and metrics in models/experiments/stage1/ without modifying production.
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel

RANDOM_SEED = 42
TARGET_LEGIT_URLS = [
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4",
    "https://www.wikipedia.org/",
    "https://www.microsoft.com/",
    "https://github.com/",
    "https://www.python.org/",
]

TARGET_PHISH_URLS = [
    "http://netflix-billing-alert.com/login",
    "http://login-account-update.xyz/verify",
    "http://192.241.220.14/portal/admin/login.php",
    "https://paypal.com.account-verification-notice.org/login",
    "https://secure-chase-auth.top/signin",
]


def extract_matrix(urls: List[str], schema: str) -> np.ndarray:
    """Extract feature matrix for a list of URLs."""
    ext = ExperimentalURLFeatureExtractor()
    features = [ext.extract_vector(u, schema=schema) for u in urls]
    return np.array(features, dtype=np.float32)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict[str, Any]:
    """Calculate comprehensive evaluation metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None
    pr_auc = float(average_precision_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else None
    brier = float(brier_score_loss(y_true, y_proba))

    return {
        "n_samples": int(len(y_true)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "brier_score": brier,
    }


def main():
    print("=== STAGE 2 & 3: MODEL RETRAINING & MULTI-TIER EVALUATION ===")
    models_dir = os.path.join(PROJECT_ROOT, "models", "experiments", "stage1")
    os.makedirs(models_dir, exist_ok=True)

    # 1. Load Datasets
    train_path = os.path.join(PROJECT_ROOT, "data", "experiments", "stage1_training.csv")
    val_path = os.path.join(PROJECT_ROOT, "data", "experiments", "stage1_validation.csv")
    eval_path = os.path.join(PROJECT_ROOT, "data", "experiments", "stage1_evaluation.csv")
    real_path = os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv")

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_eval = pd.read_csv(eval_path)
    df_real = pd.read_csv(real_path)

    print(f"Loaded Train Data : {len(df_train)} rows ({dict(df_train['label'].value_counts())})")
    print(f"Loaded Val Data   : {len(df_val)} rows ({dict(df_val['label'].value_counts())})")
    print(f"Loaded Eval Data  : {len(df_eval)} rows ({dict(df_eval['label'].value_counts())})")
    print(f"Loaded Real Data  : {len(df_real)} rows ({dict(df_real['label'].value_counts())})")

    # 2. Extract Features
    print("\n--- Extracting Features ---")
    t0 = time.time()
    X_train_22 = extract_matrix(df_train["url"].tolist(), schema="baseline")
    X_train_30 = extract_matrix(df_train["url"].tolist(), schema="experimental")
    y_train = df_train["label"].values.astype(int)

    X_val_22 = extract_matrix(df_val["url"].tolist(), schema="baseline")
    X_val_30 = extract_matrix(df_val["url"].tolist(), schema="experimental")
    y_val = df_val["label"].values.astype(int)

    X_eval_22 = extract_matrix(df_eval["url"].tolist(), schema="baseline")
    X_eval_30 = extract_matrix(df_eval["url"].tolist(), schema="experimental")
    y_eval = df_eval["label"].values.astype(int)

    X_real_22 = extract_matrix(df_real["url"].tolist(), schema="baseline")
    X_real_30 = extract_matrix(df_real["url"].tolist(), schema="experimental")
    y_real = df_real["label"].values.astype(int)
    print(f"Feature extraction completed in {time.time() - t0:.2f}s.")

    # 3. Load Production Baseline Model for Reference
    prod_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib")
    prod_artifact = joblib.load(prod_path)
    prod_model = prod_artifact["model"] if isinstance(prod_artifact, dict) else prod_artifact

    # 4. Train Candidates on Training Set
    # Candidate 1: RF Baseline (22f, unconstrained)
    print("\n--- Training Candidate 1: RF Baseline (22f, unconstrained) ---")
    rf_base_22 = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1)
    rf_base_22.fit(X_train_22, y_train)
    joblib.dump({"model": rf_base_22, "features": ExperimentalURLFeatureExtractor.BASELINE_FEATURE_NAMES, "schema": "baseline"},
                os.path.join(models_dir, "rf_baseline_22f.joblib"))

    # Candidate 2: RF Regularized (22f, depth=18, min_samples_leaf=4)
    print("--- Training Candidate 2: RF Regularized (22f, depth=18) ---")
    rf_reg_22 = RandomForestClassifier(n_estimators=100, max_depth=18, min_samples_leaf=4, max_features="sqrt", class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1)
    rf_reg_22.fit(X_train_22, y_train)
    joblib.dump({"model": rf_reg_22, "features": ExperimentalURLFeatureExtractor.BASELINE_FEATURE_NAMES, "schema": "baseline"},
                os.path.join(models_dir, "rf_regularized_22f.joblib"))

    # Candidate 3: RF Experimental (30f, component-isolated, regularized)
    print("--- Training Candidate 3: RF Experimental (30f, component-isolated) ---")
    rf_exp_30 = RandomForestClassifier(n_estimators=100, max_depth=18, min_samples_leaf=4, max_features="sqrt", class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1)
    rf_exp_30.fit(X_train_30, y_train)
    joblib.dump({"model": rf_exp_30, "features": ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES, "schema": "experimental"},
                os.path.join(models_dir, "rf_experimental_30f.joblib"))

    # Candidate 4: RF Calibrated (30f, 5-fold CV Platt Scaling)
    print("--- Training Candidate 4: RF Calibrated (30f, 5-fold CV Platt Scaling) ---")
    base_rf = RandomForestClassifier(n_estimators=100, max_depth=18, min_samples_leaf=4, max_features="sqrt", class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1)
    rf_cal_30 = CalibratedClassifierCV(estimator=base_rf, method="sigmoid", cv=5)
    rf_cal_30.fit(X_train_30, y_train)
    joblib.dump({"model": rf_cal_30, "features": ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES, "schema": "experimental"},
                os.path.join(models_dir, "rf_calibrated_30f.joblib"))

    # 5. Validation-Split Model Selection Evaluation
    print("\n=== VALIDATION SPLIT EVALUATION (MODEL SELECTION GATE) ===")
    val_candidates = [
        ("Candidate 1 (RF Baseline 22f)", rf_base_22, "baseline", X_val_22),
        ("Candidate 2 (RF Regularized 22f)", rf_reg_22, "baseline", X_val_22),
        ("Candidate 3 (RF Experimental 30f)", rf_exp_30, "experimental", X_val_30),
        ("Candidate 4 (RF Calibrated 30f)", rf_cal_30, "experimental", X_val_30),
    ]
    val_metrics = {}
    for name, m, schema, X_v in val_candidates:
        p = m.predict_proba(X_v)[:, 1]
        y_pred = (p >= 0.5).astype(int)
        met = compute_metrics(y_val, y_pred, p)
        val_metrics[name] = met
        print(f"  {name:<35}: Acc={met['accuracy']:.4f} | Prec={met['precision']:.4f} | Rec={met['recall']:.4f} | F1={met['f1_score']:.4f} | FPR={met['false_positive_rate']:.4%}")

    # 6. Held-Out Evaluation (Unseen Registered Domains, N=11,382)
    print("\n=== HELD-OUT UNSEEN DOMAIN EVALUATION (N=11,382) ===")
    eval_candidates = [
        ("Production RF (22f, Baseline)", prod_model, "baseline", X_eval_22),
        ("Candidate 1 (RF Baseline 22f)", rf_base_22, "baseline", X_eval_22),
        ("Candidate 2 (RF Regularized 22f)", rf_reg_22, "baseline", X_eval_22),
        ("Candidate 3 (RF Experimental 30f)", rf_exp_30, "experimental", X_eval_30),
        ("Candidate 4 (RF Calibrated 30f)", rf_cal_30, "experimental", X_eval_30),
    ]
    eval_metrics = {}
    for name, m, schema, X_e in eval_candidates:
        p = m.predict_proba(X_e)[:, 1]
        y_pred = (p >= 0.5).astype(int)
        met = compute_metrics(y_eval, y_pred, p)
        eval_metrics[name] = met
        print(f"  {name:<35}: Acc={met['accuracy']:.4f} | Prec={met['precision']:.4f} | Rec={met['recall']:.4f} | F1={met['f1_score']:.4f} | FPR={met['false_positive_rate']:.4%}")

    # 7. Separate Realistic Benchmark Evaluation (N=41)
    print("\n=== SEPARATE REALISTIC BENCHMARK EVALUATION (N=41) ===")
    real_metrics = {}
    for name, m, schema, _ in eval_candidates:
        X_r = X_real_22 if schema == "baseline" else X_real_30
        p = m.predict_proba(X_r)[:, 1]
        y_pred = (p >= 0.5).astype(int)
        met = compute_metrics(y_real, y_pred, p)
        real_metrics[name] = met
        print(f"  {name:<35}: TN={met['tn']}/26, FP={met['fp']}, FN={met['fn']}/15, TP={met['tp']} | FPR={met['false_positive_rate']:.2%}, Rec={met['recall']:.2%}")

    # 8. Real Prediction Tests (Stage 4)
    print("\n=== STAGE 4: REAL PREDICTION TESTS ON TARGET URLS ===")
    test_urls = TARGET_LEGIT_URLS + TARGET_PHISH_URLS
    test_results = []

    ext = ExperimentalURLFeatureExtractor()
    for u in test_urls:
        vec_22 = np.array([ext.extract_vector(u, "baseline")], dtype=np.float32)
        vec_30 = np.array([ext.extract_vector(u, "experimental")], dtype=np.float32)

        prod_p = float(prod_model.predict_proba(vec_22)[0, 1])
        c1_p = float(rf_base_22.predict_proba(vec_22)[0, 1])
        c2_p = float(rf_reg_22.predict_proba(vec_22)[0, 1])
        c3_p = float(rf_exp_30.predict_proba(vec_30)[0, 1])
        c4_p = float(rf_cal_30.predict_proba(vec_30)[0, 1])

        # Layered Decision Engine evaluation (using Candidate 2)
        engine = LayeredDecisionEngine(ml_model=rf_reg_22, feature_schema="baseline", model_name="RF_Regularized_22f")
        engine_res = engine.evaluate_url(u)

        row = {
            "url": u,
            "type": "LEGIT" if u in TARGET_LEGIT_URLS else "PHISH",
            "prod_prob": prod_p,
            "c1_prob": c1_p,
            "c2_prob": c2_p,
            "c3_prob": c3_p,
            "c4_prob": c4_p,
            "engine_verdict": engine_res.verdict.value,
            "engine_standardized": engine_res.standardized_verdict,
            "engine_risk_level": engine_res.risk_level.value,
        }
        test_results.append(row)
        u_short = u[:55]
        print(f"[{row['type']}] {u_short:<55} | Prod:{prod_p:.2f} | C1:{c1_p:.2f} | C2:{c2_p:.2f} | C3:{c3_p:.2f} | Engine:{row['engine_standardized']}")

    # 9. Dump All Metrics to JSON
    output_summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "random_seed": RANDOM_SEED,
        "validation_metrics": val_metrics,
        "held_out_evaluation_metrics": eval_metrics,
        "realistic_benchmark_metrics": real_metrics,
        "target_url_predictions": test_results,
    }
    out_json = os.path.join(models_dir, "stage1_evaluation_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(output_summary, f, indent=2)

    print(f"\nAll Stage 1 results successfully saved to: {out_json}")


if __name__ == "__main__":
    main()
