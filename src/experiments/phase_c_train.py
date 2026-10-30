"""PhishGuardAI - Experimental Model Training & Evaluation Pipeline (Phase C)

This script trains and rigorously evaluates experimental models on the
partitioned Phase C dataset (zero domain overlap, zero near-duplicate leakage).

Models trained:
1. rf_augmented_22f: Baseline 22-feature Random Forest on augmented dataset.
2. rf_experimental_30f: Component-isolated 30-feature Random Forest on augmented dataset.
3. rf_calibrated_30f: 30-feature Random Forest with 5-fold Platt probability calibration.

All artifacts are persisted strictly in models/experiments/phase_c/ without
modifying any production models or application code.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
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

# Set project root
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

RANDOM_SEED = 42
TARGET_YOUTUBE_URL = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"


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


def evaluate_slice(
    model: Any,
    urls: List[str],
    y_true: np.ndarray,
    schema: str,
    threshold: float = 0.5
) -> Dict[str, Any]:
    """Evaluate model on a specific slice of URLs."""
    if len(urls) == 0:
        return {}
    X = extract_matrix(urls, schema=schema)
    y_proba = model.predict_proba(X)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)
    return compute_metrics(y_true, y_pred, y_proba)


def main():
    print("=== PHASE C4: TRAINING EXPERIMENTAL MODELS ===")
    os.makedirs(os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c"), exist_ok=True)

    train_path = os.path.join(PROJECT_ROOT, "data", "experiments", "phase_c_training.csv")
    eval_path = os.path.join(PROJECT_ROOT, "data", "experiments", "phase_c_evaluation.csv")
    real_path = os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv")

    df_train = pd.read_csv(train_path)
    df_eval = pd.read_csv(eval_path)
    df_real = pd.read_csv(real_path)

    print(f"Loaded Train Data: {len(df_train)} rows ({dict(df_train['label'].value_counts())})")
    print(f"Loaded Eval Data : {len(df_eval)} rows ({dict(df_eval['label'].value_counts())})")
    print(f"Loaded Real Data : {len(df_real)} rows ({dict(df_real['label'].value_counts())})")

    # Load Production Model for comparison
    prod_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib")
    prod_artifact = joblib.load(prod_path)
    prod_model = prod_artifact["model"] if isinstance(prod_artifact, dict) else prod_artifact

    # Extract Features
    print("\n--- Extracting Training Features ---")
    t0 = time.time()
    X_train_22 = extract_matrix(df_train["url"].tolist(), schema="baseline")
    X_train_30 = extract_matrix(df_train["url"].tolist(), schema="experimental")
    y_train = df_train["label"].values.astype(int)
    print(f"Train features extracted in {time.time() - t0:.2f}s: 22f shape={X_train_22.shape}, 30f shape={X_train_30.shape}")

    print("\n--- Extracting Evaluation Features ---")
    t0 = time.time()
    X_eval_22 = extract_matrix(df_eval["url"].tolist(), schema="baseline")
    X_eval_30 = extract_matrix(df_eval["url"].tolist(), schema="experimental")
    y_eval = df_eval["label"].values.astype(int)
    print(f"Eval features extracted in {time.time() - t0:.2f}s: 22f shape={X_eval_22.shape}, 30f shape={X_eval_30.shape}")

    # Model 1: Random Forest on Augmented Data with 22 Baseline Features
    print("\n--- Training Model 1: RF Augmented 22-Feature Baseline ---")
    rf_aug_22 = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    t0 = time.time()
    rf_aug_22.fit(X_train_22, y_train)
    t_train_1 = time.time() - t0
    print(f"Model 1 trained in {t_train_1:.2f}s")
    joblib.dump(
        {"model": rf_aug_22, "features": ExperimentalURLFeatureExtractor.BASELINE_FEATURE_NAMES, "schema": "baseline"},
        os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_augmented_22f.joblib")
    )

    # Model 2: Random Forest on Augmented Data with 30 Experimental Features (Regularized)
    print("\n--- Training Model 2: RF Experimental 30-Feature (Regularized) ---")
    rf_exp_30 = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_leaf=5,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    t0 = time.time()
    rf_exp_30.fit(X_train_30, y_train)
    t_train_2 = time.time() - t0
    print(f"Model 2 trained in {t_train_2:.2f}s")
    joblib.dump(
        {"model": rf_exp_30, "features": ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES, "schema": "experimental"},
        os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_experimental_30f.joblib")
    )

    # Model 3: Calibrated Random Forest (30 Features, Sigmoid Platt Scaling via 5-Fold CV)
    print("\n--- Training Model 3: Calibrated RF (30-Feature, 5-Fold CV Platt Scaling) ---")
    base_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_leaf=5,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    rf_cal_30 = CalibratedClassifierCV(estimator=base_rf, method="sigmoid", cv=5)
    t0 = time.time()
    rf_cal_30.fit(X_train_30, y_train)
    t_train_3 = time.time() - t0
    print(f"Model 3 trained in {t_train_3:.2f}s")
    joblib.dump(
        {"model": rf_cal_30, "features": ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES, "schema": "experimental"},
        os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_calibrated_30f.joblib")
    )

    print("\n=== PHASE C5: RIGOROUS EVALUATION ===")

    models_config = [
        ("Production RF (22f, unaugmented)", prod_model, "baseline", X_eval_22),
        ("Model 1: RF Augmented (22f, baseline arch)", rf_aug_22, "baseline", X_eval_22),
        ("Model 2: RF Experimental (30f, regularized)", rf_exp_30, "experimental", X_eval_30),
        ("Model 3: RF Calibrated (30f, platt scaled)", rf_cal_30, "experimental", X_eval_30),
    ]

    eval_results = {}

    for name, model, schema, X_eval in models_config:
        print(f"\nEvaluating: {name}")
        y_proba = model.predict_proba(X_eval)[:, 1]
        y_pred = (y_proba >= 0.5).astype(int)
        metrics = compute_metrics(y_eval, y_pred, y_proba)
        eval_results[name] = {"held_out_partition": metrics}
        print(f"  Accuracy: {metrics['accuracy']:.4f} | Prec: {metrics['precision']:.4f} | Rec: {metrics['recall']:.4f} | F1: {metrics['f1_score']:.4f}")
        print(f"  FPR: {metrics['false_positive_rate']:.4%}, FNR: {metrics['false_negative_rate']:.4%}, Brier: {metrics['brier_score']:.4f}")

        # Realistic complexity benchmark evaluation
        real_urls = df_real["url"].tolist()
        real_y = df_real["label"].values.astype(int)
        X_real = extract_matrix(real_urls, schema=schema)
        real_proba = model.predict_proba(X_real)[:, 1]
        real_pred = (real_proba >= 0.5).astype(int)
        real_metrics = compute_metrics(real_y, real_pred, real_proba)
        eval_results[name]["realistic_benchmark"] = real_metrics
        print(f"  Realistic Benchmark (N=38): TN={real_metrics['tn']}, FP={real_metrics['fp']}, FN={real_metrics['fn']}, TP={real_metrics['tp']}")
        print(f"    FPR: {real_metrics['false_positive_rate']:.4%}, Phishing Recall: {real_metrics['recall']:.4%}")

        # Slice 1: Legitimate with query parameters in evaluation set
        legit_with_query_mask = (y_eval == 0) & (df_eval["url"].str.contains(r"\?", regex=True))
        if legit_with_query_mask.sum() > 0:
            slice_urls = df_eval[legit_with_query_mask]["url"].tolist()
            slice_y = y_eval[legit_with_query_mask]
            slice_res = evaluate_slice(model, slice_urls, slice_y, schema=schema)
            eval_results[name]["legit_with_query"] = slice_res
            print(f"  Slice [Legit with Query Params] (N={len(slice_urls)}): FP={slice_res['fp']}, TN={slice_res['tn']}, FPR={slice_res['false_positive_rate']:.4%}")

        # Slice 2: Phishing with simple structure (no query params, clean paths)
        phish_simple_mask = (y_eval == 1) & (~df_eval["url"].str.contains(r"\?", regex=True)) & (df_eval["url"].str.count("/") <= 4)
        if phish_simple_mask.sum() > 0:
            slice_urls = df_eval[phish_simple_mask]["url"].tolist()
            slice_y = y_eval[phish_simple_mask]
            slice_res = evaluate_slice(model, slice_urls, slice_y, schema=schema)
            eval_results[name]["phish_simple_structure"] = slice_res
            print(f"  Slice [Simple Phishing Paths] (N={len(slice_urls)}): TP={slice_res['tp']}, FN={slice_res['fn']}, Recall={slice_res['recall']:.4%}")

    print("\n=== PHASE C6: INVESTIGATING THE TARGET YOUTUBE URL ===")
    ext = ExperimentalURLFeatureExtractor()
    yt_vec_22 = np.array([ext.extract_vector(TARGET_YOUTUBE_URL, schema="baseline")], dtype=np.float32)
    yt_vec_30 = np.array([ext.extract_vector(TARGET_YOUTUBE_URL, schema="experimental")], dtype=np.float32)

    yt_results = {}
    for name, model, schema, _ in models_config:
        vec = yt_vec_22 if schema == "baseline" else yt_vec_30
        proba = model.predict_proba(vec)[0]
        pred_label = int(proba[1] >= 0.5)
        yt_results[name] = {
            "p_legitimate": float(proba[0]),
            "p_phishing": float(proba[1]),
            "prediction": "phishing" if pred_label == 1 else "legitimate",
            "is_correct": bool(pred_label == 0)
        }
        print(f"  {name}:")
        print(f"    P(Phishing): {proba[1]:.4%}, P(Legitimate): {proba[0]:.4%} -> Classified as: {yt_results[name]['prediction']} (Correct: {yt_results[name]['is_correct']})")

    # Save comprehensive results
    output_meta = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "random_seed": RANDOM_SEED,
        "n_train": len(df_train),
        "n_eval": len(df_eval),
        "target_youtube_url": TARGET_YOUTUBE_URL,
        "target_youtube_evaluation": yt_results,
        "model_evaluations": eval_results
    }
    meta_path = os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "phase_c_evaluation_results.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(output_meta, f, indent=2)

    print(f"\nAll experimental results successfully saved to: {meta_path}")


if __name__ == "__main__":
    main()
