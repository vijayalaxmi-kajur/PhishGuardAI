"""PhishGuardAI — Domain-Aware Validation & Generalization Analysis

Implements independent model validation using domain-held-out evaluation.
Ensures zero domain overlap between training and testing partitions,
evaluating how the 22-feature Random Forest generalizes to completely
unseen domains without modifying production models or datasets.
"""

import os
import sys
import json
import datetime
from typing import Tuple, Dict, Any, Optional, List

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
    roc_curve,
    precision_recall_curve
)
from sklearn.calibration import calibration_curve
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Project Root resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extraction import URLFeatureExtractor


FEATURE_NAMES = URLFeatureExtractor.FEATURE_NAMES
DEFAULT_DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "Dataset.csv")
DEFAULT_EXPERIMENT_DIR = os.path.join(PROJECT_ROOT, "models", "experiments")
DEFAULT_FIGURES_DIR = os.path.join(PROJECT_ROOT, "reports", "figures")


def create_domain_aware_split(
    dataset_path: Optional[str] = None,
    random_state: int = 42,
    n_splits: int = 5
) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, Dict[str, Any]]:
    """Partition the dataset by registered domain to prevent domain leakage.
    
    Uses StratifiedGroupKFold to group all URLs belonging to the same domain together
    while preserving the authentic ~14.4% phishing / ~85.6% legitimate class ratio.
    
    Args:
        dataset_path: Path to dataset CSV. Defaults to dataset/Dataset.csv.
        random_state: Random seed for deterministic reproducibility.
        n_splits: Number of folds (default 5 for 80% train / 20% test).
        
    Returns:
        Tuple of (X_train, y_train, X_test, y_test, split_metadata_dict).
        
    Raises:
        FileNotFoundError: If dataset does not exist.
        ValueError: If grouping fails or domain overlap is detected.
    """
    if dataset_path is None:
        dataset_path = DEFAULT_DATASET_PATH

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Target dataset not found at {dataset_path}")

    df_raw = pd.read_csv(dataset_path)

    # Deterministic deduplication matching production preprocessing
    df = df_raw.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)

    if "dom" not in df.columns:
        raise ValueError("Dataset lacks 'dom' column required for domain-level grouping.")
    if "label" not in df.columns:
        raise ValueError("Dataset lacks 'label' target column.")

    # Validate all 22 features exist
    for f in FEATURE_NAMES:
        if f not in df.columns:
            raise ValueError(f"Required feature '{f}' missing from dataset.")

    # StratifiedGroupKFold partitioning
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    train_idx, test_idx = next(sgkf.split(df, df["label"], groups=df["dom"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    test_df = df.iloc[test_idx].copy().reset_index(drop=True)

    X_train = train_df[FEATURE_NAMES]
    y_train = train_df["label"].astype(int)
    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["label"].astype(int)

    train_domains = set(train_df["dom"].astype(str))
    test_domains = set(test_df["dom"].astype(str))
    overlap = train_domains.intersection(test_domains)

    if len(overlap) > 0:
        raise ValueError(f"Domain leakage detected: {len(overlap)} shared domains between train and test.")

    # Calculate statistics
    total_samples = len(df)
    train_samples = len(train_df)
    test_samples = len(test_df)

    train_phish = int((y_train == 1).sum())
    train_legit = int((y_train == 0).sum())
    test_phish = int((y_test == 1).sum())
    test_legit = int((y_test == 0).sum())

    metadata = {
        "random_state": random_state,
        "n_splits": n_splits,
        "split_ratio": f"{round(train_samples/total_samples*100, 2)}% Train / {round(test_samples/total_samples*100, 2)}% Test",
        "total_clean_samples": total_samples,
        "train_samples": train_samples,
        "test_samples": test_samples,
        "total_unique_domains": df["dom"].nunique(),
        "train_domains_count": len(train_domains),
        "test_domains_count": len(test_domains),
        "domain_overlap_count": len(overlap),
        "train_phishing_count": train_phish,
        "train_phishing_pct": round(train_phish / train_samples * 100, 2),
        "train_legitimate_count": train_legit,
        "train_legitimate_pct": round(train_legit / train_samples * 100, 2),
        "test_phishing_count": test_phish,
        "test_phishing_pct": round(test_phish / test_samples * 100, 2),
        "test_legitimate_count": test_legit,
        "test_legitimate_pct": round(test_legit / test_samples * 100, 2),
        "feature_names": FEATURE_NAMES
    }

    return X_train, y_train, X_test, y_test, metadata


def train_domain_experimental_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    random_state: int = 42,
    n_estimators: int = 100
) -> RandomForestClassifier:
    """Train experimental Random Forest on domain-held-out training partition.
    
    Args:
        X_train: Feature matrix.
        y_train: Labels.
        random_state: Seed for reproducibility.
        n_estimators: Number of decision trees.
        
    Returns:
        Fitted RandomForestClassifier.
    """
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    return model


def evaluate_model_on_domain_split(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series
) -> Dict[str, Any]:
    """Rigorously evaluate a model on the domain-held-out evaluation partition.
    
    Args:
        model: Trained classifier with predict and predict_proba.
        X_test: Unseen test feature matrix.
        y_test: Ground truth test labels.
        
    Returns:
        Dictionary of comprehensive evaluation metrics.
    """
    y_pred = model.predict(X_test)

    # Determine class 1 index safely
    classes_list = list(model.classes_)
    phish_idx = classes_list.index(1) if 1 in classes_list else 1
    probabilities = model.predict_proba(X_test)
    y_prob = probabilities[:, phish_idx]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1_phish = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    roc_auc = float(roc_auc_score(y_test, y_prob))
    pr_auc = float(average_precision_score(y_test, y_prob))
    brier = float(brier_score_loss(y_test, y_prob))

    # Calibration curve calculation (10 uniform probability bins)
    prob_true, prob_pred = calibration_curve(y_test, y_prob, n_bins=10, strategy="uniform")
    calibration_bins = [
        {
            "bin_index": idx + 1,
            "mean_predicted_prob": round(float(p), 4),
            "fraction_of_positives": round(float(t), 4)
        }
        for idx, (t, p) in enumerate(zip(prob_true, prob_pred))
    ]

    return {
        "accuracy": round(acc, 4),
        "phishing_precision": round(prec, 4),
        "phishing_recall": round(rec, 4),
        "phishing_f1": round(f1_phish, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score": round(brier, 4),
        "calibration_bins": calibration_bins,
        "sample_size": len(y_test),
        "evaluation_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


def save_experimental_artifacts(
    model: RandomForestClassifier,
    split_metadata: Dict[str, Any],
    eval_metrics: Dict[str, Any],
    X_test: pd.DataFrame,
    y_test: pd.Series,
    output_dir: Optional[str] = None,
    figures_dir: Optional[str] = None
) -> Dict[str, str]:
    """Persist the experimental model, experiment metadata, and plots.
    
    Guarantees that production models (models/phishing_model.joblib) are NEVER overwritten.
    
    Args:
        model: Fitted experimental Random Forest.
        split_metadata: Domain split parameter metadata.
        eval_metrics: Computed evaluation metrics.
        X_test: Test features for plotting.
        y_test: Test ground truth labels for plotting.
        output_dir: Destination folder for experimental model.
        figures_dir: Destination folder for evaluation figures.
        
    Returns:
        Dictionary of created file paths.
    """
    if output_dir is None:
        output_dir = DEFAULT_EXPERIMENT_DIR
    if figures_dir is None:
        figures_dir = DEFAULT_FIGURES_DIR

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(figures_dir, exist_ok=True)

    # 1. Save Experimental Model Artifact (Dictionary Wrapper)
    model_path = os.path.join(output_dir, "domain_heldout_random_forest.joblib")
    artifact = {
        "model": model,
        "model_name": "Domain-Held-Out Random Forest (Experimental)",
        "feature_names": FEATURE_NAMES,
        "classes": [int(c) for c in model.classes_],
        "phishing_class_index": list(model.classes_).index(1),
        "n_features": len(FEATURE_NAMES),
        "split_type": "domain_held_out",
        "metrics": eval_metrics
    }
    joblib.dump(artifact, model_path)

    # 2. Save Experiment Metadata JSON
    metadata_path = os.path.join(output_dir, "domain_experiment_metadata.json")
    full_metadata = {
        "experiment_name": "Phase 8: Domain Generalization Analysis",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "split_metadata": split_metadata,
        "evaluation_metrics": eval_metrics,
        "model_configuration": {
            "n_estimators": model.n_estimators,
            "class_weight": model.class_weight,
            "random_state": model.random_state
        }
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(full_metadata, f, indent=2)

    # 3. Generate Visualizations
    cm_path = os.path.join(figures_dir, "domain_generalization_confusion_matrix.png")
    roc_pr_path = os.path.join(figures_dir, "domain_generalization_roc_pr_curves.png")
    calib_path = os.path.join(figures_dir, "domain_generalization_calibration_curve.png")

    cm_data = eval_metrics["confusion_matrix"]
    cm_array = np.array([
        [cm_data["true_negatives"], cm_data["false_positives"]],
        [cm_data["false_negatives"], cm_data["true_positives"]]
    ])

    # Plot A: Confusion Matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(cm_array, cmap=plt.cm.Blues, alpha=0.85)
    for i in range(2):
        for j in range(2):
            val = cm_array[i, j]
            ax.text(x=j, y=i, s=f"{val:,}", va="center", ha="center", fontsize=14, fontweight="bold")
    fig.colorbar(cax)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Legitimate (0)", "Phishing (1)"], fontsize=10)
    ax.set_yticklabels(["Legitimate (0)", "Phishing (1)"], fontsize=10)
    ax.set_xlabel("Predicted Label", fontsize=11, fontweight="bold", labelpad=10)
    ax.set_ylabel("True Label", fontsize=11, fontweight="bold")
    ax.set_title("Domain-Held-Out Evaluation Confusion Matrix", fontsize=12, fontweight="bold", pad=20)
    plt.tight_layout()
    fig.savefig(cm_path, dpi=200)
    plt.close(fig)

    # Plot B: ROC & PR Curves
    phish_idx = list(model.classes_).index(1)
    y_prob = model.predict_proba(X_test)[:, phish_idx]
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    precision_vals, recall_vals, _ = precision_recall_curve(y_test, y_prob)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    # ROC
    ax1.plot(fpr, tpr, color="#2563eb", lw=2, label=f"ROC Curve (AUC = {eval_metrics['roc_auc']:.4f})")
    ax1.plot([0, 1], [0, 1], color="#94a3b8", linestyle="--", label="Random Classifier")
    ax1.set_xlim([0.0, 1.0])
    ax1.set_ylim([0.0, 1.02])
    ax1.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=10)
    ax1.set_ylabel("True Positive Rate (Recall)", fontsize=10)
    ax1.set_title("ROC Curve (Unseen Domains)", fontsize=11, fontweight="bold")
    ax1.legend(loc="lower right")
    ax1.grid(True, linestyle=":", alpha=0.6)

    # PR Curve
    base_rate = (y_test == 1).mean()
    ax2.plot(recall_vals, precision_vals, color="#10b981", lw=2, label=f"PR Curve (AUC = {eval_metrics['pr_auc']:.4f})")
    ax2.axhline(y=base_rate, color="#94a3b8", linestyle="--", label=f"Base Rate ({base_rate*100:.1f}%)")
    ax2.set_xlim([0.0, 1.0])
    ax2.set_ylim([0.0, 1.02])
    ax2.set_xlabel("Recall", fontsize=10)
    ax2.set_ylabel("Precision", fontsize=10)
    ax2.set_title("Precision-Recall Curve (Unseen Domains)", fontsize=11, fontweight="bold")
    ax2.legend(loc="lower left")
    ax2.grid(True, linestyle=":", alpha=0.6)

    plt.tight_layout()
    fig.savefig(roc_pr_path, dpi=200)
    plt.close(fig)

    # Plot C: Calibration Reliability Curve
    prob_true, prob_pred = calibration_curve(y_test, y_prob, n_bins=10, strategy="uniform")
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot([0, 1], [0, 1], linestyle="--", color="#94a3b8", label="Perfect Calibration")
    ax.plot(prob_pred, prob_true, marker="o", color="#ef4444", lw=2, label=f"Random Forest (Brier = {eval_metrics['brier_score']:.4f})")
    ax.set_xlabel("Mean Predicted Probability", fontsize=10, fontweight="bold")
    ax.set_ylabel("Fraction of Positive (Phishing) Cases", fontsize=10, fontweight="bold")
    ax.set_title("Probability Calibration Reliability Diagram", fontsize=11, fontweight="bold")
    ax.legend(loc="upper left")
    ax.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    fig.savefig(calib_path, dpi=200)
    plt.close(fig)

    return {
        "model_artifact": model_path,
        "metadata_json": metadata_path,
        "confusion_matrix_plot": cm_path,
        "roc_pr_plot": roc_pr_path,
        "calibration_plot": calib_path
    }


def run_pipeline() -> Dict[str, Any]:
    """Execute complete Phase 8 domain generalization experiment."""
    print("=" * 78)
    print("      PHISHGUARDAI — DOMAIN GENERALIZATION & VALIDATION PIPELINE     ")
    print("=" * 78)

    print("\n[1] GENERATING DOMAIN-AWARE STRATIFIED SPLIT...")
    X_train, y_train, X_test, y_test, split_meta = create_domain_aware_split()
    print(f"    - Clean Total Samples : {split_meta['total_clean_samples']:,}")
    print(f"    - Unique Domains Total: {split_meta['total_unique_domains']:,}")
    print(f"    - Training Partition  : {split_meta['train_samples']:,} samples ({split_meta['train_domains_count']:,} domains)")
    print(f"      * Legitimate (0)    : {split_meta['train_legitimate_count']:,} ({split_meta['train_legitimate_pct']}%)")
    print(f"      * Phishing (1)      : {split_meta['train_phishing_count']:,} ({split_meta['train_phishing_pct']}%)")
    print(f"    - Evaluation Partition: {split_meta['test_samples']:,} samples ({split_meta['test_domains_count']:,} domains)")
    print(f"      * Legitimate (0)    : {split_meta['test_legitimate_count']:,} ({split_meta['test_legitimate_pct']}%)")
    print(f"      * Phishing (1)      : {split_meta['test_phishing_count']:,} ({split_meta['test_phishing_pct']}%)")
    print(f"    - Domain Overlap      : {split_meta['domain_overlap_count']} (Confirmed Zero Overlap)")

    print("\n[2] TRAINING EXPERIMENTAL RANDOM FOREST CLASSIFIER...")
    model = train_domain_experimental_model(X_train, y_train)
    print(f"    - Estimators: {model.n_estimators}")
    print(f"    - Class Weight: {model.class_weight}")
    print(f"    - Features Evaluated: {len(FEATURE_NAMES)}")

    print("\n[3] EVALUATING ON COMPLETELY UNSEEN DOMAINS...")
    eval_metrics = evaluate_model_on_domain_split(model, X_test, y_test)
    print(f"    - Accuracy          : {eval_metrics['accuracy']*100:.2f}%")
    print(f"    - Phishing Precision: {eval_metrics['phishing_precision']*100:.2f}%")
    print(f"    - Phishing Recall   : {eval_metrics['phishing_recall']*100:.2f}%")
    print(f"    - Phishing F1-Score : {eval_metrics['phishing_f1']*100:.2f}%")
    print(f"    - Macro F1-Score    : {eval_metrics['macro_f1']*100:.2f}%")
    print(f"    - Weighted F1-Score : {eval_metrics['weighted_f1']*100:.2f}%")
    print(f"    - ROC-AUC           : {eval_metrics['roc_auc']:.4f}")
    print(f"    - PR-AUC (Avg Prec) : {eval_metrics['pr_auc']:.4f}")
    print(f"    - Brier Score Loss  : {eval_metrics['brier_score']:.4f}")
    cm = eval_metrics["confusion_matrix"]
    print(f"    - Confusion Matrix  : TN={cm['true_negatives']:,}, FP={cm['false_positives']:,}, FN={cm['false_negatives']:,}, TP={cm['true_positives']:,}")

    print("\n[4] PERSISTING EXPERIMENTAL ARTIFACTS...")
    saved_paths = save_experimental_artifacts(model, split_meta, eval_metrics, X_test, y_test)
    for name, p in saved_paths.items():
        print(f"    - {name}: {p}")

    print("\n[5] AUDITING PRODUCTION MODEL AGAINST EXPERIMENT...")
    prod_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib")
    if os.path.exists(prod_path):
        prod_art = joblib.load(prod_path)
        prod_m = prod_art["model"] if isinstance(prod_art, dict) else prod_art
        prod_eval = evaluate_model_on_domain_split(prod_m, X_test, y_test)
        print(f"    - Production Model on Unseen Domains:")
        print(f"      * Accuracy : {prod_eval['accuracy']*100:.2f}%")
        print(f"      * Precision: {prod_eval['phishing_precision']*100:.2f}%")
        print(f"      * Recall   : {prod_eval['phishing_recall']*100:.2f}%")
        print(f"      * F1-Score : {prod_eval['phishing_f1']*100:.2f}%")

    print("\n" + "=" * 78)
    print("      DOMAIN GENERALIZATION EXPERIMENT COMPLETED SUCCESSFULLY        ")
    print("=" * 78)

    return {
        "split_metadata": split_meta,
        "eval_metrics": eval_metrics,
        "saved_paths": saved_paths
    }


if __name__ == "__main__":
    run_pipeline()
