"""
PhishGuardAI - Phase 13C-2 Pre-Training Dataset & Feature Audit
Validates all pre-conditions before any model training:
1. Row counts & dimensional alignment across features and targets
2. Absence of NaNs, Infs, nulls, or non-numeric types
3. Verification of feature names and schema ordering
4. Partition isolation & zero leakage (URL, domain, benchmark)
5. Class balance and label distributions
"""

import os
import sys
import json
import pandas as pd
import numpy as np

PROJECT_ROOT = r"c:\Users\yalla\OneDrive\Desktop\PhishGuardAI"
SPLITS_DIR = os.path.join(PROJECT_ROOT, "data", "phase13c", "splits")
BENCH_PATH = os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extraction import URLFeatureExtractor
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

print("Starting Pre-Training Integrity Audit...")

# 1. Load Partitions and Targets
train_df = pd.read_csv(os.path.join(SPLITS_DIR, "train.csv"))
val_df = pd.read_csv(os.path.join(SPLITS_DIR, "val.csv"))
test_df = pd.read_csv(os.path.join(SPLITS_DIR, "test.csv"))

y_train = pd.read_csv(os.path.join(SPLITS_DIR, "y_train.csv")).squeeze()
y_val = pd.read_csv(os.path.join(SPLITS_DIR, "y_val.csv")).squeeze()
y_test = pd.read_csv(os.path.join(SPLITS_DIR, "y_test.csv")).squeeze()

# Load Feature Matrices
X_train_22 = pd.read_csv(os.path.join(SPLITS_DIR, "X_train_22f.csv"))
X_val_22 = pd.read_csv(os.path.join(SPLITS_DIR, "X_val_22f.csv"))
X_test_22 = pd.read_csv(os.path.join(SPLITS_DIR, "X_test_22f.csv"))

X_train_30 = pd.read_csv(os.path.join(SPLITS_DIR, "X_train_30f.csv"))
X_val_30 = pd.read_csv(os.path.join(SPLITS_DIR, "X_val_30f.csv"))
X_test_30 = pd.read_csv(os.path.join(SPLITS_DIR, "X_test_30f.csv"))

audit_results = {}

# Check Row Count Alignment
row_counts = {
    "train": {"metadata": len(train_df), "y": len(y_train), "X_22": len(X_train_22), "X_30": len(X_train_30)},
    "val": {"metadata": len(val_df), "y": len(y_val), "X_22": len(X_val_22), "X_30": len(X_val_30)},
    "test": {"metadata": len(test_df), "y": len(y_test), "X_22": len(X_test_22), "X_30": len(X_test_30)}
}
audit_results["row_counts"] = row_counts
for split, counts in row_counts.items():
    assert counts["metadata"] == counts["y"] == counts["X_22"] == counts["X_30"], f"Row count mismatch in {split}!"

print("Row count alignment: PASSED across all splits.")

# Check Columns & Schemas
expected_22 = URLFeatureExtractor.FEATURE_NAMES
expected_30 = ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES

assert list(X_train_22.columns) == expected_22, "X_train_22 column mismatch!"
assert list(X_val_22.columns) == expected_22, "X_val_22 column mismatch!"
assert list(X_test_22.columns) == expected_22, "X_test_22 column mismatch!"

assert list(X_train_30.columns) == expected_30, "X_train_30 column mismatch!"
assert list(X_val_30.columns) == expected_30, "X_val_30 column mismatch!"
assert list(X_test_30.columns) == expected_30, "X_test_30 column mismatch!"

print("Feature schemas & column ordering: PASSED (22f and 30f match exact specifications).")

# Check NaNs, Infs, Non-numeric types
def check_data_cleanliness(df: pd.DataFrame, name: str):
    null_cnt = df.isnull().sum().sum()
    inf_cnt = np.isinf(df.to_numpy()).sum()
    non_num = [c for c in df.columns if not np.issubdtype(df[c].dtype, np.number)]
    return {"nulls": int(null_cnt), "infs": int(inf_cnt), "non_numeric_cols": non_num}

cleanliness = {
    "X_train_22": check_data_cleanliness(X_train_22, "X_train_22"),
    "X_val_22": check_data_cleanliness(X_val_22, "X_val_22"),
    "X_test_22": check_data_cleanliness(X_test_22, "X_test_22"),
    "X_train_30": check_data_cleanliness(X_train_30, "X_train_30"),
    "X_val_30": check_data_cleanliness(X_val_30, "X_val_30"),
    "X_test_30": check_data_cleanliness(X_test_30, "X_test_30"),
}
audit_results["cleanliness"] = cleanliness
for k, v in cleanliness.items():
    assert v["nulls"] == 0 and v["infs"] == 0 and len(v["non_numeric_cols"]) == 0, f"Cleanliness failed on {k}!"

print("Data cleanliness (NaNs, Infs, non-numeric): PASSED (Zero defects).")

# Check Target Class Alignment
for split, df, y in [("train", train_df, y_train), ("val", val_df, y_val), ("test", test_df, y_test)]:
    assert (df["label"].values == y.values).all(), f"Target label misalignment in {split}!"

print("Target vector alignment: PASSED (y vectors perfectly match metadata labels).")

# Check Overlap & Leakage
train_urls = set(train_df["url"])
val_urls = set(val_df["url"])
test_urls = set(test_df["url"])

train_groups = set(train_df["split_group_key"])
val_groups = set(val_df["split_group_key"])
test_groups = set(test_df["split_group_key"])

bench_df = pd.read_csv(BENCH_PATH)
bench_urls = set(bench_df["url"])
bench_domains = set()
import tldextract
ext = tldextract.TLDExtract(suffix_list_urls=None)
for u in bench_df["url"]:
    res = ext(u)
    if res.suffix:
        bench_domains.add(f"{res.domain}.{res.suffix}".lower())

leakage = {
    "url_overlap": {
        "train_val": len(train_urls.intersection(val_urls)),
        "train_test": len(train_urls.intersection(test_urls)),
        "val_test": len(val_urls.intersection(test_urls)),
    },
    "group_overlap": {
        "train_val": len(train_groups.intersection(val_groups)),
        "train_test": len(train_groups.intersection(test_groups)),
        "val_test": len(val_groups.intersection(test_groups)),
    },
    "benchmark_leakage": {
        "train_url_match": len(train_urls.intersection(bench_urls)),
        "val_url_match": len(val_urls.intersection(bench_urls)),
        "test_url_match": len(test_urls.intersection(bench_urls)),
        "train_domain_match": len(set(train_df["registered_domain"]).intersection(bench_domains)),
        "val_domain_match": len(set(val_df["registered_domain"]).intersection(bench_domains)),
        "test_domain_match": len(set(test_df["registered_domain"]).intersection(bench_domains)),
    }
}
audit_results["leakage"] = leakage

assert leakage["url_overlap"]["train_val"] == 0
assert leakage["url_overlap"]["train_test"] == 0
assert leakage["url_overlap"]["val_test"] == 0
assert leakage["group_overlap"]["train_val"] == 0
assert leakage["group_overlap"]["train_test"] == 0
assert leakage["group_overlap"]["val_test"] == 0
assert leakage["benchmark_leakage"]["train_domain_match"] == 0
assert leakage["benchmark_leakage"]["val_domain_match"] == 0
assert leakage["benchmark_leakage"]["test_domain_match"] == 0

print("Leakage verification: PASSED (Zero URL overlap, zero domain group overlap, zero benchmark exposure).")

# Class Distributions
audit_results["distributions"] = {
    "train": {"total": len(y_train), "c0": int((y_train == 0).sum()), "c1": int((y_train == 1).sum()), "c1_pct": float((y_train == 1).mean() * 100)},
    "val": {"total": len(y_val), "c0": int((y_val == 0).sum()), "c1": int((y_val == 1).sum()), "c1_pct": float((y_val == 1).mean() * 100)},
    "test": {"total": len(y_test), "c0": int((y_test == 0).sum()), "c1": int((y_test == 1).sum()), "c1_pct": float((y_test == 1).mean() * 100)},
}

output_audit_path = os.path.join(PROJECT_ROOT, "reports", "phase13", "phase13c2", "pre_training_audit.json")
os.makedirs(os.path.dirname(output_audit_path), exist_ok=True)
with open(output_audit_path, "w") as f:
    json.dump(audit_results, f, indent=2)

print(f"Pre-training integrity audit completed successfully -> {output_audit_path}")
