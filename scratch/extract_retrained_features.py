"""PhishGuardAI - Feature Extractor for Retrained Corpus
Extracts 30-feature matrices for train, val, and holdout splits using ExperimentalURLFeatureExtractor.
"""

import os
import sys
import time
import pandas as pd
import numpy as np

PROJECT_ROOT = os.path.abspath(".")
sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "retrained")
extractor = ExperimentalURLFeatureExtractor()
feature_names = ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES

for split in ["train", "val", "holdout"]:
    csv_path = os.path.join(DATA_DIR, f"{split}.csv")
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path)
    
    t0 = time.time()
    feature_rows = []
    for idx, u in enumerate(df["url"]):
        row_dict = extractor.extract_experimental_features(u)
        feature_rows.append([row_dict[fn] for fn in feature_names])
        if (idx + 1) % 5000 == 0:
            print(f"  [{split}] Extracted {idx + 1}/{len(df)} URLs...")
            
    X = pd.DataFrame(feature_rows, columns=feature_names)
    y = df["label"].copy()
    
    # Validation checks
    assert not X.isna().any().any(), f"NaN found in {split} features"
    assert not np.isinf(X.values).any(), f"Inf found in {split} features"
    assert len(X) == len(y), "Length mismatch"
    
    X_path = os.path.join(DATA_DIR, f"X_{split}_30f.csv")
    y_path = os.path.join(DATA_DIR, f"y_{split}.csv")
    
    X.to_csv(X_path, index=False)
    y.to_csv(y_path, index=False)
    elapsed = time.time() - t0
    print(f"Finished {split} in {elapsed:.2f}s -> {X_path} ({X.shape})")

print("All features extracted successfully!")
