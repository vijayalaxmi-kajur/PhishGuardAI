"""
Extract 30-feature matrices for Phase 15C train, val, and holdout splits.
"""
import os
import sys
sys.path.insert(0, os.path.abspath("."))
import time
import pandas as pd
import numpy as np
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

DATA_DIR = "data/phase15c"
extractor = ExperimentalURLFeatureExtractor()
feature_names = extractor.EXPERIMENTAL_FEATURE_NAMES

print(f"Extracting 30-feature schema ({len(feature_names)} features):")
print(feature_names)

for split in ["train", "val", "holdout"]:
    csv_path = os.path.join(DATA_DIR, f"{split}.csv")
    df = pd.read_csv(csv_path)
    urls = df["url"].tolist()
    y = df["label"].values.astype(int)
    
    print(f"\nExtracting features for {split} ({len(urls)} samples)...")
    t0 = time.time()
    
    # Batch extraction
    matrix = np.array([extractor.extract_vector(u, schema="experimental") for u in urls], dtype=np.float32)
    elapsed = time.time() - t0
    print(f"Extracted in {elapsed:.2f}s ({len(urls)/elapsed:.1f} URLs/sec). Shape: {matrix.shape}")
    
    # Save feature matrix and labels
    df_feat = pd.DataFrame(matrix, columns=feature_names)
    df_feat.to_csv(os.path.join(DATA_DIR, f"X_{split}_30f.csv"), index=False)
    pd.DataFrame({"label": y}).to_csv(os.path.join(DATA_DIR, f"y_{split}.csv"), index=False)

print("\nFeature extraction complete for all Phase 15C partitions!")
