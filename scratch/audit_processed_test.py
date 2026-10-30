import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.abspath("."))
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

ext = ExperimentalURLFeatureExtractor()

df_test = pd.read_csv("data/processed/test.csv")
print(f"Loaded original processed test.csv: {len(df_test)} rows")
print("Columns:", list(df_test.columns[:5]))

y_test = df_test["label"].values.astype(int)

# In test.csv, the 22 features are already computed!
from src.preprocess import DataPreprocessor
feature_cols = DataPreprocessor.FEATURE_NAMES

X_test_22 = df_test[feature_cols].values.astype(np.float32)

prod_m = joblib.load("models/phishing_model.joblib")["model"]
c1_m = joblib.load("models/experiments/stage1/rf_baseline_22f.joblib")["model"]
c2_m = joblib.load("models/experiments/stage1/rf_regularized_22f.joblib")["model"]

print("\n=== EVALUATION ON ORIGINAL PROCESSED TEST SET (N=23,047) ===")
for name, m in [("Production RF", prod_m), ("Candidate 1 (22f Base)", c1_m), ("Candidate 2 (22f Reg)", c2_m)]:
    p = m.predict_proba(X_test_22)[:, 1]
    y_pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)
    print(f"{name:<25}: Acc={acc:.4f} | Prec={prec:.4f} | Rec={rec:.4f} | F1={f1:.4f} | FPR={fpr:.4%} | FNR={fnr:.4%}")
