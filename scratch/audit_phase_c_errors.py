import os
import sys
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath("."))
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

ext = ExperimentalURLFeatureExtractor()

df_real = pd.read_csv("data/realistic_evaluation_set.csv")
y_real = df_real["label"].values.astype(int)

X22 = np.array([ext.extract_vector(u, "baseline") for u in df_real["url"]], dtype=np.float32)
X30 = np.array([ext.extract_vector(u, "experimental") for u in df_real["url"]], dtype=np.float32)

prod_m = joblib.load("models/phishing_model.joblib")["model"]
c1_m = joblib.load("models/experiments/stage1/rf_baseline_22f.joblib")["model"]
c2_m = joblib.load("models/experiments/stage1/rf_regularized_22f.joblib")["model"]
c3_m = joblib.load("models/experiments/stage1/rf_experimental_30f.joblib")["model"]
c4_m = joblib.load("models/experiments/stage1/rf_calibrated_30f.joblib")["model"]

p_prod = prod_m.predict_proba(X22)[:, 1]
p_c1 = c1_m.predict_proba(X22)[:, 1]
p_c2 = c2_m.predict_proba(X22)[:, 1]
p_c3 = c3_m.predict_proba(X30)[:, 1]
p_c4 = c4_m.predict_proba(X30)[:, 1]

df_real["prob_prod"] = p_prod
df_real["prob_c1"] = p_c1
df_real["prob_c2"] = p_c2
df_real["prob_c3"] = p_c3
df_real["prob_c4"] = p_c4

df_real["pred_prod"] = (p_prod >= 0.5).astype(int)
df_real["pred_c1"] = (p_c1 >= 0.5).astype(int)
df_real["pred_c2"] = (p_c2 >= 0.5).astype(int)
df_real["pred_c3"] = (p_c3 >= 0.5).astype(int)
df_real["pred_c4"] = (p_c4 >= 0.5).astype(int)

print("==================================================================")
print("            REALISTIC BENCHMARK COMPLETE ERROR ANALYSIS           ")
print("==================================================================")

print("\n--- FALSE POSITIVES (Ground Truth Label = 0, Predicted = 1) ---")
fps = df_real[(df_real["label"] == 0) & ((df_real["pred_prod"] == 1) | (df_real["pred_c1"] == 1) | (df_real["pred_c3"] == 1))]
for idx, row in fps.iterrows():
    u = row["url"]
    vec22 = ext.extract_vector(u, "baseline")
    vec30 = ext.extract_vector(u, "experimental")
    print(f"\nURL: {u}")
    print(f"  Category: {row['category']} | Status: {row['verification_status']}")
    print(f"  Probs: Prod={row['prob_prod']:.2f}, C1={row['prob_c1']:.2f}, C2={row['prob_c2']:.2f}, C3={row['prob_c3']:.2f}, C4={row['prob_c4']:.2f}")
    print(f"  Preds: Prod={row['pred_prod']}, C1={row['pred_c1']}, C2={row['pred_c2']}, C3={row['pred_c3']}, C4={row['pred_c4']}")
    print(f"  Key Features (22f): len={vec22[0]:.0f}, dom_len={vec22[1]:.0f}, entropy={vec22[19]:.2f}, path_len={vec22[20]:.0f}, query_len={vec22[21]:.0f}, is_https={vec22[17]:.0f}, digits={vec22[6]:.0f}")

print("\n--- FALSE NEGATIVES (Ground Truth Label = 1, Predicted = 0) ---")
fns = df_real[(df_real["label"] == 1) & ((df_real["pred_prod"] == 0) | (df_real["pred_c1"] == 0) | (df_real["pred_c3"] == 0))]
for idx, row in fns.iterrows():
    u = row["url"]
    vec22 = ext.extract_vector(u, "baseline")
    vec30 = ext.extract_vector(u, "experimental")
    print(f"\nURL: {u}")
    print(f"  Category: {row['category']} | Status: {row['verification_status']}")
    print(f"  Probs: Prod={row['prob_prod']:.2f}, C1={row['prob_c1']:.2f}, C2={row['prob_c2']:.2f}, C3={row['prob_c3']:.2f}, C4={row['prob_c4']:.2f}")
    print(f"  Preds: Prod={row['pred_prod']}, C1={row['pred_c1']}, C2={row['pred_c2']}, C3={row['pred_c3']}, C4={row['pred_c4']}")
    print(f"  Key Features (22f): len={vec22[0]:.0f}, dom_len={vec22[1]:.0f}, entropy={vec22[19]:.2f}, path_len={vec22[20]:.0f}, query_len={vec22[21]:.0f}, is_https={vec22[17]:.0f}, digits={vec22[6]:.0f}")
