import os
import sys
import pandas as pd
import joblib
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

df_real = pd.read_csv(os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv"))
ext = ExperimentalURLFeatureExtractor()

prod_art = joblib.load(os.path.join(PROJECT_ROOT, "models", "phishing_model.joblib"))
prod_model = prod_art["model"] if isinstance(prod_art, dict) else prod_art
m1_art = joblib.load(os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_augmented_22f.joblib"))
m1_model = m1_art["model"]
m2_art = joblib.load(os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_experimental_30f.joblib"))
m2_model = m2_art["model"]
m3_art = joblib.load(os.path.join(PROJECT_ROOT, "models", "experiments", "phase_c", "rf_calibrated_30f.joblib"))
m3_model = m3_art["model"]

X_22 = np.array([ext.extract_vector(u, "baseline") for u in df_real["url"]])
X_30 = np.array([ext.extract_vector(u, "experimental") for u in df_real["url"]])

p_prod = prod_model.predict_proba(X_22)[:, 1]
p_m1 = m1_model.predict_proba(X_22)[:, 1]
p_m2 = m2_model.predict_proba(X_30)[:, 1]
p_m3 = m3_model.predict_proba(X_30)[:, 1]

df_real["prod_p"] = p_prod
df_real["m1_p"] = p_m1
df_real["m2_p"] = p_m2
df_real["m3_p"] = p_m3

print(f"{'TYPE':<7} | {'URL':<50} | {'PROD':<6} | {'M1(22f)':<7} | {'M2(30f)':<7} | {'M3(cal)':<7}")
print("-" * 90)
for idx, r in df_real.iterrows():
    lbl = "LEGIT" if r["label"] == 0 else "PHISH"
    u_str = r["url"][:48]
    print(f"{lbl:<7} | {u_str:<50} | {r['prod_p']:<6.2f} | {r['m1_p']:<7.2f} | {r['m2_p']:<7.2f} | {r['m3_p']:<7.2f}")
