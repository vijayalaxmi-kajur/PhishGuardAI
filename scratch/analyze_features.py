import json
import pandas as pd
import numpy as np
import joblib

with open("scratch/reproduction_results.json") as f:
    results = json.load(f)

for r in results:
    print(f"\n==========================================")
    print(f"URL: {r['label']} -> {r['url']}")
    print(f"Prod Model Phishing Prob: {r['app_py_prod']['phishing_prob']:.2%}")
    f22 = r["f22"]
    f30 = r["f30"]
    print("--- 22 Features (Production Pipeline) ---")
    for k, v in f22.items():
        print(f"  {k:15s}: {v}")
    print("--- Additional 8 Features in 30-Feature Schema ---")
    extra_keys = [k for k in f30.keys() if k not in f22]
    for k in extra_keys:
        print(f"  {k:15s}: {f30[k]}")

# Load training dataset distribution to check percentiles
print("\n==========================================")
print("TRAINING DATASET DISTRIBUTION COMPARISON")
train_df = pd.read_csv("dataset/Dataset.csv")
print(f"Dataset rows: {len(train_df)}")

# Summary stats for key features in Dataset.csv (class 0 vs class 1)
key_cols = ["url_len", "dom_len", "special_cnt", "entropy", "path_len", "query_len", "dash_cnt", "dot_cnt", "subdom_cnt", "amp_cnt", "eq_cnt"]
available_cols = [c for c in key_cols if c in train_df.columns]

print("\nMean feature values by Class (0 = Legit, 1 = Phish) in Dataset.csv:")
grouped = train_df.groupby("label")[available_cols].mean().T
grouped.columns = ["Class 0 (Legit) Mean", "Class 1 (Phish) Mean"]
print(grouped)

print("\n95th percentile in Dataset.csv by Class:")
p95_0 = train_df[train_df["label"] == 0][available_cols].quantile(0.95)
p95_1 = train_df[train_df["label"] == 1][available_cols].quantile(0.95)
p95_df = pd.DataFrame({"Class 0 P95": p95_0, "Class 1 P95": p95_1})
print(p95_df)
