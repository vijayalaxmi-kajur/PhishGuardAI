import os
import sys
import json
import urllib.parse
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.abspath("."))
import tldextract

def extract_registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.registered_domain:
        return ext.registered_domain.lower()
    return ext.domain.lower() if ext.domain else "unknown"

print("==================================================================")
print("                   PHASE B - DATA AND LABEL AUDIT                 ")
print("==================================================================")

files = {
    "train": "data/experiments/stage1_training.csv",
    "val": "data/experiments/stage1_validation.csv",
    "eval": "data/experiments/stage1_evaluation.csv",
    "real": "data/realistic_evaluation_set.csv",
    "base_raw": "dataset/Dataset.csv"
}

dfs = {}
for k, path in files.items():
    if os.path.exists(path):
        dfs[k] = pd.read_csv(path)
        print(f"Loaded {k:<10}: {len(dfs[k]):>7} rows, columns: {list(dfs[k].columns[:6])}")
    else:
        print(f"MISSING FILE: {path}")

# 1. Missing / Malformed URLs
print("\n--- 1. Missing / Null / Malformed URL Check ---")
for k, df in dfs.items():
    null_urls = df["url"].isnull().sum()
    empty_urls = (df["url"].astype(str).str.strip() == "").sum()
    print(f"{k:<10}: null_urls={null_urls}, empty_urls={empty_urls}")

# 2. Duplicate & Canonicalized URLs within splits
print("\n--- 2. Duplicate and Conflict Check within Splits ---")
for k, df in dfs.items():
    n_total = len(df)
    n_unique_urls = df["url"].nunique()
    exact_dups = n_total - n_unique_urls
    
    # Check label conflicts
    label_conflicts = df.groupby("url")["label"].nunique()
    n_conflicts = (label_conflicts > 1).sum()
    print(f"{k:<10}: Total={n_total}, Unique URLs={n_unique_urls}, Dups={exact_dups}, Conflicting Labels={n_conflicts}")

# 3. Class Imbalance
print("\n--- 3. Class Imbalance Breakdown ---")
for k, df in dfs.items():
    counts = df["label"].value_counts().to_dict()
    c0 = counts.get(0, 0)
    c1 = counts.get(1, 0)
    total = c0 + c1
    print(f"{k:<10}: Legit(0)={c0:>6} ({c0/total:6.2%}) | Phish(1)={c1:>6} ({c1/total:6.2%}) | Total={total}")

# 4. Domain Overlap across Splits
print("\n--- 4. Cross-Split Domain & URL Overlap Analysis ---")
splits = ["train", "val", "eval", "real"]
domains = {}
urls = {}
for s in splits:
    if "dom" in dfs[s].columns:
        domains[s] = set(dfs[s]["dom"].astype(str).str.lower().unique())
    else:
        domains[s] = set(dfs[s]["url"].apply(extract_registered_domain).unique())
    urls[s] = set(dfs[s]["url"].unique())

print(f"Unique Domains: Train={len(domains['train'])}, Val={len(domains['val'])}, Eval={len(domains['eval'])}, Real={len(domains['real'])}")

pairs = [
    ("train", "val"),
    ("train", "eval"),
    ("val", "eval"),
    ("train", "real"),
    ("val", "real"),
    ("eval", "real"),
]

for s1, s2 in pairs:
    url_overlap = urls[s1].intersection(urls[s2])
    dom_overlap = domains[s1].intersection(domains[s2])
    print(f"Overlap {s1:>5} vs {s2:<5}: URLs={len(url_overlap)}, Domains={len(dom_overlap)}")
    if len(dom_overlap) > 0 and (s1 == "real" or s2 == "real"):
        print(f"   Shared domains between {s1} and {s2}: {list(dom_overlap)[:10]}")

# 5. Provenance & Source Distribution
print("\n--- 5. Dataset Provenance Breakdown in Training Split ---")
if "source" in dfs["train"].columns:
    print(dfs["train"]["source"].value_counts())
    print("\nTraining Category Breakdown:")
    print(dfs["train"]["category"].value_counts())

# 6. Benchmark Set Independent Verification
print("\n--- 6. Realistic Benchmark Verification Status ---")
print(dfs["real"]["verification_status"].value_counts())
print("\nCategories with verification status:")
print(pd.crosstab(dfs["real"]["category"], dfs["real"]["verification_status"]))
