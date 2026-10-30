"""
PhishGuardAI - Phase 13B Dataset Audit & Quality Engine
Calculates comprehensive metrics for:
1. Dataset Inventory & Schema
2. Dataset Quality & Statistical Skew
3. Label Quality & Provenance
4. Dataset Leakage & Partition Overlap
5. Realistic Benchmark Integrity
"""

import os
import sys
import json
import re
import urllib.parse
import hashlib
from collections import Counter
import pandas as pd
import numpy as np
import tldextract

PROJECT_ROOT = r"c:\Users\yalla\OneDrive\Desktop\PhishGuardAI"
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(DATA_DIR, "phase13b")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Helper: defang URL for safe reporting
def defang_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    # replace http with hxxp, dots with [.]
    u = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # replace domain dots with [.]
    parsed = urllib.parse.urlsplit(url)
    if parsed.netloc:
        defanged_netloc = parsed.netloc.replace(".", "[.]")
        u = u.replace(parsed.netloc, defanged_netloc, 1)
    return u

# Helper: normalize URL
def normalize_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    u = url.strip()
    try:
        parsed = urllib.parse.urlsplit(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        # strip standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        # path
        path = parsed.path
        if path == "/":
            path = ""
        # query: sort parameters
        query = parsed.query
        if query:
            q_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            q_pairs.sort()
            query = urllib.parse.urlencode(q_pairs)
        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return u.lower()

# Helper: extract registered domain using tldextract
def get_registered_domain(url: str) -> str:
    if not isinstance(url, str):
        return ""
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ext.domain.lower() if ext.domain else ""
    except Exception:
        return ""

print("Loading raw dataset: dataset/Dataset.csv...")
raw_path = os.path.join(PROJECT_ROOT, "dataset", "Dataset.csv")
df_raw = pd.read_csv(raw_path, low_memory=False)

print(f"Loaded {len(df_raw)} rows, {len(df_raw.columns)} columns.")

# ==========================================
# 1. DATASET INVENTORY & INTEGRITY
# ==========================================
inventory = {
    "total_rows": len(df_raw),
    "total_columns": len(df_raw.columns),
    "columns": list(df_raw.columns),
    "null_counts": {col: int(df_raw[col].isnull().sum()) for col in df_raw.columns if df_raw[col].isnull().sum() > 0},
    "class_distribution": {
        "class_0_count": int((df_raw["label"] == 0).sum()),
        "class_0_pct": float((df_raw["label"] == 0).mean() * 100),
        "class_1_count": int((df_raw["label"] == 1).sum()),
        "class_1_pct": float((df_raw["label"] == 1).mean() * 100),
    },
    "exact_duplicate_rows": int(df_raw.duplicated().sum()),
    "exact_duplicate_urls": int(df_raw["url"].duplicated().sum()),
    "unique_urls": int(df_raw["url"].nunique()),
}

# Duplicate URLs by class
dup_mask = df_raw.duplicated(subset=["url"], keep="first")
dup_urls_df = df_raw[dup_mask]
inventory["duplicates_by_class"] = {
    "class_0_duplicates": int((dup_urls_df["label"] == 0).sum()),
    "class_1_duplicates": int((dup_urls_df["label"] == 1).sum()),
}

# Check conflicting labels for identical URLs
url_label_counts = df_raw.groupby("url")["label"].nunique()
conflicting_urls = url_label_counts[url_label_counts > 1]
inventory["conflicting_urls_count"] = len(conflicting_urls)

# Normalized URLs
print("Computing normalized URLs...")
normalized_urls = df_raw["url"].apply(normalize_url)
df_raw["url_norm"] = normalized_urls
norm_dup_count = int(df_raw["url_norm"].duplicated().sum())
unique_norm_urls = int(df_raw["url_norm"].nunique())
inventory["normalized_duplicates"] = norm_dup_count
inventory["unique_normalized_urls"] = unique_norm_urls

norm_conflicts = df_raw.groupby("url_norm")["label"].nunique()
inventory["normalized_conflicting_urls_count"] = int((norm_conflicts > 1).sum())

# Registered domains
print("Extracting registered domains...")
df_raw["reg_domain"] = df_raw["url"].apply(get_registered_domain)
unique_domains = df_raw["reg_domain"].nunique()
domain_counts = df_raw["reg_domain"].value_counts()
inventory["unique_registered_domains"] = int(unique_domains)
inventory["domains_with_single_url"] = int((domain_counts == 1).sum())
inventory["top_10_domains"] = {dom: int(cnt) for dom, cnt in domain_counts.head(10).items()}

# Domain conflict: same domain with both class 0 and class 1
domain_label_counts = df_raw.groupby("reg_domain")["label"].nunique()
conflicting_domains = domain_label_counts[domain_label_counts > 1]
inventory["conflicting_domains_count"] = len(conflicting_domains)
inventory["conflicting_domains_pct_of_all_domains"] = float(len(conflicting_domains) / unique_domains * 100)

# Save inventory
with open(os.path.join(OUTPUT_DIR, "inventory_metrics.json"), "w") as f:
    json.dump(inventory, f, indent=2)

print("Inventory metrics saved.")

# ==========================================
# 2. QUALITY & SKEW METRICS
# ==========================================
print("Computing quality & distribution metrics...")
df_c0 = df_raw[df_raw["label"] == 0].copy()
df_c1 = df_raw[df_raw["label"] == 1].copy()

# URL length statistics
def compute_stats(series):
    return {
        "mean": float(series.mean()),
        "std": float(series.std()),
        "min": float(series.min()),
        "p25": float(series.quantile(0.25)),
        "p50": float(series.quantile(0.50)),
        "p75": float(series.quantile(0.75)),
        "p90": float(series.quantile(0.90)),
        "p95": float(series.quantile(0.95)),
        "p99": float(series.quantile(0.99)),
        "max": float(series.max())
    }

quality = {
    "url_len": {
        "class_0": compute_stats(df_c0["url_len"]),
        "class_1": compute_stats(df_c1["url_len"])
    },
    "dom_len": {
        "class_0": compute_stats(df_c0["dom_len"]),
        "class_1": compute_stats(df_c1["dom_len"])
    },
    "path_len": {
        "class_0": compute_stats(df_c0["path_len"]),
        "class_1": compute_stats(df_c1["path_len"])
    },
    "query_len": {
        "class_0": compute_stats(df_c0["query_len"]),
        "class_1": compute_stats(df_c1["query_len"])
    },
    "entropy": {
        "class_0": compute_stats(df_c0["entropy"]),
        "class_1": compute_stats(df_c1["entropy"])
    }
}

# Protocol distribution: is_https
c0_https_col = int((df_c0["is_https"] == 1).sum())
c0_http_col = int((df_c0["is_https"] == 0).sum())
c1_https_col = int((df_c1["is_https"] == 1).sum())
c1_http_col = int((df_c1["is_https"] == 0).sum())

# Actual URL scheme parsed
df_raw["parsed_scheme"] = df_raw["url"].apply(lambda u: urllib.parse.urlsplit(u).scheme.lower() if isinstance(u, str) else "")
scheme_by_class = pd.crosstab(df_raw["parsed_scheme"], df_raw["label"]).to_dict()

quality["protocol_skew"] = {
    "class_0_is_https_flag": {"count": c0_https_col, "pct": float(c0_https_col / len(df_c0) * 100)},
    "class_0_is_http_flag": {"count": c0_http_col, "pct": float(c0_http_col / len(df_c0) * 100)},
    "class_1_is_https_flag": {"count": c1_https_col, "pct": float(c1_https_col / len(df_c1) * 100)},
    "class_1_is_http_flag": {"count": c1_http_col, "pct": float(c1_http_col / len(df_c1) * 100)},
    "parsed_scheme": scheme_by_class
}

# Query parameter presence
df_raw["has_query"] = df_raw["qm_cnt"] > 0
query_c0_cnt = int((df_c0["qm_cnt"] > 0).sum())
query_c1_cnt = int((df_c1["qm_cnt"] > 0).sum())

quality["query_parameter_skew"] = {
    "class_0_has_query": {"count": query_c0_cnt, "pct": float(query_c0_cnt / len(df_c0) * 100)},
    "class_1_has_query": {"count": query_c1_cnt, "pct": float(query_c1_cnt / len(df_c1) * 100)},
    "ratio_class1_to_class0_query_rate": float((query_c1_cnt / len(df_c1)) / (query_c0_cnt / len(df_c0)))
}

# Length bucket breakdown
buckets = [(0, 30), (30, 50), (50, 70), (70, 90), (90, 120), (120, 10000)]
bucket_results = []
for low, high in buckets:
    sub = df_raw[(df_raw["url_len"] >= low) & (df_raw["url_len"] < high)]
    total = len(sub)
    c0 = int((sub["label"] == 0).sum())
    c1 = int((sub["label"] == 1).sum())
    c1_rate = float(c1 / total * 100) if total > 0 else 0.0
    bucket_results.append({
        "bucket": f"[{low}, {high})" if high < 10000 else f"[{low}+)",
        "total": total,
        "class_0": c0,
        "class_1": c1,
        "phishing_pct": c1_rate
    })

quality["length_buckets"] = bucket_results

# IP addresses
c0_ip = int((df_c0["is_ip"] == 1).sum())
c1_ip = int((df_c1["is_ip"] == 1).sum())
quality["ip_hosts"] = {
    "class_0_ip": c0_ip,
    "class_1_ip": c1_ip
}

with open(os.path.join(OUTPUT_DIR, "quality_metrics.json"), "w") as f:
    json.dump(quality, f, indent=2)

print("Quality metrics saved.")

# ==========================================
# 3. LEAKAGE AUDIT ACROSS PARTITIONS
# ==========================================
print("Auditing partition leakage...")
# Load datasets for leakage checks
stage1_train_path = os.path.join(DATA_DIR, "experiments", "stage1_training.csv")
stage1_val_path = os.path.join(DATA_DIR, "experiments", "stage1_validation.csv")
stage1_eval_path = os.path.join(DATA_DIR, "experiments", "stage1_evaluation.csv")
phase_c_train_path = os.path.join(DATA_DIR, "experiments", "phase_c_training.csv")
phase_c_eval_path = os.path.join(DATA_DIR, "experiments", "phase_c_evaluation.csv")
benchmark_path = os.path.join(DATA_DIR, "realistic_evaluation_set.csv")

leakage = {}

if os.path.exists(benchmark_path):
    df_bench = pd.read_csv(benchmark_path)
    df_bench["url_norm"] = df_bench["url"].apply(normalize_url)
    df_bench["reg_domain"] = df_bench["url"].apply(get_registered_domain)
    
    bench_urls = set(df_bench["url"])
    bench_norm = set(df_bench["url_norm"])
    bench_domains = set(df_bench["reg_domain"].dropna())
    
    leakage["benchmark"] = {
        "total_records": len(df_bench),
        "unique_urls": len(bench_urls),
        "unique_domains": len(bench_domains),
        "class_0": int((df_bench["label"] == 0).sum()),
        "class_1": int((df_bench["label"] == 1).sum())
    }
    
    # Check baseline raw dataset overlap with benchmark
    raw_urls = set(df_raw["url"])
    raw_norm = set(df_raw["url_norm"])
    raw_domains = set(df_raw["reg_domain"].dropna())
    
    overlap_raw_urls = bench_urls.intersection(raw_urls)
    overlap_raw_norm = bench_norm.intersection(raw_norm)
    overlap_raw_dom = bench_domains.intersection(raw_domains)
    
    leakage["benchmark_vs_raw_dataset"] = {
        "exact_url_overlap_count": len(overlap_raw_urls),
        "normalized_url_overlap_count": len(overlap_raw_norm),
        "domain_overlap_count": len(overlap_raw_dom),
        "overlapping_domains": list(overlap_raw_dom)
    }
    
    # Check Stage 1 training overlap with benchmark
    if os.path.exists(stage1_train_path):
        df_s1_train = pd.read_csv(stage1_train_path)
        df_s1_val = pd.read_csv(stage1_val_path)
        df_s1_eval = pd.read_csv(stage1_eval_path)
        
        s1_train_urls = set(df_s1_train["url"])
        s1_train_domains = set(df_s1_train["dom"].apply(lambda d: get_registered_domain(f"http://{d}") if isinstance(d, str) else ""))
        
        s1_val_urls = set(df_s1_val["url"])
        s1_val_domains = set(df_s1_val["dom"].apply(lambda d: get_registered_domain(f"http://{d}") if isinstance(d, str) else ""))
        
        s1_eval_urls = set(df_s1_eval["url"])
        s1_eval_domains = set(df_s1_eval["dom"].apply(lambda d: get_registered_domain(f"http://{d}") if isinstance(d, str) else ""))
        
        # Inter-split leakage
        leakage["stage1_inter_split"] = {
            "train_val_url_overlap": len(s1_train_urls.intersection(s1_val_urls)),
            "train_eval_url_overlap": len(s1_train_urls.intersection(s1_eval_urls)),
            "val_eval_url_overlap": len(s1_val_urls.intersection(s1_eval_urls)),
            "train_val_domain_overlap": len(s1_train_domains.intersection(s1_val_domains)),
            "train_eval_domain_overlap": len(s1_train_domains.intersection(s1_eval_domains)),
            "val_eval_domain_overlap": len(s1_val_domains.intersection(s1_eval_domains))
        }
        
        # Stage 1 Train vs Benchmark
        s1_bench_url_overlap = bench_urls.intersection(s1_train_urls)
        s1_bench_dom_overlap = bench_domains.intersection(s1_train_domains)
        
        leakage["stage1_train_vs_benchmark"] = {
            "exact_url_overlap_count": len(s1_bench_url_overlap),
            "domain_overlap_count": len(s1_bench_dom_overlap),
            "overlapping_domains": list(s1_bench_dom_overlap)
        }
        
    # Check Phase C training overlap with benchmark
    if os.path.exists(phase_c_train_path):
        df_pc_train = pd.read_csv(phase_c_train_path)
        pc_train_urls = set(df_pc_train["url"])
        pc_train_domains = set(df_pc_train["dom"].apply(lambda d: get_registered_domain(f"http://{d}") if isinstance(d, str) else ""))
        
        pc_bench_url_overlap = bench_urls.intersection(pc_train_urls)
        pc_bench_dom_overlap = bench_domains.intersection(pc_train_domains)
        
        leakage["phase_c_train_vs_benchmark"] = {
            "exact_url_overlap_count": len(pc_bench_url_overlap),
            "exact_overlapping_urls": [defang_url(u) for u in pc_bench_url_overlap],
            "domain_overlap_count": len(pc_bench_dom_overlap),
            "overlapping_domains": list(pc_bench_dom_overlap)
        }

with open(os.path.join(OUTPUT_DIR, "leakage_metrics.json"), "w") as f:
    json.dump(leakage, f, indent=2)

print("Leakage metrics saved.")

# ==========================================
# 4. BENCHMARK INTEGRITY
# ==========================================
if os.path.exists(benchmark_path):
    print("Auditing benchmark integrity...")
    bench_records = []
    for idx, row in df_bench.iterrows():
        bench_records.append({
            "index": idx,
            "url_defanged": defang_url(row["url"]),
            "label": int(row["label"]),
            "category": str(row.get("category", "")),
            "source": str(row.get("source", "")),
            "verification_status": str(row.get("verification_status", "")),
            "verification_notes": str(row.get("verification_notes", "")),
            "url_len": len(row["url"]),
            "has_query": "?" in row["url"],
            "registered_domain": get_registered_domain(row["url"])
        })
    
    # Categorize into subsets:
    # 1. verified_legit
    # 2. verified_phish
    # 3. unverified_stress
    status_counts = df_bench["verification_status"].value_counts().to_dict()
    category_counts = df_bench["category"].value_counts().to_dict()
    
    bench_audit = {
        "total_records": len(df_bench),
        "status_counts": {k: int(v) for k, v in status_counts.items()},
        "category_counts": {k: int(v) for k, v in category_counts.items()},
        "records": bench_records
    }
    
    with open(os.path.join(OUTPUT_DIR, "benchmark_audit.json"), "w") as f:
        json.dump(bench_audit, f, indent=2)

print("Benchmark audit saved.")

# ==========================================
# 5. LABEL QUALITY & ANOMALIES AUDIT
# ==========================================
print("Auditing label quality and questionable patterns...")

# Sample records by category:
# 1. Conflicting domains (domains with both class 0 and 1)
sample_conflicting_domains = []
for dom in conflicting_domains.index[:20]:
    dom_sub = df_raw[df_raw["reg_domain"] == dom]
    c0_sub = dom_sub[dom_sub["label"] == 0]
    c1_sub = dom_sub[dom_sub["label"] == 1]
    sample_conflicting_domains.append({
        "domain": dom,
        "total_urls": len(dom_sub),
        "class_0_count": len(c0_sub),
        "class_1_count": len(c1_sub),
        "sample_class_0": [defang_url(u) for u in c0_sub["url"].head(2)],
        "sample_class_1": [defang_url(u) for u in c1_sub["url"].head(2)]
    })

# 2. Repetitive / Template URLs in Class 1
# Check for common repetitive subdomains or path structures
c1_hosts = df_c1["dom"].value_counts()
top_c1_hosts = {h: int(c) for h, c in c1_hosts.head(15).items()}

label_audit = {
    "conflicting_domain_samples": sample_conflicting_domains,
    "top_phishing_hosts": top_c1_hosts,
    "mendeley_partition_split": {
        "rows_0_to_99999": {"count": 100000, "all_class_0": bool((df_raw.iloc[:100000]["label"] == 0).all())},
        "rows_100000_to_111659": {"count": 11660, "all_class_1": bool((df_raw.iloc[100000:111660]["label"] == 1).all())},
        "rows_111660_to_116599": {"count": 4940, "all_class_1": bool((df_raw.iloc[111660:116600]["label"] == 1).all())}
    }
}

with open(os.path.join(OUTPUT_DIR, "label_quality_audit.json"), "w") as f:
    json.dump(label_audit, f, indent=2)

print("Label quality audit saved.")
print("ALL PHASE 13B AUDIT DATA GENERATED SUCCESSFULLY!")
