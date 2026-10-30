"""
PhishGuardAI - Generate Phase 13B Questionable & Conflicting Records CSV
Produces a safe, defanged CSV audit log of all questionable records,
conflicting domains, benchmark anomalies, and leakage cases.
"""

import os
import urllib.parse
import pandas as pd
import tldextract

PROJECT_ROOT = r"c:\Users\yalla\OneDrive\Desktop\PhishGuardAI"
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(DATA_DIR, "phase13b")

def defang_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    u = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parsed = urllib.parse.urlsplit(url)
    if parsed.netloc:
        defanged_netloc = parsed.netloc.replace(".", "[.]")
        u = u.replace(parsed.netloc, defanged_netloc, 1)
    return u

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

audit_rows = []

# 1. Benchmark 3 Unverified Stress Cases
bench_path = os.path.join(DATA_DIR, "realistic_evaluation_set.csv")
if os.path.exists(bench_path):
    df_bench = pd.read_csv(bench_path)
    stress_df = df_bench[df_bench["verification_status"] == "unverified_stress_case"]
    for idx, row in stress_df.iterrows():
        audit_rows.append({
            "record_id": f"BENCH_STRESS_{idx:03d}",
            "source_dataset": "data/realistic_evaluation_set.csv",
            "url_defanged": defang_url(row["url"]),
            "original_label": int(row["label"]),
            "registered_domain": get_registered_domain(row["url"]),
            "classification_category": "Unknown or unverified",
            "reason_for_concern": f"Unverified stress scenario: {row.get('category')}. Non-routable or unexpanded link.",
            "recommended_action": "Segregate from canonical ground-truth benchmark; evaluate in dedicated exploratory stress suite."
        })

# 2. Leaked URLs from Phase C Training
pc_train_path = os.path.join(DATA_DIR, "experiments", "phase_c_training.csv")
if os.path.exists(pc_train_path) and os.path.exists(bench_path):
    df_pc = pd.read_csv(pc_train_path)
    bench_urls = set(df_bench["url"])
    leaked = df_pc[df_pc["url"].isin(bench_urls)]
    for idx, row in leaked.iterrows():
        audit_rows.append({
            "record_id": f"PHASE_C_LEAK_{idx:05d}",
            "source_dataset": "data/experiments/phase_c_training.csv",
            "url_defanged": defang_url(row["url"]),
            "original_label": int(row["label"]),
            "registered_domain": get_registered_domain(row["url"]),
            "classification_category": "Conflicting evidence",
            "reason_for_concern": "Exact test set contamination: record was present in both training data and evaluation benchmark.",
            "recommended_action": "Purge from all future training partitions to prevent in-sample evaluation bias."
        })

# 3. Conflicting Domain Samples from Baseline Dataset
raw_path = os.path.join(PROJECT_ROOT, "dataset", "Dataset.csv")
df_raw = pd.read_csv(raw_path, low_memory=False)
df_raw["reg_domain"] = df_raw["url"].apply(get_registered_domain)
domain_labels = df_raw.groupby("reg_domain")["label"].nunique()
conflicting_domains = domain_labels[domain_labels > 1].index

for dom in conflicting_domains:
    dom_sub = df_raw[df_raw["reg_domain"] == dom]
    c0_sample = dom_sub[dom_sub["label"] == 0].iloc[0]
    c1_sample = dom_sub[dom_sub["label"] == 1].iloc[0]
    
    audit_rows.append({
        "record_id": f"DOM_CONFLICT_C0_{dom}",
        "source_dataset": "dataset/Dataset.csv",
        "url_defanged": defang_url(c0_sample["url"]),
        "original_label": 0,
        "registered_domain": dom,
        "classification_category": "Likely label, requiring confirmation",
        "reason_for_concern": f"Multi-tenant or compromised domain '{dom}' hosts both legitimate and phishing URLs.",
        "recommended_action": "Apply tenant-level subdomain grouping; do not split solely by root domain."
    })
    audit_rows.append({
        "record_id": f"DOM_CONFLICT_C1_{dom}",
        "source_dataset": "dataset/Dataset.csv",
        "url_defanged": defang_url(c1_sample["url"]),
        "original_label": 1,
        "registered_domain": dom,
        "classification_category": "Verified label",
        "reason_for_concern": f"Phishing lure hosted on multi-tenant domain '{dom}'.",
        "recommended_action": "Preserve as verified phishing lure under isolated tenant subdomain grouping."
    })

out_df = pd.DataFrame(audit_rows)
out_csv_path = os.path.join(OUTPUT_DIR, "questionable_and_conflicting_records.csv")
out_df.to_csv(out_csv_path, index=False)
print(f"Saved {len(out_df)} audited records to {out_csv_path}")
