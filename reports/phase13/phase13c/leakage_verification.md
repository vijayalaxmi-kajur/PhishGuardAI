# Phase 13C-1: Partition Leakage & Benchmark Holdout Verification Report

**Document ID:** `PGAI-REP-2026-PH13C-LEAK`  
**Phase:** Phase 13C-1 — Experimental Dataset Construction  
**Author:** Senior Cybersecurity Data Engineer & ML Researcher  
**Date:** October 28, 2026  
**Status:** COMPLETE (Zero Retraining / Cryptographically Preserved Baseline)  

---

## 1. Executive Summary

This document verifies the total mathematical elimination of dataset leakage across the Phase 13C-1 experimental dataset partitions ([`data/phase13c/splits/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/)). 

In previous phases, evaluations were compromised by two distinct leakage pathways:
1. **Benchmark Contamination:** In Phase C, 11 exact URLs and 29 domains from the realistic benchmark were present in the training set. In Stage 1, 26 benchmark domains were present in training data.
2. **Train/Test Domain Overlap:** In the baseline preprocessing pipeline ([`src/preprocess.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/preprocess.py)), naive record-level random splitting leaked 2,120 domains (10.84% of test domains) between train and test.

In Phase 13C-1, we implemented a **Benchmark Holdout Quarantine** and a **Salted Deterministic Domain-Grouped Split Algorithm** with Public Suffix List (PSL) awareness. Programmatic verification confirms **zero exact URL overlap, zero normalized URL overlap, zero domain group overlap, and zero benchmark domain contamination**.

---

## 2. Benchmark Holdout Quarantine Audit

Prior to partitioning, every candidate URL was cross-referenced against the 41 realistic benchmark URLs ([`data/realistic_evaluation_set.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/realistic_evaluation_set.csv)) and their 40 registered domains:

```
[Raw Candidate Corpus: 117,104 Records]
                 │
                 ├── [Matches Benchmark URL or Domain] ──► Quarantined: 6,356 Records
                 │                                         (data/phase13c/cleaned/quarantined_benchmark_records.csv)
                 │
                 └── [Completely Unseen Domains] ────────► Clean Training Pool: 110,748 Records
```

* **Quarantine Criteria:** Any record matching an exact benchmark URL, an RFC 3986 normalized benchmark URL, or belonging to any of the 40 benchmark registered domains (e.g., `youtube.com`, `google.com`, `amazon.com`, `wikipedia.org`, `github.com`, `ebay.com`, `cdc.gov`) was quarantined.
* **Total Quarantined Records:** **6,356 records** were safely segregated into [`data/phase13c/cleaned/quarantined_benchmark_records.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/cleaned/quarantined_benchmark_records.csv).
* **Benchmark Isolation:** The remaining clean candidate pool contains **zero samples from any benchmark domain**, ensuring that future evaluations on `data/realistic_evaluation_set.csv` test genuine out-of-distribution domain generalization.

---

## 3. Partition Leakage Verification Matrix

Programmatic assertions executed during dataset construction verified that all partition intersections are strictly empty:

| Verification Target | Comparison Pair | Measured Overlap Count | Status | Cryptographic Assurance |
| :--- | :--- | :--- | :--- | :--- |
| **Exact URL Overlap** | Train vs. Validation | **0** | **PASSED** | $\text{URLs}_{\text{Train}} \cap \text{URLs}_{\text{Val}} = \emptyset$ |
| **Exact URL Overlap** | Train vs. Test | **0** | **PASSED** | $\text{URLs}_{\text{Train}} \cap \text{URLs}_{\text{Test}} = \emptyset$ |
| **Exact URL Overlap** | Validation vs. Test | **0** | **PASSED** | $\text{URLs}_{\text{Val}} \cap \text{URLs}_{\text{Test}} = \emptyset$ |
| **Normalized URL Overlap** | Train vs. Validation | **0** | **PASSED** | $\text{NormURLs}_{\text{Train}} \cap \text{NormURLs}_{\text{Val}} = \emptyset$ |
| **Normalized URL Overlap** | Train vs. Test | **0** | **PASSED** | $\text{NormURLs}_{\text{Train}} \cap \text{NormURLs}_{\text{Test}} = \emptyset$ |
| **Normalized URL Overlap** | Validation vs. Test | **0** | **PASSED** | $\text{NormURLs}_{\text{Val}} \cap \text{NormURLs}_{\text{Test}} = \emptyset$ |
| **Domain Group Overlap** | Train vs. Validation | **0** | **PASSED** | $\text{Groups}_{\text{Train}} \cap \text{Groups}_{\text{Val}} = \emptyset$ (31,100 vs 3,884 groups) |
| **Domain Group Overlap** | Train vs. Test | **0** | **PASSED** | $\text{Groups}_{\text{Train}} \cap \text{Groups}_{\text{Test}} = \emptyset$ (31,100 vs 3,812 groups) |
| **Domain Group Overlap** | Validation vs. Test | **0** | **PASSED** | $\text{Groups}_{\text{Val}} \cap \text{Groups}_{\text{Test}} = \emptyset$ (3,884 vs 3,812 groups) |
| **Benchmark Domain Leakage** | Train vs. Benchmark | **0** | **PASSED** | Zero benchmark domains present in training data |
| **Benchmark Domain Leakage** | Validation vs. Benchmark | **0** | **PASSED** | Zero benchmark domains present in validation data |
| **Benchmark Domain Leakage** | Test vs. Benchmark | **0** | **PASSED** | Zero benchmark domains present in test data |

---

## 4. Multi-Tenant Infrastructure Handling

In multi-tenant environments (e.g. `pages.dev`, `weebly.com`, `s3.amazonaws.com`, `azurewebsites.net`, `firebaseapp.com`), grouping solely by registered root domain creates artificial cluster contamination, as thousands of distinct users and phishers share the same base domain.

### Implemented Protocol:
* For domains identified in `MULTI_TENANT_DOMAINS`, the grouping key was set to **`subdomain_tenant.registered_domain`** (e.g., `metamask-wallet.pages.dev` and `legit-docs.pages.dev` form separate, isolated groups).
* For standard standalone domains, the grouping key was set to the **registered domain** via the Public Suffix List (`tldextract`).
* Result: Legitimate tenant subdomains and phishing tenant subdomains are partitioned independently without cross-contaminating standard domain groupings.

---

## 5. Partition Seed & Processing Parameters

To ensure deterministic reproducibility:
* **Salt Value:** `"phishguard_phase13c_v1"`
* **Hash Function:** SHA-256 over `f"{split_group_key}_{SALT}"`
* **Partition Thresholds:**
  * $\text{int}(\text{SHA256}[:8], 16) \pmod{100} < 80 \implies \text{Train Split}$ (80%)
  * $80 \le \text{int}(\text{SHA256}[:8], 16) \pmod{100} < 90 \implies \text{Validation Split}$ (10%)
  * $\text{int}(\text{SHA256}[:8], 16) \pmod{100} \ge 90 \implies \text{Test Split}$ (10%)
* **Final Test Split Isolation:** The final test split ([`data/phase13c/splits/test.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/test.csv), $N=4,901$) is strictly quarantined and must NEVER be accessed during hyperparameter grid search or threshold optimization.

---
*End of Report — Leakage Verification Passed.*
