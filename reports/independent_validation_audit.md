# PhishGuardAI — Independent Model Validation & Experiment Audit Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Document Type:** Pre-Experiment Audit & Evaluation Limitation Analysis  
**Phase:** Phase 8 — Independent Model Validation & Generalization Analysis  
**Date:** October 28, 2026  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Audit Scope

Prior to conducting new machine-learning experiments, an independent audit of the existing PhishGuardAI codebase, dataset, preprocessing pipeline, feature extractor, trained artifacts, and evaluation reports was conducted. 

The audit confirms that while the baseline Random Forest classifier (`models/phishing_model.joblib`) achieved exceptional performance on the standard 80/20 stratified split (**97.61% accuracy, 91.83% phishing F1-score, 0.9913 ROC-AUC**), that evaluation was subject to **domain overlap (group leakage)**:
* **2,120 domains (10.84% of test domains)** appear in both the training set and the test set.
* For multi-URL platforms (such as `weebly.com` with 2,455 URLs and `google.com` with 1,450 URLs), URLs with identical domain names and top-level suffixes were partitioned across both training and testing sets.
* Consequently, the random-split test set measured the model's ability to classify URLs from **known platforms and familiar domains**, but did **not** strictly measure how well the model generalizes to **completely novel, unseen domains**.

This document details the findings of this audit and establishes the scientific justification for a **domain-held-out validation experiment**.

---

## 2. Dataset Schema & Label Distribution Audit

### 2.1 Raw Dataset (`dataset/Dataset.csv`)
* **Total Records:** 116,600 rows, 26 columns.
* **Target Label Distribution:**
  * Label 0 (Legitimate): 100,000 samples (85.76%)
  * Label 1 (Phishing): 16,600 samples (14.24%)
  * Class Imbalance Ratio: ~6 : 1
* **Duplicate Rows:** 1,369 exact duplicate rows (1,359 in Class 0, 10 in Class 1).
* **Conflicting Labels:** Exactly 0 conflicting labels (no identical URL is labeled both 0 and 1).

### 2.2 Deduplicated Working Dataset
* **Clean Retained Rows:** 115,231 unique URLs.
* **Class 0 (Legitimate):** 98,641 rows (85.60%)
* **Class 1 (Phishing):** 16,590 rows (14.40%)
* **Target Feature Ordering:**
  1. `url_len`
  2. `dom_len`
  3. `is_ip`
  4. `tld_len`
  5. `subdom_cnt`
  6. `letter_cnt`
  7. `digit_cnt`
  8. `special_cnt`
  9. `eq_cnt`
  10. `qm_cnt`
  11. `amp_cnt`
  12. `dot_cnt`
  13. `dash_cnt`
  14. `under_cnt`
  15. `letter_ratio`
  16. `digit_ratio`
  17. `spec_ratio`
  18. `is_https`
  19. `slash_cnt`
  20. `entropy`
  21. `path_len`
  22. `query_len`
* **Integrity Check:** The 22 numerical features are strictly non-null and finite across all 115,231 records.

---

## 3. Audit of the Existing Random 80/20 Split

The baseline preprocessing pipeline (`src/preprocess.py`) partitioned the 115,231 clean URLs using a standard random stratified 80/20 split (`random_state=42`):
* **Training Partition (`data/processed/train.csv`):** 92,184 samples (78,912 legitimate, 13,272 phishing).
* **Testing Partition (`data/processed/test.csv`):** 23,047 samples (19,729 legitimate, 3,318 phishing).
* **URL Overlap:** Exactly 0 URLs (verified).

### 3.1 Domain Overlap Analysis
While the split guarantees zero identical URL leakage, an audit of the domain key (`dom`) reveals significant **group-level overlap**:

| Metric | Training Set | Testing Set | Total Unique | Overlap / Intersection |
|---|---|---|---|---|
| **Unique Domains** | 73,425 | 19,555 | 90,860 | **2,120 domains** |
| **Percentage of Test Domains in Train** | — | — | — | **10.84%** |
| **Total URLs Belonging to Overlapping Domains** | 18,728 | 4,682 | 23,410 | **20.32% of entire test set!** |

> [!WARNING]
> Over **20% of the URLs in the test set** (4,682 out of 23,047) belong to a domain that the model already observed during training!

### 3.2 Largest Overlapping Domains in the Random Split
The top domains contributing to this overlap are high-volume public web hosting, cloud services, and URL shorteners:

| Registered Domain | Total URLs | Legitimate URLs | Phishing URLs | Train Partition URLs | Test Partition URLs |
|---|---|---|---|---|---|
| `weebly.com` | 2,455 | 11 | 2,444 | 1,964 | 491 |
| `google.com` | 1,450 | 11 | 1,439 | 1,160 | 290 |
| `pages.dev` | 1,050 | 0 | 1,050 | 840 | 210 |
| `bit.ly` | 763 | 0 | 763 | 610 | 153 |
| `hsforms.com` | 358 | 0 | 358 | 286 | 72 |
| `qrco.de` | 329 | 0 | 329 | 263 | 66 |
| `r2.dev` | 240 | 0 | 240 | 192 | 48 |
| `va.gov` | 219 | 219 | 0 | 175 | 44 |
| `q-r.to` | 212 | 0 | 212 | 170 | 42 |
| `ead.me` | 210 | 0 | 210 | 168 | 42 |
| `campaign-archive.com`| 204 | 0 | 204 | 163 | 41 |
| `t.co` | 200 | 0 | 200 | 160 | 40 |
| `jotform.com` | 198 | 0 | 198 | 158 | 40 |
| `webflow.io` | 164 | 0 | 164 | 131 | 33 |
| `wixsite.com` | 160 | 10 | 150 | 128 | 32 |

---

## 4. Audit of Feature Extraction & Model Architecture

### 4.1 Feature Extraction Engine (`src/feature_extraction.py`)
* The extraction engine computes all 22 features completely offline using `tldextract` (configured with `suffix_list_urls=None` to ensure zero network calls) and Python's standard library `urllib.parse`.
* Verified that feature names, data types, and ordering match `URLFeatureExtractor.FEATURE_NAMES`.
* All 12 unit tests in `tests/test_feature_extraction.py` pass without warnings.

### 4.2 Production Model Artifact (`models/phishing_model.joblib`)
* Serialized object structure: Dictionary wrapper containing:
  * `model`: `RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)`
  * `feature_names`: 22 feature names in schema order
  * `metrics`: Accuracy (97.61%), Precision (90.52%), Recall (93.19%), F1 (91.83%)
  * `classes`: `[0, 1]` with phishing index at `1`
* Expected feature shape: Matrix with 22 columns.

---

## 5. Limitations of the Existing Evaluation

### 5.1 Group Leakage / Domain Leakage
In machine learning literature (e.g., *Kaufman et al., "Leakage in Data Mining"*, IEEE TKDE), evaluating models on data points sharing groups with the training set is a well-documented cause of inflated optimism:
1. **Domain Memorization via Features:** Features such as `dom_len`, `tld_len`, and character counts correlate with specific prominent domains. For example, `weebly.com` has `dom_len=10` and `tld_len=3`. If 1,964 `weebly.com` phishing URLs appear in training, the decision trees can easily split on combinations of `dom_len=10` and specific path/entropy thresholds to identify the remaining 491 test URLs.
2. **Real-World Mismatch:** In production cybersecurity deployments, an end-user rarely encounters a phishing URL hosted on a domain the model was specifically trained on yesterday. Most phishing attacks leverage newly registered domains (NRDs) or unfamiliar top-level domains.
3. **The Unanswered Question:** Can the Random Forest classifier detect phishing URLs when the **entire domain is completely novel and has never been seen in the training data**?

### 5.2 Mixed-Label Domains
The audit discovered **24 domains** in the dataset that contain **both legitimate (label 0) and phishing (label 1)** URLs:
* Examples: `weebly.com` (11 legit, 2,444 phish), `google.com` (11 legit, 1,439 phish), `wixsite.com` (10 legit, 150 phish), `dropbox.com` (1 legit, 108 phish), `adobe.com` (1 legit, 22 phish).
* These represent public content-hosting platforms abused by threat actors. A model trained on a random split might learn to treat `google.com` or `weebly.com` as inherently suspicious or inherently safe, confounding domain reputation with lexical feature structure.

---

## 6. Audit Conclusions & Proposed Experimental Design

| Evaluation Dimension | Existing Random Split | Proposed Domain-Held-Out Split |
|---|---|---|
| **Partitioning Key** | Uniform Random URLs | Registered Domain (`dom`) |
| **Domain Overlap** | **2,120 domains (10.84% of test domains)** | **Strictly 0 domains (Zero Overlap)** |
| **Evaluation Objective** | Standard In-Distribution Benchmark | Out-of-Distribution Domain Generalization |
| **Model Evaluated** | Production Model (`models/phishing_model.joblib`) | New Experimental Model (`models/experiments/...`) |
| **Preservation Rule** | Original datasets & models untouched | Original datasets & models untouched |

### Action Plan for Phase 8:
1. **Domain Grouping Key:** Use the verified registrable domain column `dom` (which handles multi-part public suffixes such as `.edu.au` and `.gov.au` identically to `tldextract`).
2. **Stratified Group Splitting:** Utilize `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` to generate an 80/20 train/test partition where **0 domains are shared** and class balance (14.4% phishing) is mathematically preserved.
3. **Experimental Model Training:** Train an experimental Random Forest under `models/experiments/domain_heldout_random_forest.joblib` without touching production models.
4. **Evaluation & Calibration:** Measure generalization metrics (accuracy, precision, recall, F1, ROC-AUC, PR-AUC) and evaluate probability calibration (Brier score and reliability curves).
