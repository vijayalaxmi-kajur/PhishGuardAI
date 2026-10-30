# Phase 13B: Dataset Inventory & Repository Verification Report

**Document ID:** `PGAI-REP-2026-PH13B-01`  
**Phase:** Phase 13B — Dataset Reconstruction and Quality Audit  
**Author:** Senior Machine Learning Engineer & Dataset Quality Auditor  
**Date:** October 28, 2026  
**Status:** COMPLETE (Zero Retraining / Cryptographically Preserved Baseline)  

---

## 1. Executive Overview

This document establishes an authoritative inventory of all URL datasets, preprocessing pipelines, feature extractors, training scripts, and evaluation benchmarks across the PhishGuardAI repository. In accordance with Task 1, all figures, schemas, and configurations were verified directly against active repository files.

---

## 2. Dataset Inventory

The repository maintains datasets across three distinct lifecycle stages: the raw baseline, the preprocessed baseline feature splits, and experimental candidate sets.

| Dataset Name | File Path | File Size | Exact Rows | Exact Columns | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Raw Baseline Dataset** | [`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv) | 15,149,338 B | 116,600 | 26 | Canonical raw labeled dataset containing original URL strings, reference domain/TLD strings, 22 numerical features, and binary target labels. |
| **Baseline Train Split** | [`data/processed/train.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/train.csv) | 7,336,041 B | 92,184 | 23 | Preprocessed training split (80%) containing the 22 numerical features and target `label`. URL strings are excluded. |
| **Baseline Test Split** | [`data/processed/test.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/test.csv) | 1,834,913 B | 23,047 | 23 | Preprocessed testing split (20%) containing the 22 numerical features and target `label`. URL strings are excluded. |
| **Baseline Feature Matrices** | [`data/processed/X_train.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/X_train.csv)<br>[`data/processed/X_test.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/X_test.csv) | 7,151,667 B<br>1,788,813 B | 92,184<br>23,047 | 22<br>22 | Isolated 22 numerical feature matrices used directly by scikit-learn estimators. |
| **Baseline Target Vectors** | [`data/processed/y_train.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/y_train.csv)<br>[`data/processed/y_test.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/processed/y_test.csv) | 276,559 B<br>69,148 B | 92,184<br>23,047 | 1<br>1 | Binary target series (Class 0: Legitimate, Class 1: Phishing). |
| **Phase C Training Set** | [`data/experiments/phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv) | 12,655,334 B | 91,486 | 7 | Experimental training split augmented with 45 complex legitimate URLs. |
| **Phase C Evaluation Set** | [`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv) | 3,083,857 B | 22,871 | 7 | Experimental evaluation split. |
| **Stage 1 Training Set** | [`data/experiments/stage1_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/stage1_training.csv) | 11,889,380 B | 91,965 | 7 | Stage 1 domain-split training set (72,508 unique domains) augmented with 429 complex dynamic URLs. |
| **Stage 1 Validation Set** | [`data/experiments/stage1_validation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/stage1_validation.csv) | 1,460,449 B | 11,382 | 7 | Stage 1 hyperparameter tuning validation split (9,199 unseen domains). |
| **Stage 1 Evaluation Set** | [`data/experiments/stage1_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/stage1_evaluation.csv) | 1,458,821 B | 11,382 | 7 | Stage 1 domain-held-out test split (9,199 unseen domains). |
| **Realistic Benchmark** | [`data/realistic_evaluation_set.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/realistic_evaluation_set.csv) | 10,405 B | 41 | 7 | Real-world benchmark containing 26 legitimate and 15 phishing URLs across streaming, education, e-commerce, and modern threat archetypes. |

---

## 3. Schemas and Column Definitions

### 3.1 Raw Baseline Schema (`dataset/Dataset.csv`)
The raw dataset consists of **26 columns**:
* **3 Metadata / Reference Columns:**
  * `url` (`object` / string): The raw target URL string.
  * `dom` (`object` / string): Extracted host/domain substring.
  * `tld` (`object` / string): Extracted top-level domain extension (contains 14 nulls corresponding to direct IP addresses).
* **22 Lexical & Structural Features:**
  1. `url_len` (`int64`): Total character length of URL.
  2. `dom_len` (`int64`): Character length of host domain.
  3. `is_ip` (`int64`): Binary flag (1 if host is IPv4, 0 otherwise).
  4. `tld_len` (`int64`): Character length of TLD extension.
  5. `subdom_cnt` (`int64`): Count of subdomain components.
  6. `letter_cnt` (`int64`): Count of ASCII alphabetic characters (`[a-zA-Z]`).
  7. `digit_cnt` (`int64`): Count of numeric digits (`[0-9]`).
  8. `special_cnt` (`int64`): Count of non-alphanumeric characters.
  9. `eq_cnt` (`int64`): Count of equals signs (`=`).
  10. `qm_cnt` (`int64`): Count of question marks (`?`).
  11. `amp_cnt` (`int64`): Count of ampersands (`&`).
  12. `dot_cnt` (`int64`): Count of periods (`.`).
  13. `dash_cnt` (`int64`): Count of hyphens (`-`).
  14. `under_cnt` (`int64`): Count of underscores (`_`).
  15. `letter_ratio` (`float64`): Ratio of letters to total URL length.
  16. `digit_ratio` (`float64`): Ratio of digits to total URL length.
  17. `spec_ratio` (`float64`): Ratio of special characters to total URL length.
  18. `is_https` (`int64`): Binary flag (1 if scheme is `https`, 0 if `http`).
  19. `slash_cnt` (`int64`): Count of forward slashes (`/`).
  20. `entropy` (`float64`): Shannon entropy of the URL character distribution.
  21. `path_len` (`int64`): Character length of the URL path component.
  22. `query_len` (`int64`): Character length of the query string component.
* **1 Target Column:**
  * `label` (`int64`): Binary ground truth (0 = Legitimate, 1 = Phishing).

### 3.2 Experimental Sets Schema (`stage1_*.csv` and `phase_c_*.csv`)
Experimental datasets share a normalized 7-column schema:
1. `url` (`object`): Full URL string.
2. `dom` (`object`): Host/domain identifier.
3. `label` (`int64`): Binary ground truth target.
4. `category` (`object`): Archetype classification (e.g., `legit_video`, `phish_free_hosting`).
5. `source` (`object`): Provenance feed (e.g., `PhishTank`, `OpenPhish`, `Tranco`, `YouTube`).
6. `collection_date` (`object`): Timestamp of ingestion (`YYYY-MM-DD`).
7. `verification_status` (`object`): Label validation state (`verified_legitimate`, `verified_phishing`, `unverified_stress_case`).

---

## 4. Ground Truth & Label Definitions

* **Class `0` — Legitimate / Benign:**
  - Documented Meaning: Authentic web resources belonging to legitimate organizations, institutions, and publishers without malicious payloads, deceptive impersonation, or credential-harvesting mechanisms.
  - Sourcing: Older Alexa/Tranco top lists, educational domains (`.edu`), government domains (`.gov`), and major enterprise homepages.
* **Class `1` — Phishing / Malicious:**
  - Documented Meaning: Social-engineering destinations designed to deceive visitors into disclosing sensitive credentials, banking information, or downloading malicious binaries.
  - Sourcing: Active threat feeds, including PhishTank, OpenPhish, and Mendeley URL-Phish.

---

## 5. Feature Extraction Dependencies

The system supports two feature-extraction pipelines:
1. **Production Pipeline (22 Features):** Implemented in [`src/features.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/features.py) and [`src/feature_extraction.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/feature_extraction.py). Uses standard library `urllib.parse`, `math.log2`, `re`, and `ipaddress`. No external network calls are performed.
2. **Experimental Pipeline (30 Features):** Implemented in [`src/experiments/features_expanded.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/features_expanded.py). Isolates lexical metrics across URL components (scheme, hostname, path, query) and adds entropy contrast, authentication path tokens, and ratio metrics.
3. **Inference Standardization:** As established in Phase 13A, [`src/decision_engine/adapter.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/adapter.py) (`ModelInferenceAdapter`) automatically detects whether the model was fitted on 22 or 30 features and whether named `pd.DataFrame` columns are required.

---

## 6. Train/Validation/Test Split Methodologies Across Phases

| Split Methodology | Component | Partition Ratios | Grouping Key | Domain Overlap Between Train & Test |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline Stratified Split** | [`src/preprocess.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/preprocess.py) | 80% Train / 20% Test | None (Record-level stratified split) | **2,120 domains (10.84% of test domains)** leaked into training set. |
| **Phase C Domain Split** | `scratch/build_phase_c_dataset.py` | 80% Train / 20% Eval | Host string (`dom`) | Contaminated by 11 exact benchmark URLs and 29 benchmark domains. |
| **Stage 1 Domain Split** | `scratch/build_stage1_dataset.py` | 80% Train / 10% Val / 10% Eval | Registered domain (`dom`) | Zero domain leakage between Train, Val, and Eval splits. **However, 26 benchmark domains were included in training.** |

---

## 7. Data Provenance

1. **URL-Phish Benchmark (Mendeley Data):**
   * Authors: Dam Minh Linh & Tran Cong Hung (2025).
   * DOI: [10.17632/65z9twcx3r.1](https://doi.org/10.17632/65z9twcx3r.1).
   * License: CC BY 4.0.
   * Documented composition: 100,000 benign URLs + 11,660 phishing URLs (111,660 total).
2. **Local Baseline Variant (`dataset/Dataset.csv`):**
   * Contains exactly 116,600 rows (100,000 benign + 16,600 phishing).
   * The additional 4,940 phishing rows (rows 111,660–116,599) represent an enriched phishing batch appended to strengthen the minority class.
3. **PhishTank & OpenPhish Active Feeds:**
   * Provided ground-truth malicious feeds used in Phase C, Stage 1, and the realistic benchmark.
4. **Legitimate URL Expansions:**
   * Stage 1 ingested 429 dynamic URLs from Wikipedia, arXiv, YouTube, and government services to supplement underrepresented long paths and query parameters.

---

## 8. Inconsistencies Between Reports and Actual Code

| Finding / Claim | Reported in Earlier Audits | Actual Verified Value in Codebase | Technical Reconciliation |
| :--- | :--- | :--- | :--- |
| **Mendeley Row Count** | 111,660 rows reported | **116,600 rows** in [`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv) | Rows 111,660–116,599 contain an unannounced append of 4,940 phishing samples. Verified. |
| **Domain Leakage Claim** | "Zero domain leakage verified" | **26 of 40 benchmark domains in Train** | Zero domain leakage was enforced *internally* between Train, Val, and Eval splits, but the realistic benchmark domains were not held out from Stage 1 training data. |
| **Candidate 2 Estimators** | 150 trees documented in Stage 1 report | **100 trees** in [`src/experiments/stage1_train.py:152`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/stage1_train.py#L152) | Training script constrained tree count to 100 to reduce execution latency. |
| **Candidate 3 Depth** | Max depth 20 documented | **Max depth 18** in [`src/experiments/stage1_train.py:159`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/stage1_train.py#L159) | Parameter clamped to 18 during grid validation. |
| **Phase C Benchmark Contamination** | Reported as independent evaluation | **11 exact benchmark URLs in Phase C Train** | Phase C training script ingested benchmark URLs directly, causing severe evaluation leakage. Documented and isolated. |

---
*End of Report — Inventory Verified.*
