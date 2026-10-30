# PhishGuardAI — Phase 11 Phase B: Comprehensive Investigation Summary Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase B — Read-Only Investigation: Comprehensive Synthesis & Executive Briefing  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Preservation Status:** Strictly Read-Only (Zero Retraining, Zero Model Overwrite, Zero Dataset Alteration)  

---

## 1. Executive Summary & Investigation Context

PhishGuardAI utilizes a 22-feature Random Forest classifier to detect malicious URLs. During testing, the production model classified the legitimate YouTube playlist lecture link:
`https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`
as **PHISHING** with **94.00% probability** (94 out of 100 decision trees voted for phishing).

Phase B conducted an exhaustive, read-only empirical investigation across six investigative dimensions to determine whether this false positive stems from dataset sampling bias, inadequate feature representation, model behavior, or evaluation leakage. 

All analyses were executed directly against the physical dataset files, serialized model artifacts, and project source code. **Zero files, models, thresholds, or datasets were modified during Phase B.**

---

## 2. Core Diagnostic Answers to Key Investigation Questions

### 1. Which dataset and model files were actually inspected?
The audit programmatically inspected and verified the following physical files:
* **Raw Dataset:** `dataset/Dataset.csv` (15,149,338 bytes, SHA-256: `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`)
* **Clean Processed Splits:**
  * `data/processed/train.csv` (7,336,041 bytes)
  * `data/processed/test.csv` (1,834,913 bytes)
  * `data/processed/X_train.csv` (7,151,667 bytes)
  * `data/processed/X_test.csv` (1,788,813 bytes)
  * `data/processed/y_train.csv` (276,559 bytes)
  * `data/processed/y_test.csv` (69,148 bytes)
  * `data/processed/split_metadata.json` (1,319 bytes)
* **Model Artifacts:**
  * `models/phishing_model.joblib` (Production Random Forest, 51,777,896 bytes, SHA-256: `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5`)
  * `models/random_forest.joblib` (51,777,896 bytes, identical to production)
  * `models/logistic_regression.joblib` (3,677 bytes)
  * `models/experiments/domain_heldout_random_forest.joblib` (Phase 8 experiment, 48,801,105 bytes)
  * `models/experiments/domain_experiment_metadata.json` (3,140 bytes)
  * `models/models_metadata.json` (1,328 bytes)
* **Source Modules:** `src/feature_extraction.py`, `src/preprocess.py`, `src/train.py`, `src/domain_validation.py`, `app.py`.

### 2. What is the verified dataset size and label distribution?
* **Raw Dataset (`Dataset.csv`):** Exactly **116,600 rows** and **26 columns**:
  * Legitimate (`label = 0`): **100,000 samples (85.76%)**
  * Phishing (`label = 1`): **16,600 samples (14.24%)**
  * Imbalance ratio: **6.02 : 1**.
* **Deduplicated Clean Dataset:** Exactly **115,231 unique URLs**:
  * Legitimate (`label = 0`): **98,641 samples (85.60%)**
  * Phishing (`label = 1`): **16,590 samples (14.40%)**
  * Duplicates removed: exactly **1,369 rows** (1,359 in class 0, 10 in class 1).
  * Conflicting labels: **0 conflicting URLs**.
* **Stratified 80/20 Partitions:**
  * Training split: **92,184 samples** (78,912 Legitimate, 13,272 Phishing).
  * Testing split: **23,047 samples** (19,729 Legitimate, 3,318 Phishing).

### 3. Are legitimate URLs with long query strings underrepresented?
* **Yes, severely and disproportionately:**
  * **97.99% of legitimate URLs (96,660 / 98,641)** have **zero query string (`query_len = 0`)**.
  * Only **2.01% of legitimate URLs (1,981 / 98,641)** have any query string.
  * Only **0.12% (118 URLs)** have `query_len >= 50`.
  * Only **0.07% (69 URLs)** have `query_len >= 61` (the YouTube target URL has 61 characters).
  * Only **0.16% (162 URLs)** have 3 or more query parameters (the YouTube URL has 3).
  * Modern dynamic web platforms are entirely absent from the benign training set: **0 YouTube URLs**, **0 Google Search URLs**, and **0 Amazon product URLs**.
  * Over 95% of benign URLs have 0 digits, whereas 56.8% of phishing URLs have digits.

### 4. Was any feature-extraction inconsistency found?
* **Training vs. Inference Consistency:** 100% consistent across all 22 features (0 mismatches across 2,000 sampled records).
* **Threshold Boundary Inconsistency:**
  * In `scikit-learn`'s `model.predict()`, ties at exactly 0.50 are broken in favor of Class 0 (Legitimate), yielding **324 False Positives** on the test set.
  * In `app.py` line 260 (`if phishing_prob >= decision_threshold:`), ties at 0.50 are broken in favor of Class 1 (Phishing), yielding **331 False Positives** on the test set (7 borderline samples flipped).
* **Architectural Flaw:** The extractor computes global character counts across the full URL string rather than isolating domain tokens from query parameters. This allows standard query syntax (`?`, `=`, `&`, and base64 video identifiers) to artificially inflate `entropy` (5.47), `digit_ratio` (0.066), and `special_cnt` (13).

### 5. What is the main evidence behind the false-positive problem?
The false-positive classification of the YouTube URL ($p = 0.94$) is caused by a **compound sampling and inductive trap**:
1. **Structural Parameter Overlap:** The YouTube URL contains 6 digits, 13 special characters, 3 equals signs, 2 ampersands, `query_len = 61`, and `entropy = 5.47`.
2. **Extreme Tail Position:** An entropy of 5.47 exceeds **99.99%** of benign URLs in the dataset. A query length of 61 exceeds **99.93%** of benign URLs.
3. **Inverted HTTPS Bias:** In the training dataset, **91.4% of phishing URLs use HTTPS**, compared to only **34.9% of benign URLs**. Decision trees treat HTTPS (`is_https = 1`) as a strong indicator of phishing (Rank #1 Gini importance: 15.55%).
4. **Ensemble Voting:** 94 out of 100 decision trees evaluate `entropy > 4.4`, `is_https == 1`, `digit_cnt > 0.5`, and `query_len > 10.5` and branch directly into phishing leaves.

### 6. Was data leakage detected?
* **Exact URL Leakage:** None (0 identical URLs between train and test).
* **Near-Duplicate Leakage:** **302 near-duplicate URL pairs** exist across train and test that differ only by protocol (`http` vs. `https`) or trailing slash (`/`).
* **Domain Overlap in Random Split:** **2,120 registered domains (10.84% of test domains)** appear in both train and test. **23.78% of test URLs (5,480 samples)** belong to domains seen during training.
* **Generalization Penalty on Novel Domains:** In Phase 8, when domain overlap was strictly eliminated ($\text{Train} \cap \text{Test} = \emptyset$), phishing recall dropped from **93.19% down to 87.34%**, and missed attacks (False Negatives) nearly doubled from **226 to 420 missed attacks (+85.8%)**. High random-split accuracy (97.61%) creates an over-optimistic impression of generalization.

### 7. What are the three highest-priority improvements?
1. **Priority 1: Dataset Augmentation with Complex Legitimate URLs:** Ingest verified benign URLs with multi-parameter query strings, video identifiers, tracking parameters, and modern HTTPS to balance the continuous feature space.
2. **Priority 2: Domain-Aware Evaluation Standard (`StratifiedGroupKFold`):** Standardize on zero-domain-overlap evaluation as the primary acceptance gate to eliminate over-optimistic evaluation leakage.
3. **Priority 3: Post-Hoc Probability Calibration & Tree Depth Regularization:** Apply Platt scaling / Isotonic regression to pull the 116 borderline false positives ($0.50 \le p < 0.60$) below the decision threshold, and constrain tree depth to prevent brittle memorization of entropy splits.

### 8. What are the exact paths of all reports created?
All seven Phase B investigation reports have been saved in `reports/phase11/`:
1. `reports/phase11/phase_b_dataset_quality.md`
2. `reports/phase11/phase_b_url_distribution.md`
3. `reports/phase11/phase_b_feature_consistency.md`
4. `reports/phase11/phase_b_false_positive_analysis.md`
5. `reports/phase11/phase_b_leakage_audit.md`
6. `reports/phase11/phase_b_recommendations.md`
7. `reports/phase11/phase_b_summary.md`

### 9. Were there any checks that could not be completed?
* **Live Network Content Verification:** Offline audit protocols strictly prohibited sending live HTTP/DNS queries to historical URLs in the dataset to avoid network dependencies and ground-truth poisoning.
* **Archival Crawler Metadata:** The raw CSV does not preserve the original web crawler depth, user-agent, or crawl date, preventing exact reconstruction of the authors' original 2025 scraping parameters.

---

## 3. High-Level Summary Table of Empirical Measurements

| Metric / Dimension | Baseline Random Split | Domain-Held-Out Split | Clean Dataset Total | Audit Assessment |
|---|---|---|---|---|
| **Total Evaluated Samples** | 23,047 | 23,045 | 115,231 | 100% Reconciled |
| **Legitimate Samples (Class 0)** | 19,729 (85.6%) | 19,727 (85.6%) | 98,641 (85.6%) | Exact Class Balance |
| **Phishing Samples (Class 1)** | 3,318 (14.4%) | 3,318 (14.4%) | 16,590 (14.4%) | Exact Sample Match |
| **True Negatives (TN)** | 19,405 | 19,403 | — | Specificity Robust |
| **False Positives (FP)** | **324** (1.64% FPR) | **324** (1.64% FPR) | — | Identical False Alarms |
| **False Negatives (FN)** | **226** (6.81% FNR) | **420** (12.66% FNR) | — | **+194 Missed Attacks on Unseen Sites** |
| **True Positives (TP)** | 3,092 | 2,898 | — | Drop in Sensitivity |
| **Phishing Precision** | **90.52%** | **89.94%** | — | High Specificity |
| **Phishing Recall** | **93.19%** | **87.34%** | — | **-5.85% Generalization Drop** |
| **Phishing F1-Score** | **91.83%** | **88.62%** | — | -3.21% Delta |
| **ROC-AUC** | 0.9913 | 0.9826 | — | High Discrimination |
| **PR-AUC** | 0.9716 | 0.9286 | — | Noticeable Minor Class Drop |
| **Domain Overlap** | **2,120 domains (10.84%)** | **0 domains (Strictly 0)** | — | Leakage Eliminated in Exp |
| **Near-Duplicate Overlap** | **302 URL pairs** | Handled in Phase 8 | — | Normalization Required |
| **Target YouTube Probability** | **0.9400 (94.0%)** | — | — | **Severe False Positive** |

---

## 4. Evidentiary Distinctions

In compliance with reporting directives, the findings are categorized as follows:
* **Verified Facts from Actual Files:**
  * Raw dataset has 116,600 rows (100k benign, 16.6k phishing) and 26 columns.
  * Deduplication removes 1,369 rows, leaving 115,231 clean unique URLs with 0 conflicting labels.
  * Extractor calculates all 22 features identically to dataset ground truth.
  * Exactly 0 YouTube, Google Search, or Amazon URLs exist in the benign dataset.
* **Measured Results:**
  * 97.99% of benign URLs have `query_len = 0`.
  * The target YouTube URL has `query_len = 61` (top 0.07% of benign), `entropy = 5.47` (top 0.01% of benign), and `is_https = 1` (matches 91.4% phishing vs. 34.9% benign).
  * 302 near-duplicate URLs exist across train and test; 2,120 domains overlap in the random split.
* **Hypotheses Needing Further Testing:**
  * Feature decoupling (separating domain entropy from query entropy) combined with dataset augmentation will eliminate the false positive on the YouTube URL without reducing phishing recall.
* **Missing Evidence / Limitations:**
  * Lack of original collection timestamps limits temporal drift analysis.

---

## 5. Phase B Conclusion & Status

Phase B is complete. The root causes of the false positive on legitimate complex URLs have been empirically measured, documented, and diagnosed. All original models, datasets, thresholds, and applications remain in their untouched baseline state. 

**Antigravity will stop here and await user instructions before proceeding to Phase C.**
