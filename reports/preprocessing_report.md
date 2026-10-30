# PhishGuardAI — Preprocessing & Stratified Splitting Report

**Project:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Pipeline Module:** `src/preprocess.py`  
**Execution Timestamp:** 2026-10-28 12:47:04  
**Random Seed:** `42`  
**Split Ratio:** `80% Train / 20% Test`  

---

## 1. Executive Summary

The dataset preprocessing pipeline was executed to prepare raw data for machine-learning model training.
The original `dataset/Dataset.csv` was preserved with zero in-place modifications.
Deterministic deduplication, strict feature isolation, and stratified splitting were enforced to prevent train-test data leakage.

| Metric | Raw Dataset | Processed & Cleaned | Variance / Removed |
| :--- | :--- | :--- | :--- |
| **Total Rows** | 116,600 | **115,231** | -1,369 duplicates |
| **Class 0 (Legitimate)** | 100,000 (85.76%) | **98,641** (85.60%) | -1,359 duplicates |
| **Class 1 (Phishing)** | 16,600 (14.24%) | **16,590** (14.40%) | -10 duplicates |
| **Total Features ($X$)** | 22 numerical features | **22 numerical features** | Exact schema order |
| **Conflicting Labels** | 0 | **0** | Perfect consistency |

---

## 2. Deduplication Policy & Data Leakage Prevention

### Deterministic Deduplication:
* **Issue:** The raw dataset contained **1,369 duplicate URL rows** (1,359 in Class 0, 10 in Class 1).
* **Policy Applied:** Exact duplicate URLs were pruned by retaining the **first occurrence** (`drop_duplicates(subset=['url'], keep='first')`).
* **Leakage Avoidance:** Deduplication was performed **prior to train/test splitting**.
  If duplicates had remained, identical URLs would have leaked across both splits, causing the model to simply memorize specific addresses rather than learning generalizable structural rules.
* **Verification:** Post-split verification confirmed **exactly 0 overlapping URLs** between training and testing sets.

### Domain Overlap Analysis (Limitation & Recommendation):
* **Observation:** Out of 90,860 unique domains, **2,120 domains (10.84% of test domains)** appear in both the training and test sets.
* **Reason:** Legitimate public platforms (e.g., `google.com`, `github.io`, multi-page university domains) host multiple distinct URLs in the benchmark.
* **Impact:** While standard stratified URL splitting is essential for baseline benchmarking, evaluators in a viva will ask about domain-level generalization.
* **Recommendation:** In Phase 4/5, a secondary **GroupKFold by registered domain** experiment should be performed to measure how well the model generalizes to completely unseen domains.

---

## 3. Stratified Split Proportions & Imbalance Handling

Stratification ensures that the training set and testing set mirror the authentic class distribution:

| Split Set | Total Samples | Class 0 (Legitimate) | Class 1 (Phishing) | Phishing Ratio |
| :--- | :--- | :--- | :--- | :--- |
| **Training Set (80%)** | **92,184** | 78,912 (85.60%) | 13,272 (14.40%) | 1 : 5.95 |
| **Testing Set (20%)** | **23,047** | 19,729 (85.60%) | 3,318 (14.40%) | 1 : 5.94 |
| **Total (100%)** | **115,231** | 98,641 (85.60%) | 16,590 (14.40%) | 1 : 5.95 |

### Class Imbalance Viva Defense:
* The dataset exhibits an imbalance ratio of **~6 : 1** (85.6% benign vs. 14.4% phishing).
* **Why Accuracy is Insufficient:** A trivial dummy classifier that always predicts 0 achieves **85.6% accuracy** while detecting 0 phishing attacks.
* **Evaluation Metrics Mandated:** Model benchmarking in Phase 4 must evaluate:
  1. **Precision:** Out of all URLs predicted as phishing, how many were actually phishing? (Minimizes false alarms on legitimate sites).
  2. **Recall (Sensitivity):** Out of all actual phishing URLs, how many did the system catch? (Minimizes missed cyber threats).
  3. **F1-Score:** Harmonic mean of precision and recall.
  4. **ROC-AUC & PR-AUC:** Discrimination ability across all classification thresholds.
  5. **Confusion Matrix:** Full tabular breakdown of True Positives, False Positives, True Negatives, and False Negatives.

---

## 4. Selected Feature Matrix ($X$) Schema

The feature matrix $X$ consists strictly of the 22 numerical features in the established order:

```text
 1. url_len       7. digit_cnt     13. dash_cnt      19. slash_cnt
 2. dom_len       8. special_cnt   14. under_cnt     20. entropy
 3. is_ip         9. eq_cnt        15. letter_ratio  21. path_len
 4. tld_len      10. qm_cnt        16. digit_ratio   22. query_len
 5. subdom_cnt   11. amp_cnt       17. spec_ratio
 6. letter_cnt   12. dot_cnt       18. is_https
```

All non-feature columns (`url`, `dom`, `tld`) and the target column (`label`) were strictly excluded from $X$.

---

## 5. Generated Artifacts

The processed datasets are saved in `data/processed/`:
* `data/processed/train.csv` (Features + Label, 92,184 rows)
* `data/processed/test.csv` (Features + Label, 23,047 rows)
* `data/processed/X_train.csv` (Features only, shape (92,184, 22))
* `data/processed/X_test.csv` (Features only, shape (23,047, 22))
* `data/processed/y_train.csv` (Labels only, shape (92,184, 1))
* `data/processed/y_test.csv` (Labels only, shape (23,047, 1))
* `data/processed/split_metadata.json` (Full parameter & hash metadata)
