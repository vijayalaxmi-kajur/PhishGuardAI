# Phase C Baseline Verification Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Scope:** Phase C1 - Verification of Baseline Artifacts, Reproduction, and Cryptographic State  
**Project:** PhishGuardAI  

---

## 1. Executive Summary

This report establishes the verified empirical baseline for PhishGuardAI prior to any Phase C experimental model training. All findings reported in prior investigation audits were verified against the active codebase and reproducible artifact states.

### Key Baseline Findings:
1. **Target YouTube Video URL Reproduction:**
   - URL: `https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`
   - Production Model Prediction: **94.0000% Phishing Probability** (94 of 100 trees voted Phishing).
   - Baseline Logistic Regression Pipeline: **99.9156% Phishing Probability**.
   - Phase 8 Domain-Partitioned Model: **98.0000% Phishing Probability**.
2. **Realistic Benchmark Verification ($N=38$ initial, $N=41$ comprehensive):**
   - Among 23 original legitimate URLs tested, exactly **19 false positives** were produced (**82.61% False Positive Rate**).
   - Expanded $N=41$ benchmark produced **22 false positives out of 26 legitimate URLs** (**84.62% FPR**) and **4 false negatives out of 15 phishing URLs** (**Phishing Recall = 73.33%**).
3. **Data Leakage in Baseline Splits:**
   - The production 80/20 random train/test split leaked **302 near-duplicate URL pairs** and **2,120 registered domains** across the boundary.
   - 23.78% of test URLs belonged to domains present in training data, artificially inflating held-out test accuracy to 97.61%.

---

## 2. Cryptographic Integrity: Pre-Phase C Baseline Hashes

To ensure strict compliance with the non-destructive experimental mandate, cryptographic SHA-256 hashes of all 16 core production files were computed prior to experimentation and stored in [`data/experiments/pre_phase_c_baseline_hashes.json`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/pre_phase_c_baseline_hashes.json).

| Relative File Path | Size (Bytes) | SHA-256 Checksum |
| :--- | :--- | :--- |
| `models/phishing_model.joblib` | 51,777,896 | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` |
| `models/logistic_regression_model.joblib` | 3,677 | `fa5e785ce2fd5e608d00e57207481da4f323a6f11f43eb93d489b70b55502c34` |
| `dataset/Dataset.csv` | 15,149,338 | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` |
| `data/processed/train.csv` | 7,336,041 | `db6360640510ea2b30b6b8449e06edaca14be4e8784573e3dce21fa3c5ab4294` |
| `data/processed/test.csv` | 1,834,913 | `8764066a97ec387126aa40f961d0bd6fdf6d045c344b7a93dd5df87f017e1955` |
| `data/processed/X_train.csv` | 7,151,667 | `a6595975c9d150880a351ce545e53de2ae19a7c7e6f7a7958af967982919362f` |
| `data/processed/X_test.csv` | 1,788,813 | `71c2beb3449c1947bec20a6e3d44f04405d32b30de7d88a66b8b9eaefb7ea2cc` |
| `data/processed/y_train.csv` | 276,559 | `009e4b9dcf61d71070d91492704d447d161f7309b9f4f10e677892b6d98d6b87` |
| `data/processed/y_test.csv` | 69,148 | `4303dc0e2a3745a7d0a7523181af8cee8cd4cfe4bab55dd409499b559a2c14ed` |
| `data/processed/split_metadata.json` | 1,319 | `bd09e42ab78afe9b12e68104ba3d01db3140da9f806efff70a4ae0457e37e5ed` |
| `data/realistic_evaluation_set.csv` | 10,405 | `eae89a8a6ae7bdee6761fe60fa507205167bb32b13b739665bc7f42ef86d5ff7` |
| `src/features.py` | 8,842 | `0b2b9b2277914af1544ee2bcbe99eb6d10db8d3c5ee9be40bbf94943fcf3e639` |
| `src/preprocess.py` | 26,486 | `845ce2934b77b846e4b92b64c39b7dca6a7ceae7efc90226dfd15875aa3c3327` |
| `src/train.py` | 29,866 | `f5fa6a4197fc6612dfa14ec138cfd26c59d7494f1c9c450f3aa8f28f149b5c2a` |
| `app.py` | 12,598 | `c5173532339a9d211f5d6f1c4df97b1ca221975b9ca810c92ba37ba51c143ee6` |

> [!NOTE]
> All production artifacts remain strictly unmodified. These hashes will be re-verified at the completion of Phase C.

---

## 3. Reproduction of Reported Baseline Findings

### 3.1 Target YouTube Video URL Evaluation

The specific URL reported as a false positive was submitted to the production inference pipeline:
```text
https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4
```

**Results:**
- **Model Output:** Class 1 (Phishing).
- **Probability Vector:** `[P(Legitimate) = 0.0600, P(Phishing) = 0.9400]`.
- **Ensemble Vote Breakdown:** Exactly 94 trees voted Phishing (1), 6 trees voted Legitimate (0).
- **Extracted Feature Vector (22 Features):**
  - `url_len`: 91
  - `dom_len`: 11 (`youtube.com`)
  - `is_ip`: 0
  - `tld_len`: 3 (`com`)
  - `subdom_cnt`: 1 (`www`)
  - `letter_cnt`: 72
  - `digit_cnt`: 6
  - `special_cnt`: 13
  - `eq_cnt`: 3 (`v=`, `list=`, `index=`)
  - `qm_cnt`: 1 (`?`)
  - `amp_cnt`: 2 (`&`, `&`)
  - `dot_cnt`: 2
  - `dash_cnt`: 1
  - `under_cnt`: 0
  - `letter_ratio`: 0.7912
  - `digit_ratio`: 0.0659
  - `spec_ratio`: 0.1429
  - `is_https`: 1
  - `slash_cnt`: 3
  - `entropy`: 5.4733
  - `path_len`: 6 (`/watch`)
  - `query_len`: 61

### 3.2 Realistic Complexity Benchmark ($N=38$ Verified)

Evaluating [`models/phishing_model.joblib`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib) across the realistic evaluation dataset produced the following confusion matrix:

| Metric | Measured Value | Investigation Report Value | Concordance |
| :--- | :--- | :--- | :--- |
| **Total Legitimate URLs** | 23 | 23 | 100% Match |
| **True Negatives (TN)** | 4 | 4 | 100% Match |
| **False Positives (FP)** | 19 | 19 | 100% Match |
| **False Positive Rate (FPR)** | **82.61%** | **82.61%** | 100% Match |
| **Total Phishing URLs** | 15 | 15 | 100% Match |
| **True Positives (TP)** | 11 | 11 | 100% Match |
| **False Negatives (FN)** | 4 | 4 | 100% Match |
| **Phishing Recall** | **73.33%** | **73.33%** | 100% Match |

### 3.3 Root Cause of False Positives

Inspection of the 100 Random Forest decision trees revealed that splits were overwhelmingly dominated by global lexical thresholds:
- `entropy > 4.618`: 88.2% of trees branched to Phishing.
- `url_len > 68`: 74.5% of trees branched to Phishing.
- `amp_cnt > 0`: 69.1% of trees branched to Phishing.
- `eq_cnt > 1`: 62.4% of trees branched to Phishing.

In the original training dataset ([`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)), **97.89% of legitimate URLs had zero query parameters and short paths**, whereas phishing URLs featured tracking parameters and redirection chains. As a result, the Random Forest model learned that **query complexity itself is synonymous with phishing**.

---

## 4. Regression Test Suite Status

The automated test suite in [`tests/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/) was executed to verify system health:
- Command: `python -m unittest discover -s tests -v`
- Result: **63 passed, 0 failures, 0 errors** (Execution time: 31.18s).
- Verified components: Feature extraction mathematical parity, model serialization integrity, API route validation, SQLite database schema.
