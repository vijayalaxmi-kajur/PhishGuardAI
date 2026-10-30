# PhishGuardAI — Phase 11 Phase B: Dataset Quality & Verification Audit Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase B — Read-Only Investigation: Dataset Quality, Representation & Integrity  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Preservation Status:** Strictly Read-Only (Zero Retraining, Zero Model Overwrite, Zero Dataset Alteration)  

---

## 1. Executive Summary & Audit Mandate

The primary objective of Investigation 1 is to locate, inspect, and verify the physical dataset files used to train and evaluate PhishGuardAI. Previous documentation and academic citations reported conflicting sample counts (e.g., 111,660 in original publication abstracts vs. 116,600 in raw files vs. 115,231 in clean processed files). 

In accordance with strict read-only audit directives, all metrics, file hashes, row counts, label distributions, missing value counts, duplicate rows, and structural block boundaries were measured programmatically from the physical files on disk without modifying any files.

---

## 2. Physical File Verification & Cryptographic Integrity

All physical data and model files were verified using file size checks and SHA-256 cryptographic digests:

| File Role | Exact File Path | Size (Bytes) | SHA-256 Digest | Verification Status |
|---|---|---|---|---|
| **Raw Baseline Dataset** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\dataset\Dataset.csv` | 15,149,338 | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | Verified (Exact Match) |
| **Deduplicated Training Split** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\train.csv` | 7,336,041 | `db6360640510ea2b30b6b8449e06edaca14be4e8784573e3dce21fa3c5ab4294` | Verified (Exact Match) |
| **Deduplicated Testing Split** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\test.csv` | 1,834,913 | `8764066a97ec387126aa40f961d0bd6fdf6d045c344b7a93dd5df87f017e1955` | Verified (Exact Match) |
| **Training Feature Matrix** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\X_train.csv` | 7,151,667 | `a6595975c9d150880a351ce545e53de2ae19a7c7e6f7a7958af967982919362f` | Verified (Exact Match) |
| **Testing Feature Matrix** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\X_test.csv` | 1,788,813 | `71c2beb3449c1947bec20a6e3d44f04405d32b30de7d88a66b8b9eaefb7ea2cc` | Verified (Exact Match) |
| **Training Labels Vector** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\y_train.csv` | 276,559 | `009e4b9dcf61d71070d91492704d447d161f7309b9f4f10e677892b6d98d6b87` | Verified (Exact Match) |
| **Testing Labels Vector** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\y_test.csv` | 69,148 | `4303dc0e2a3745a7d0a7523181af8cee8cd4cfe4bab55dd409499b559a2c14ed` | Verified (Exact Match) |
| **Split Metadata Record** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\data\processed\split_metadata.json` | 1,319 | `bd09e42ab78afe9b049b7aa1f868ad58bf4e8574d6fba5f7d26c5991807d9b75` | Verified (Exact Match) |
| **Production Model Artifact** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\models\phishing_model.joblib` | 51,777,896 | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | Verified (Exact Match) |
| **Random Forest Baseline** | `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\models\random_forest.joblib` | 51,777,896 | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | Identical to production |
| **Logistic Regression Baseline**| `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\models\logistic_regression.joblib` | 3,677 | `fa5e785ce2fd5e60a1e70d526a060e840d0e51d2a50fc6570c73d41c9e25cc55` | Verified (Exact Match) |

---

## 3. Dataset Schema, Columns, and Label Definitions

### 3.1 Schema Dimensions
* **Total Rows in Raw CSV:** **116,600 rows**
* **Total Columns in Raw CSV:** **26 columns**
* **Target Label Column:** `label` (Integer `0` or `1`)

### 3.2 Label Definitions and Ground Truth Meaning
* **Class `0` — Legitimate / Benign Web Addresses:**
  * Count in raw file: **100,000 samples (85.76%)**
  * Sourced primarily from academic institutions, government portals, and established commercial domains (e.g., top Tranco / Alexa domains).
  * Represents benign web navigation.
* **Class `1` — Phishing / Malicious Web Addresses:**
  * Count in raw file: **16,600 samples (14.24%)**
  * Sourced from active cyber threat feeds (e.g., PhishTank, OpenPhish) targeting credential theft, financial deception, and account takeovers.
  * Represents confirmed malicious URLs.

### 3.3 Complete Column List (26 Columns)
1. Reference Text Columns (3): `url` (raw string), `dom` (registered domain), `tld` (top-level domain suffix)
2. Numerical Feature Columns (22): `url_len`, `dom_len`, `is_ip`, `tld_len`, `subdom_cnt`, `letter_cnt`, `digit_cnt`, `special_cnt`, `eq_cnt`, `qm_cnt`, `amp_cnt`, `dot_cnt`, `dash_cnt`, `under_cnt`, `letter_ratio`, `digit_ratio`, `spec_ratio`, `is_https`, `slash_cnt`, `entropy`, `path_len`, `query_len`
3. Target Column (1): `label`

---

## 4. Missing Values, Duplicates, and Data Anomalies

### 4.1 Missing / Null Value Audit
* **Columns with Missing Values:** Exactly **1 column** (`tld`) has missing entries:
  * `tld` missing count: **14 rows (0.012%)**
  * **13 of these 14 rows** correspond to IP-address hostnames (e.g., `http://202.194.232.100:8005/...`, `https://43.133.3.131/...`). Because raw IP addresses do not have a public suffix, `tld` is correctly null, `tld_len = 0`, and `is_ip = 1`.
  * **1 row** (`https://www.ucatolica.edu.coeasyweb/`) contains a malformed path delimiter where the public suffix boundary was merged with the path string.
* **Numerical Features Missing Count:** **0 nulls** across all 22 numerical features.
* **Label Missing Count:** **0 nulls**. Every single row has an explicit integer label (`0` or `1`).

### 4.2 Duplicate Rows and URLs Audit
* **Exact Duplicate Rows across all 26 columns:** Exactly **1,369 rows** are identical copies of other rows.
* **Duplicate URL Rows:** Exactly **1,369 rows**. Every duplicate URL in the dataset is identical across all feature columns.
* **Unique URLs:** **115,231 unique URLs**.
* **Duplicates by Class:**
  * Class 0 (Legitimate): 2,356 duplicate rows representing **1,359 redundant entries** removed during deduplication.
  * Class 1 (Phishing): 20 duplicate rows representing **10 redundant entries** removed during deduplication.
* **Conflicting Labels:** **Exactly 0 conflicting URLs**. There is not a single URL in the entire dataset that is assigned both label 0 and label 1.

### 4.3 Malformed & Invalid URL Checks
* Every URL in `Dataset.csv` was parsed with `urllib.parse.urlparse`.
* **RFC Netloc Validity:** **116,600 out of 116,600 URLs (100.0%)** contain a non-empty, parseable network location (`netloc`).
* **Non-string or empty URLs:** **0**.

---

## 5. Merged Dataset Structure Analysis

An inspection of row indices and label transitions revealed how the dataset was constructed:

```text
Row Range               Count     Label   Description
[0       : 99,999]     100,000      0     Contiguous block of Legitimate URLs
[100,000 : 111,659]     11,660      1     Original Block of Phishing URLs (Mendeley Version 1)
[111,660 : 116,599]      4,940      1     Appended Supplemental Block of Phishing URLs
```

### Analysis of the Block Structure:
1. **The dataset was created by merging distinct contiguous sources**, not by uniform random sampling.
2. The first 100,000 rows are 100% benign URLs.
3. Rows 100,000 to 111,659 (11,660 rows) correspond exactly to the original peer-reviewed publication abstract count (*URL-Phish: Linh & Hung, 2025*), which reported 111,660 total records.
4. Rows 111,660 to 116,599 consist of an additional **4,940 verified phishing URLs** appended to the end of the file.
5. This appended block increased phishing representation from 10.4% (11,660 / 111,660) to 14.2% (16,600 / 116,600), improving minority class sample size.

---

## 6. Reconciliation of Reported Row Counts

Past reports in the repository cited varying sample sizes depending on the pipeline stage. The table below reconciles every reported number directly to its file source and data transformation:

| Reported Count | Stage / Context | Exact File Source | Mathematical Explanation | Verified Status |
|---|---|---|---|---|
| **111,660** | Mendeley Paper Abstract | Citation abstract (Linh & Hung, 2025) | 100,000 Benign + 11,660 Phishing in initial publication release. | Verified |
| **116,600** | Raw Local CSV | `dataset/Dataset.csv` | 100,000 Benign + 16,600 Phishing (includes 4,940 extra phishing rows). | Verified |
| **115,231** | Clean Deduplicated Set | In-memory clean dataset (`src/preprocess.py`) | $116,600 - 1,369 \text{ duplicates} = 115,231$ (98,641 Benign, 16,590 Phishing). | Verified |
| **92,184** | 80% Random Train Split | `data/processed/train.csv`, `X_train.csv` | Stratified 80% split of 115,231: 78,912 Benign (85.6%) + 13,272 Phishing (14.4%). | Verified |
| **23,047** | 20% Random Test Split | `data/processed/test.csv`, `X_test.csv` | Stratified 20% split of 115,231: 19,729 Benign (85.6%) + 3,318 Phishing (14.4%). | Verified |
| **92,186** | 80% Domain-Held-Out Train | `models/experiments/` (Phase 8) | StratifiedGroupKFold 80% split: 78,914 Benign (85.6%) + 13,272 Phishing (14.4%). | Verified |
| **23,045** | 20% Domain-Held-Out Test | `models/experiments/` (Phase 8) | StratifiedGroupKFold 20% split: 19,727 Benign (85.6%) + 3,318 Phishing (14.4%). | Verified |
| **90,860** | Unique Registered Domains | Clean dataset domain count (`dom`) | Number of distinct registered domains across the 115,231 unique URLs. | Verified |

---

## 7. Investigation 1 Findings Summary

| Audit Item | Measured Value | Standard / Expectation | Compliance Assessment |
|---|---|---|---|
| **Raw Dataset Path** | `dataset/Dataset.csv` | Documented repository location | Compliant |
| **Raw Sample Size** | 116,600 rows, 26 cols | $\ge 111,660$ rows | Fully Verified |
| **Clean Sample Size** | 115,231 rows | Exact deduplication | Fully Verified |
| **Class Distribution (Raw)** | 100,000 Legit (85.76%) / 16,600 Phish (14.24%) | Binary 0 and 1 | Clean, 6.02:1 Imbalance |
| **Class Distribution (Clean)**| 98,641 Legit (85.60%) / 16,590 Phish (14.40%) | Binary 0 and 1 | Clean, 5.95:1 Imbalance |
| **Missing Values** | 14 in `tld` (13 IP hosts, 1 delimiter error); 0 in features | No missing feature data | Fully Verified |
| **Conflicting Labels** | **0 conflicting URLs** | Zero tolerance | Flawless Consistency |
| **Invalid Netloc URLs** | **0 malformed hostnames** | Parseable RFC structure | 100% Valid |

---

## 8. Evidentiary Distinctions

* **Verified Facts from Actual Files:** The raw dataset contains exactly 116,600 rows and 26 columns. Deduplication produces 115,231 clean rows. There are zero conflicting labels and zero missing numerical features.
* **Measured Results:** Class imbalance is 85.60% legitimate to 14.40% phishing in the clean dataset. 1,369 duplicates were removed before splitting.
* **Hypotheses Needing Further Testing:** The contiguous block structure (100k benign followed by 16.6k phishing) suggests benign samples were crawled from top-level landing pages, which may explain the low presence of query strings.
* **Limitations:** The raw dataset does not include original collection timestamps or crawler crawl depths, limiting direct reconstruction of original crawl configurations.
