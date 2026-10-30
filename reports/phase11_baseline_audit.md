# PhishGuardAI — Phase 11 Phase A: Read-Only Baseline Audit Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase A — Read-Only Baseline Audit  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Target URL Under Investigation:**  
`https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`  
**Preservation Status:** Strictly Read-Only (Zero Retraining, Zero Model Modification, Zero Overwrites)

---

## 1. Executive Summary & Verification Mandate

The user reported that the production application classified the legitimate YouTube playlist lecture link:
`https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`
as **PHISHING** with approximately **94% probability**.

In accordance with strict verification directives, this audit verified that claim empirically against the production model (`models/phishing_model.joblib`), inspected the full 22-feature vector, audited the individual decision trees of the Random Forest ensemble, traced the probability pipeline from model inference to database and frontend rendering, and audited the baseline training dataset and model metadata.

### Core Audit Findings:
1. **The 94% Phishing Claim is Empirically Verified (Exact: 94.0000%):**
   * The production Random Forest model classifies the target YouTube URL as **Class 1 (PHISHING)** with a predicted phishing probability of **0.940000 (94.00%)** and legitimate probability of **0.060000 (6.00%)**.
2. **Individual Tree Vote Equivalence:**
   * Across the 100 decision trees in `models/phishing_model.joblib`, **exactly 94 trees voted 1 (PHISHING)** and **exactly 6 trees voted 0 (LEGITIMATE)**.
   * Because decision trees in the ensemble have pure leaf nodes (Gini impurity = 0), each tree outputs a binary probability (1.0 or 0.0). The model's `predict_proba` output equals the exact fraction of trees voting for phishing: $\frac{94}{100} = 0.9400$.
3. **Frontend Display Pipeline:**
   * In `app.py` (`POST /api/scan`), `phishing_prob = float(probabilities[0][1])` ($0.94$) is evaluated against `decision_threshold = 0.5`. Since $0.94 \ge 0.50$, `verdict = "phishing"` and `confidence_percent = round(0.94 * 100.0, 2) = 94.0%`.
   * The scan history table (`static/js/app.js`) renders `(record.phishing_probability * 100).toFixed(2) + '%' = "94.00%"`.
4. **Primary Root Cause:**
   * The YouTube URL contains structural tokens (`entropy = 5.47`, `query_len = 61`, `digit_ratio = 0.066`, `is_https = 1`, `url_len = 91`) that match the statistical profile of phishing exploit kits in the training dataset, where 98% of benign URLs have zero query parameters and average entropy is only 3.79.
5. **Production Model Integrity & Checksum:**
   * Model file: `models/phishing_model.joblib`
   * Size: 51,777,896 bytes
   * SHA-256: `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` (100% verified and unmodified).

---

## 2. 22 Extracted Features for the Target YouTube URL

The URL was processed through the production `URLFeatureExtractor` (`src/feature_extraction.py`). All 22 numerical features were extracted strictly offline with zero network requests:

| # | Feature Name | Extracted Value | Benign Dataset Mean | Phishing Dataset Mean | Anomaly Direction |
|---|---|---|---|---|---|
| 1 | `url_len` | **91** | 29.10 | 56.31 | Over 3× higher than benign average |
| 2 | `dom_len` | **11** (`youtube.com`) | 13.02 | 11.84 | Typical domain length |
| 3 | `is_ip` | **0** | 0.0001 | 0.0004 | Standard domain name |
| 4 | `tld_len` | **3** (`com`) | 3.39 | 2.91 | Standard top-level domain |
| 5 | `subdom_cnt` | **1** (`www`) | 0.86 | 0.73 | Standard single subdomain |
| 6 | `letter_cnt` | **72** | 22.28 | 41.56 | Over 3× higher than benign average |
| 7 | `digit_cnt` | **6** (`9`, `3`, `4`, `0`, `2`, `4`) | 0.15 | 5.76 | **40× higher than benign average** |
| 8 | `special_cnt` | **13** (`:`, `/`, `/`, `.`, `.`, `/`, `?`, `=`, `&`, `=`, `-`, `&`, `=`) | 6.67 | 9.00 | Elevated special characters |
| 9 | `eq_cnt` | **3** (`=`) | 0.03 | 0.40 | **100× higher than benign average** |
| 10 | `qm_cnt` | **1** (`?`) | 0.02 | 0.15 | **50× higher than benign average** |
| 11 | `amp_cnt` | **2** (`&`) | 0.01 | 0.24 | **200× higher than benign average** |
| 12 | `dot_cnt` | **2** | 2.19 | 1.93 | Normal (2 dots in `www.youtube.com`) |
| 13 | `dash_cnt` | **1** (inside playlist ID) | 0.24 | 0.94 | Elevated (hyphen in parameter) |
| 14 | `under_cnt` | **0** | 0.03 | 0.22 | Normal |
| 15 | `letter_ratio`| **0.7912** (79.12%) | 0.7543 | 0.7418 | Typical letter proportion |
| 16 | `digit_ratio` | **0.0659** (6.59%) | 0.0031 (0.31%) | 0.0738 (7.38%) | **21× higher than benign average** |
| 17 | `spec_ratio`  | **0.1429** (14.29%) | 0.2426 | 0.1844 | Typical special character ratio |
| 18 | `is_https`    | **1** | 0.3494 (34.94%) | 0.9143 (91.43%) | **Matches phishing class bias** |
| 19 | `slash_cnt`   | **3** | 3.15 | 3.62 | Normal |
| 20 | `entropy`     | **5.4733** | 3.7888 | 4.3163 | **Highest entropy bracket (> 99th percentile)** |
| 21 | `path_len`    | **6** (`/watch`) | 4.62 | 17.16 | Normal path length |
| 22 | `query_len`   | **61** | 0.3111 | 9.3854 | **200× higher than benign average** |

---

## 3. Production Model Inference & Tree Ensemble Breakdown

### 3.1 Model Prediction Details
* **Model Class:** `sklearn.ensemble.RandomForestClassifier` (100 estimators, balanced class weights, seed 42)
* **Input Vector:**
  $$X = [91, 11, 0, 3, 1, 72, 6, 13, 3, 1, 2, 2, 1, 0, 0.7912, 0.0659, 0.1429, 1, 3, 5.4733, 6, 61]$$
* **Decision Threshold:** $\tau = 0.50$ (standard default)
* **Predicted Class:** **Class 1 (PHISHING)**
* **Predicted Probability Vector:**
  $$P(\text{Class } 0 \mid X) = 0.060000 \quad (6.00\% \text{ Legitimate})$$
  $$P(\text{Class } 1 \mid X) = 0.940000 \quad (94.00\% \text{ Phishing})$$

### 3.2 Individual Decision Tree Voting Analysis
In `RandomForestClassifier`, each decision tree $T_b$ ($b = 1, \dots, 100$) recursively splits feature space until leaves are pure. We evaluated the tree-level outputs without modifying the model artifact:

```text
Total Estimators in Ensemble : 100 Decision Trees
Trees Voting 0 (Legitimate) :   6 trees  ( 6.0%)
Trees Voting 1 (Phishing)   :  94 trees  (94.0%)
Mean Tree Prediction Probability: 0.940000 (94.00%)
predict_proba Output        : 0.940000 (94.00%)
```

* **Verification of Probability Origin:** The displayed 94% probability is **mathematically identical to the fraction of individual trees voting for phishing**. 94 separate trees independently traced decision paths that terminated in leaf nodes dominated by phishing samples.

### 3.3 Top Model Features and Their Influence on this Prediction

According to the production model's Gini importance rankings:
1. **`is_https` (Importance: 15.55% — Rank #1):**
   * Value: `1`. In the training dataset, 91.43% of phishing URLs used HTTPS, whereas only 34.94% of benign URLs used HTTPS. This feature consistently branches toward the phishing sub-tree.
2. **`entropy` (Importance: 14.20% — Rank #2):**
   * Value: `5.4733`. The benign mean is 3.79; the 99th percentile of benign URLs is 4.50. An entropy of 5.47 lands in the upper 0.1% of all URLs in the dataset. Random Forest trees branch heavily toward phishing at entropy thresholds around $\approx 4.1 - 4.4$.
3. **`digit_ratio` (Importance: 9.92% — Rank #3):**
   * Value: `0.0659`. The benign mean is 0.0031. Over 95% of benign URLs in the dataset had zero digits. Having 6.6% digits in the URL pushes tree branches into phishing leaves.
4. **`query_len` (Importance: 2.62%):**
   * Value: `61`. The benign mean is 0.31 (97.99% of benign URLs had `query_len = 0`). The presence of a 61-character query string with 3 equal signs and 2 ampersands strongly reinforces the phishing vote.

---

## 4. Frontend & API Pipeline Trace

We audited how the backend computes the score and how the dashboard displays it:

1. **Client Submission:** User enters `https://www.youtube.com/watch?v=...` and clicks **Analyze URL**.
2. **Backend Route (`POST /api/scan` in `app.py`):**
   ```python
   feature_dict = extractor.extract_features(clean_url)
   df_input = pd.DataFrame([feature_vector], columns=extractor.FEATURE_NAMES)
   probabilities = model.predict_proba(df_input)
   phishing_prob = float(probabilities[0][1])  # 0.94000
   
   if phishing_prob >= 0.5:
       verdict = "phishing"
       confidence_pct = round(phishing_prob * 100.0, 2)  # 94.0
   ```
3. **Database Persistence (`src/database.py`):**
   * The record is written to `data/scan_history.db` with `phishing_probability = 0.94` and `confidence_percent = 94.0`.
4. **Frontend Rendering (`static/js/app.js`):**
   * `renderScanResult()` displays the animated probability meter at `94%` with a red danger gradient.
   * `renderHistoryTable()` displays `(record.phishing_probability * 100).toFixed(2) + '%' = "94.00%"`.
   * **Conclusion:** The frontend accurately reflects the raw machine learning model output without alteration or hardcoded logic.

---

## 5. Dataset Definitions, Data Split, and Known Discrepancy

### 5.1 Label Definitions and Data Split
* **Target Label Definition:**
  * `0`: Legitimate / Benign URL (Safe).
  * `1`: Phishing URL (Malicious).
* **Train / Test Partitioning:**
  * Clean deduplicated dataset: **115,231 samples** (98,641 Legitimate [85.60%], 16,590 Phishing [14.40%]).
  * Stratified 80/20 train/test split with `random_state=42`:
    * Training Set (`X_train.csv`, `y_train.csv`): **92,184 samples** (78,912 Legitimate, 13,272 Phishing).
    * Test Set (`X_test.csv`, `y_test.csv`): **23,047 samples** (19,729 Legitimate, 3,318 Phishing).

### 5.2 Documentation vs. Local CSV Discrepancy Audit
The Mendeley Data publication (*URL-Phish: Dam Minh Linh & Tran Cong Hung, 2025*) documents:
* Documented total records: **111,660** (100,000 Benign, 11,660 Phishing).
* Local file `dataset/Dataset.csv`: **116,600 rows** (100,000 Benign, 16,600 Phishing).
* **Audit Findings:**
  1. The local CSV contains **exactly 4,940 additional phishing records** compared to the original Mendeley paper abstract.
  2. The local CSV contains **1,369 duplicate URL rows** (all exact duplicates with identical labels).
  3. Deduplication reduces the raw 116,600 rows to **115,231 unique URLs** (98,641 Benign, 16,590 Phishing).
  4. There are **zero conflicting labels** across the entire dataset.

---

## 6. Production Model Performance Benchmark & Checksum

Recorded metrics from `models/models_metadata.json` and `reports/model_evaluation_report.md`:

| Metric | Random Forest Baseline | Logistic Regression Baseline |
|---|---|---|
| **Accuracy** | **97.61%** | 92.80% |
| **Phishing Precision** | **90.52%** | 68.63% |
| **Phishing Recall** | **93.19%** | 92.04% |
| **Phishing F1-Score** | **91.83%** | 78.63% |
| **Macro F1-Score** | **95.22%** | 87.15% |
| **ROC-AUC** | **0.9913** | 0.9766 |
| **PR-AUC** | **0.9716** | 0.8982 |
| **Confusion Matrix** | $\mathbf{TN = 19,405}$, $\mathbf{FP = 324}$, $\mathbf{FN = 226}$, $\mathbf{TP = 3,092}$ | $TN = 18,333$, $FP = 1,396$, $FN = 264$, $TP = 3,054$ |

* **Production Model Checksum:**
  * File: `models/phishing_model.joblib`
  * SHA-256: `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` (Confirmed Unmodified).

---

## 7. Phase A Conclusion & Readiness for Phase B

Phase A confirms that the 94% phishing classification is an authentic artifact of the production model's decision logic, caused by structural feature overlap with phishing samples. With the baseline fully documented and zero files modified, the project is ready to proceed to Phase B (Data Quality and False Positive Investigation).
