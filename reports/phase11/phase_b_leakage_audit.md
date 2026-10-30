# PhishGuardAI — Phase 11 Phase B: Data Leakage & Evaluation Quality Audit Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase B — Read-Only Investigation: Data Leakage, Partitioning & Generalization Audit  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Evaluated Pipelines:** `src/preprocess.py`, `src/train.py`, `src/domain_validation.py`  
**Preservation Status:** Strictly Read-Only (Zero Retraining, Zero Model Overwrite, Zero Dataset Alteration)  

---

## 1. Executive Summary & Audit Mandate

Investigation 5 conducts an exhaustive evaluation of data leakage, preprocessing integrity, and partitioning methodologies in PhishGuardAI. Machine-learning models for phishing detection frequently report near-perfect test accuracy ($>98\%$) that fails to translate to production environments. This discrepancy is typically caused by three phenomena: exact sample leakage, near-duplicate contamination, and domain overlap.

This audit evaluates the extent to which these phenomena affect PhishGuardAI's baseline model and contrasts the random stratified evaluation with the Phase 8 domain-held-out benchmark.

### Core Audit Discoveries:
1. **Zero Exact URL Leakage:**
   * Direct hash comparison between `train.csv` ($N = 92,184$) and `test.csv` ($N = 23,047$) confirms **exactly 0 identical URL strings appear across both splits**.
2. **Near-Duplicate Contamination Detected (302 URL Pairs):**
   * Normalizing URLs (converting to lowercase, stripping `http://`/`https://`, removing `www.`, and stripping trailing slashes) revealed **302 near-duplicate URL keys shared between training and testing**.
   * These URLs represent identical web resources that differed only by protocol or trailing slash (e.g., `http://cray.com/` in train vs. `https://cray.com/` in test). All 302 share identical labels.
3. **Substantial Domain Overlap in Random Stratified Split (23.78% of Test Data):**
   * **2,120 registered domains (10.84% of test domains)** appear in both training and test sets.
   * **5,480 out of 23,047 test URLs (23.78%)** belong to domains that the model observed during training.
   * Multi-page platforms like `weebly.com` (1,964 in train, 491 in test) and `google.com` (1,165 in train, 285 in test) heavily contaminated the random test split.
4. **Generalization Gap on Unseen Domains (Phase 8 Evidence):**
   * When domain overlap is strictly eliminated ($\text{Train} \cap \text{Test} = \emptyset$), phishing recall drops from **93.19% down to 87.34%**, and missed attacks (False Negatives) nearly double from **226 to 420 missed attacks (+85.8%)**.
   * High random-split accuracy (97.61%) creates an over-optimistic estimate of real-world generalization.

---

## 2. Leakage Dimension 1: Exact and Near-Duplicate URL Overlap

### 2.1 Exact URL Deduplication
* **Implementation:** In `src/preprocess.py`, `deduplicate()` is invoked **before** `train_test_split()`:
  ```python
  df_clean = df.drop_duplicates(subset=["url"], keep="first").copy()
  df_clean = df_clean.reset_index(drop=True)
  X_train, X_test, y_train, y_test = train_test_split(..., stratify=y, random_state=42)
  ```
* **Empirical Verification:**
  * Exact URL intersection: $\text{Train URLs} \cap \text{Test URLs} = \emptyset \quad (\text{Count} = 0)$.
  * Zero exact URLs leaked across the partition.

### 2.2 Near-Duplicate URL Leakage Audit
* **Methodology:** We normalized URL strings across both splits by:
  1. Converting all characters to lowercase.
  2. Stripping protocol schemes (`http://`, `https://`, `//`).
  3. Stripping `www.` prefixes.
  4. Stripping trailing slashes (`/`).
* **Empirical Results:**
  * **302 normalized URL keys** exist in both `train.csv` and `test.csv`.
  * **302 pairs have identical ground-truth labels (100% agreement).**
  * **0 pairs have conflicting labels.**
* **Representative Sample of Leaked Near-Duplicates:**

| Normalized Key | Training URL Instance | Testing URL Instance | Label |
|---|---|---|---|
| `cray.com` | `http://www.cray.com/` | `https://www.cray.com/` | 0 (Legit) |
| `cit.ac.in` | `http://www.cit.ac.in/` | `http://cit.ac.in/` | 0 (Legit) |
| `telefactor-robotics.com` | `https://www.telefactor-robotics.com/` | `http://www.telefactor-robotics.com/` | 0 (Legit) |
| `tungtv1990.github.io` | `http://tungtv1990.github.io` | `https://tungtv1990.github.io/` | 1 (Phish) |
| `allegro.pl-oferta568172.icu` | `https://allegro.pl-oferta568172.icu` | `http://allegro.pl-oferta568172.icu` | 1 (Phish) |
| `id-ionos-de-webmail-...blogspot.com` | `http://id-ionos-de-webmail.../` | `https://id-ionos-de-webmail.../` | 1 (Phish) |

* **Analysis:** Because deduplication in `src/preprocess.py` relied on exact string matching (`subset=["url"]`), minor formatting variations survived deduplication and were randomly assigned to opposite splits.

---

## 3. Leakage Dimension 2: Registered Domain Overlap

### 3.1 Random Stratified Split Domain Exposure
In the conventional 80/20 random stratified split (`data/processed/train.csv` vs. `test.csv`):
* **Training Unique Domains:** 73,423
* **Testing Unique Domains:** 19,557
* **Overlapping Domains:** **2,120 domains** ($10.84\%$ of test domains)
* **Test Sample Exposure:** **5,480 out of 23,047 test URLs (23.78%)** belong to domains present in the training set.

### 3.2 Concentration in Multi-Page Platforms
Ten large hosting and link-shortening platforms contributed thousands of samples across both partitions:

| Registered Domain | Total URLs in Dataset | Training Count | Testing Count | Class Distribution |
|---|---|---|---|---|
| `weebly.com` | 2,455 | 1,964 | 491 | 2,444 Phishing, 11 Legitimate |
| `google.com` | 1,450 | 1,165 | 285 | 1,439 Phishing, 11 Legitimate |
| `pages.dev` | 1,050 | 838 | 212 | 1,050 Phishing (100%) |
| `bit.ly` | 763 | 609 | 154 | 763 Phishing (100%) |
| `hsforms.com` | 358 | 287 | 71 | 358 Phishing (100%) |
| `qrco.de` | 329 | 267 | 62 | 329 Phishing (100%) |
| `r2.dev` | 240 | 203 | 37 | 240 Phishing (100%) |
| `va.gov` | 219 | 170 | 49 | 219 Legitimate (100%) |
| `q-r.to` | 212 | 174 | 38 | 212 Phishing (100%) |
| `wixsite.com` | 160 | 124 | 36 | 150 Phishing, 10 Legitimate |

### 3.3 The Problem of Dual-Label Shared Platforms
We audited whether any domains in the dataset host both legitimate and phishing URLs:
* Exactly **24 registered domains** contain both Class 0 and Class 1 URLs.
* When a model is trained on `weebly.com` where 99.5% of URLs are phishing, decision trees learn that `dom_len = 10` is an indicator of phishing. When an innocent legitimate URL on `weebly.com` appears in the test set, it is misclassified with $1.00$ probability.

---

## 4. Leakage Dimension 3: Preprocessing & Feature Selection

We inspected all data transformations for potential test-set information leakage:
1. **Feature Engineering Independence:**
   * Features were fixed *a priori* based on the Linh & Hung (2025) feature catalog.
   * No data-driven feature selection (e.g., SelectKBest, Lasso regularization, PCA) was fitted across the combined dataset.
2. **Scaler & Normalization Independence:**
   * The Random Forest model operates directly on unscaled numerical features; decision trees branch on raw thresholds.
   * For the baseline Logistic Regression model, `StandardScaler` was placed inside a `sklearn.pipeline.Pipeline` that was fitted strictly on `X_train`, preventing test variance or mean leakage.
3. **Target Isolation:**
   * Reference text columns (`url`, `dom`, `tld`) and ground truth labels (`label`) are strictly excluded from the feature matrix $X$.
   * Zero target leakage was detected.

---

## 5. Random-Split vs. Domain-Held-Out Evaluation Comparison

To distinguish ordinary random-split performance from true out-of-distribution generalization, we compared the baseline Random Forest (Phase 5) against the Phase 8 domain-held-out experiment:

| Evaluation Dimension | Random Stratified Split (Phase 5) | Domain-Held-Out Split (Phase 8) | Generalization Shift | Assessment |
|---|---|---|---|---|
| **Domain Overlap** | **2,120 domains (10.84%)** | **0 domains (Strictly Zero)** | $-2,120$ shared domains | Leakage Eliminated |
| **Test Sample Size** | 23,047 | 23,045 | $-2$ samples | Identical Scale |
| **Phishing Test Samples** | 3,318 | 3,318 | Exact match | Perfect Basis for Comparison |
| **Legitimate Test Samples** | 19,729 | 19,727 | $-2$ samples | Near-identical |
| **Accuracy** | **97.61%** | **96.77%** | $-0.84\%$ | Appears minor |
| **Phishing Precision** | **90.52%** | **89.94%** | $-0.58\%$ | Specificity remains robust |
| **Phishing Recall** | **93.19%** | **87.34%** | **-5.85% (Significant Drop)** | **Recall degraded on unseen sites** |
| **Phishing F1-Score** | **91.83%** | **88.62%** | **-3.21%** | Realistic performance drop |
| **False Positives (FP)** | **324** | **324** | **0 (Identical)** | False alarms do not increase |
| **False Negatives (FN)** | **226** | **420** | **+194 Missed Attacks (+85.8%)** | **Critical Security Vulnerability** |
| **ROC-AUC** | 0.9913 | 0.9826 | $-0.0087$ | Moderate drop |
| **PR-AUC** | 0.9716 | 0.9286 | $-0.0430$ | Noticeable drop in minority class AUC |

### Critical Evaluation Insights:
1. **Random-Split Accuracy is Over-Optimistic:**
   * A 97.61% random-split accuracy overstates real-world efficacy because 23.78% of test URLs belong to familiar domains.
2. **The True Generalization Vulnerability is False Negatives, Not False Positives:**
   * When evaluating completely unseen domains, the model's False Positive count remained identical ($FP = 324$).
   * However, missed phishing attacks jumped from 226 up to **420**. Threat actors deploying phishing lures on fresh, short, newly registered domains evade lexical heuristic thresholds.

---

## 6. Evidentiary Distinctions

* **Verified Facts from Actual Files:** Exact URL overlap is 0. 302 near-duplicate URLs exist across train and test. Domain overlap in the random split is 2,120 domains (23.78% of test samples).
* **Measured Results:** On domain-held-out evaluation, False Negatives increase from 226 to 420, while False Positives remain at 324.
* **Hypotheses Needing Further Testing:** Incorporating registrar age or domain reputation features in future phases will address the 420 missed attacks without worsening the false positive rate.
* **Limitations:** Grouping by registrable domain (`dom`) forces multi-tenant platforms (e.g., `pages.dev`) entirely into either train or test, which can create class distribution imbalances for shared-hosting platforms.
