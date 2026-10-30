# PhishGuardAI — Phase 11 Phase B: URL Complexity & Feature Distribution Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase B — Read-Only Investigation: URL Complexity, Distribution & Sampling Bias  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Dataset Analyzed:** `dataset/Dataset.csv` (115,231 clean unique URLs)  
**Preservation Status:** Strictly Read-Only (Zero Retraining, Zero Model Overwrite, Zero Dataset Alteration)  

---

## 1. Executive Summary & Diagnostic Scope

Investigation 2 provides an empirical analysis of structural URL complexity across both classes (Legitimate vs. Phishing). The investigation focuses on whether legitimate URLs with long query strings, video identifiers, tracking tokens, pagination, and dynamic parameters are adequately represented in the training data, and whether their scarcity creates an inductive bias that causes legitimate complex URLs to be misclassified as phishing.

### Core Empirical Findings:
1. **Severe Benign Query String Underrepresentation:**
   * **97.99% of legitimate URLs (96,660 / 98,641)** have **zero query string (`query_len = 0`)**.
   * Only **2.01% of legitimate URLs (1,981 / 98,641)** contain any query string whatsoever.
   * In contrast, **14.56% of phishing URLs (2,415 / 16,590)** contain query strings, and long query strings ($\ge 50$ chars) are **27× more prevalent** in phishing URLs than in benign URLs (3.31% vs. 0.12%).
2. **Extreme Tail Position of the Target YouTube URL:**
   * The target lecture URL (`https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`):
     * `url_len = 91`: Exceeds the **99th percentile** of benign URLs ($p99 = 86.0$).
     * `query_len = 61`: Exceeds **99.93%** of all benign URLs in the dataset (only 69 out of 98,641 have `query_len >= 61`).
     * `digit_cnt = 6`: Exceeds the **99th percentile** of benign URLs ($p99 = 4.0$).
     * `entropy = 5.473`: Exceeds **99.99%** of benign URLs (only 11 out of 98,641 have entropy $\ge 5.47$).
     * `is_https = 1`: Matches the phishing class profile (91.43% of phishing vs. 34.94% of benign).
3. **Absence of Modern Dynamic Web Services in Benign Data:**
   * There is **zero presence of YouTube (`0 / 98,641`)**, **zero Google Search URLs (`0 / 98,641`)**, and **zero Amazon product URLs (`0 / 98,641`)** anywhere in the clean benign dataset.

---

## 2. Statistical Distributions by Class (Clean Dataset, N = 115,231)

All continuous features were evaluated across both classes. The table below presents the exact empirical percentiles calculated directly from the clean deduplicated dataset (98,641 Legitimate, 16,590 Phishing):

| Feature Name | Class | Mean | Std | Min | p25 | p50 (Median) | p75 | p90 | p95 | p99 | Max |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **`url_len`** | **Legit** | **29.10** | 13.18 | 12.0 | 22.0 | **26.0** | 32.0 | 40.0 | 51.0 | 86.0 | 582.0 |
| | **Phish** | **56.31** | 66.24 | 15.0 | 29.0 | **38.0** | 55.0 | 113.0 | 175.0 | 240.1 | 1202.0 |
| **`query_len`** | **Legit** | **0.31** | 3.37 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 9.0 | 162.0 |
| | **Phish** | **9.39** | 49.72 | 0.0 | 0.0 | **0.0** | 0.0 | 41.0 | 43.0 | 146.0 | 1148.0 |
| **`path_len`** | **Legit** | **4.62** | 11.00 | 0.0 | 1.0 | **1.0** | 1.0 | 13.0 | 23.0 | 56.0 | 456.0 |
| | **Phish** | **17.16** | 36.27 | 0.0 | 1.0 | **6.0** | 16.0 | 49.0 | 108.0 | 108.0 | 670.0 |
| **`subdom_cnt`** | **Legit** | **0.87** | 0.47 | 0.0 | 1.0 | **1.0** | 1.0 | 1.0 | 1.0 | 2.0 | 7.0 |
| | **Phish** | **0.73** | 0.56 | 0.0 | 0.0 | **1.0** | 1.0 | 1.0 | 1.0 | 2.0 | 5.0 |
| **`digit_cnt`** | **Legit** | **0.15** | 1.17 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 4.0 | 61.0 |
| | **Phish** | **5.76** | 14.61 | 0.0 | 0.0 | **1.0** | 6.0 | 17.0 | 22.0 | 51.0 | 321.0 |
| **`digit_ratio`** | **Legit** | **0.003** | 0.018 | 0.00 | 0.00 | **0.00** | 0.00 | 0.00 | 0.00 | 0.09 | 0.48 |
| | **Phish** | **0.074** | 0.098 | 0.00 | 0.00 | **0.04** | 0.11 | 0.20 | 0.31 | 0.39 | 0.83 |
| **`special_cnt`** | **Legit** | **6.67** | 1.88 | 4.0 | 6.0 | **6.0** | 7.0 | 9.0 | 10.0 | 14.0 | 58.0 |
| | **Phish** | **9.00** | 9.29 | 4.0 | 6.0 | **7.0** | 9.0 | 15.0 | 22.0 | 29.0 | 234.0 |
| **`spec_ratio`** | **Legit** | **0.243** | 0.049 | 0.07 | 0.21 | **0.24** | 0.28 | 0.30 | 0.32 | 0.33 | 0.44 |
| | **Phish** | **0.184** | 0.048 | 0.01 | 0.15 | **0.19** | 0.22 | 0.24 | 0.26 | 0.29 | 0.52 |
| **`entropy`** | **Legit** | **3.789** | 0.266 | 2.65 | 3.61 | **3.78** | 3.96 | 4.12 | 4.23 | 4.49 | 5.91 |
| | **Phish** | **4.316** | 0.494 | 2.69 | 3.99 | **4.18** | 4.46 | 5.10 | 5.54 | 5.66 | 6.03 |
| **`is_https`** | **Legit** | **0.349** | 0.477 | 0.0 | 0.0 | **0.0** | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| | **Phish** | **0.914** | 0.280 | 0.0 | 1.0 | **1.0** | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| **`is_ip`** | **Legit** | **0.000** | 0.008 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| | **Phish** | **0.000** | 0.021 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| **`eq_cnt`** | **Legit** | **0.027** | 0.225 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 1.0 | 8.0 |
| | **Phish** | **0.396** | 1.134 | 0.0 | 0.0 | **0.0** | 0.0 | 2.0 | 3.0 | 5.0 | 29.0 |
| **`qm_cnt`** | **Legit** | **0.020** | 0.140 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 |
| | **Phish** | **0.149** | 0.385 | 0.0 | 0.0 | **0.0** | 0.0 | 1.0 | 1.0 | 1.0 | 17.0 |
| **`amp_cnt`** | **Legit** | **0.008** | 0.134 | 0.0 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 0.0 | 7.0 |
| | **Phish** | **0.240** | 0.870 | 0.0 | 0.0 | **0.0** | 0.0 | 1.0 | 2.0 | 4.0 | 27.0 |
| **`dash_cnt`** | **Legit** | **0.244** | 0.837 | 0.0 | 0.0 | **0.0** | 0.0 | 1.0 | 1.0 | 4.0 | 22.0 |
| | **Phish** | **0.937** | 1.456 | 0.0 | 0.0 | **0.0** | 1.0 | 3.0 | 3.0 | 6.0 | 25.0 |
| **`dot_cnt`** | **Legit** | **2.187** | 0.735 | 1.0 | 2.0 | **2.0** | 3.0 | 3.0 | 3.0 | 4.0 | 9.0 |
| | **Phish** | **1.927** | 0.818 | 1.0 | 1.0 | **2.0** | 2.0 | 3.0 | 3.0 | 5.0 | 15.0 |
| **`slash_cnt`** | **Legit** | **3.148** | 0.790 | 2.0 | 3.0 | **3.0** | 3.0 | 4.0 | 5.0 | 6.0 | 20.0 |
| | **Phish** | **3.618** | 1.469 | 2.0 | 3.0 | **3.0** | 4.0 | 6.0 | 7.0 | 8.0 | 37.0 |

---

## 3. Deep-Dive: Query String and Parameter Complexity

A programmatically parsed query parameter count (`param_cnt`) was computed for all 115,231 clean URLs using `urllib.parse.parse_qs`:

```text
Parameter Count (param_cnt) Distribution:
Class        0 Params       1 Param       2 Params      3 Params      4+ Params     Total (>= 1)
Legitimate   96,660 (98.0%)  1,570 (1.6%)   249 (0.25%)   90 (0.09%)    72 (0.07%)    1,981 (2.01%)
Phishing     14,175 (85.4%)    770 (4.6%)   318 (1.92%)  985 (5.94%)   342 (2.06%)    2,415 (14.56%)
```

### Key Analytical Insights:
1. **Multi-Parameter URLs are Nearly Non-Existent in Benign Data:**
   * Only **411 legitimate URLs (0.42%)** in the entire dataset have 2 or more parameters.
   * Only **162 legitimate URLs (0.16%)** have 3 or more parameters.
   * In contrast, **1,645 phishing URLs (9.92%)** have 2 or more parameters, and **1,327 phishing URLs (8.00%)** have 3 or more parameters (a **50× relative frequency difference**).
2. **Query String Length Discrepancy:**
   * For legitimate URLs, `query_len` has median 0, 75th percentile 0, 90th percentile 0, and 95th percentile 0.
   * A benign URL with `query_len >= 20` occurs only **370 times (0.38%)**.
   * A benign URL with `query_len >= 50` occurs only **118 times (0.12%)**.
   * The target YouTube URL has `query_len = 61`. In the entire clean benign dataset of 98,641 URLs, only **69 URLs (0.070%)** have a query string of 61 characters or longer.

---

## 4. Modern Dynamic Services Representation Audit

To verify whether modern web architecture patterns exist in the dataset, regular expression filters were run across all 115,231 URLs:

| Architectural Pattern | Regex Pattern | Legit Count | Phish Count | Legit % of Total | Audit Finding |
|---|---|---|---|---|---|
| **YouTube Platform** | `youtube\.com\|youtu\.be` | **0** | **0** | **0.000%** | **Completely absent from dataset.** |
| **Google Search** | `google\.[a-z.]+/search` | **0** | **0** | **0.000%** | **Completely absent from dataset.** |
| **Amazon Product Pages** | `amazon\.[a-z.]+/.*/(dp\|gp)/` | **0** | **0** | **0.000%** | **Completely absent from dataset.** |
| **E-Commerce Patterns** | `product\|item\|cart\|checkout\|shop` | 248 | 445 | 0.251% | Severely under-represented in benign. |
| **Video & Media Streaming**| `watch\|video\|vimeo\|playlist` | 33 | 27 | 0.033% | Almost entirely missing. |
| **Authentication & Login** | `login\|signin\|account\|auth\|password` | 29 | 1,128 | 0.029% | **97.5% labeled as phishing.** |
| **Pagination Parameters** | `page=\|p=\|offset=\|limit=` | 107 | 1,036 | 0.108% | **90.6% labeled as phishing.** |
| **Analytics & Campaign Tags**| `utm_\|ref=\|source=\|campaign=` | 46 | 106 | 0.047% | Under-represented. |

---

## 5. Comparison: Target YouTube Lecture URL vs. Dataset Distributions

The table below directly benchmarks the target YouTube URL against the benign and phishing population distributions:

| Feature | Target Value | Benign Population Mean | Benign Percentile | Phishing Population Mean | Diagnostic Interpretation |
|---|---|---|---|---|---|
| **`url_len`** | **91** | 29.10 | **> 99.0th** ($p99 = 86.0$) | 56.31 | Heavily shifted toward phishing tail. |
| **`query_len`** | **61** | 0.31 | **> 99.93th** (Rank #70 of 98,641) | 9.39 | Over 190× benign mean; lands in phishing zone. |
| **`param_cnt`** | **3** (`v`, `list`, `index`) | 0.03 | **> 99.83th** (Only 162 have $\ge 3$) | 0.24 | 50× more common in phishing than benign. |
| **`digit_cnt`** | **6** | 0.15 | **> 99.4th** ($p99 = 4.0$) | 5.76 | Matches phishing mean (5.76) almost exactly. |
| **`digit_ratio`** | **0.0659** (6.59%) | 0.0031 (0.31%) | **> 98.5th** ($p95 = 0.0$) | 0.0738 (7.38%) | 21× higher than benign average. |
| **`entropy`** | **5.4733** | 3.7888 | **> 99.99th** (Only 11 have $\ge 5.47$) | 4.3163 | Extreme outlier; in training data, $H > 5.1$ is 95% phishing. |
| **`is_https`** | **1** | 0.3494 (34.9%) | Top 35% | 0.9143 (91.4%) | Acts as an inverted phishing indicator. |
| **`eq_cnt`** | **3** | 0.027 | **> 99.5th** ($p99 = 1.0$) | 0.396 | 100× higher than benign average. |
| **`amp_cnt`** | **2** | 0.008 | **> 99.6th** ($p99 = 0.0$) | 0.240 | Ampersands are virtually non-existent in benign set. |

---

## 6. Diagnosis: Root Cause of the 94% Phishing Prediction

The measured distributions establish the root cause of the false positive:
1. **The Benign Training Distribution is Severely Truncated:**
   * 98% of benign training URLs are simple homepage landing pages or static one-level paths (`http://institution.edu/`, `https://company.com/about`).
   * They have zero query parameters, zero digits, low Shannon entropy ($\approx 3.79$), and only 34.9% use HTTPS.
2. **Structural Parameter Overlap with Phishing Kits:**
   * Phishing exploit kits frequently employ base64 tokens, randomized campaign tracking IDs, dynamic redirection parameters, and HTTPS certificates (91.4% HTTPS, mean entropy 4.32, 5.8 digits on average).
3. **The Inductive Trap:**
   * When the Random Forest evaluates a legitimate URL with modern application parameters (e.g., YouTube playlist IDs containing alphanumeric tokens, ampersands, equal signs, and HTTPS), the decision trees evaluate:
     * `is_https == 1` $\rightarrow$ Branch toward Phishing.
     * `entropy > 4.4` $\rightarrow$ Branch toward Phishing.
     * `digit_cnt > 0.5` $\rightarrow$ Branch toward Phishing.
     * `query_len > 10.5` $\rightarrow$ Branch toward Phishing.
     * `eq_cnt > 1.5` $\rightarrow$ Branch toward Phishing.
   * **Result:** Exactly 94 out of 100 decision trees classify the URL into phishing leaves, resulting in a predicted phishing probability of **0.9400 (94.0%)**.

---

## 7. Evidentiary Distinctions

* **Verified Facts from Actual Files:** Across 98,641 clean legitimate URLs, 96,660 (97.99%) have query length 0. Exactly 0 YouTube URLs exist in the dataset.
* **Measured Results:** The target YouTube URL exceeds the 99th percentile of legitimate URLs on `url_len`, `query_len`, `digit_cnt`, `eq_cnt`, and `entropy`.
* **Hypotheses Needing Further Testing:** Augmenting the training set with legitimate multi-parameter URLs will adjust tree split thresholds and reduce the false positive rate on complex dynamic URLs.
* **Limitations:** The existing benchmark dataset does not provide parameter semantics (e.g., distinguishing video IDs from credential harvesting parameters).
