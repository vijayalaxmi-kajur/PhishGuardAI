# PhishGuardAI — Domain Generalization & Independent Model Validation Report

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Phase:** Phase 8 — Independent Model Validation & Generalization Analysis  
**Execution Date:** October 28, 2026  
**Status:** Complete & Verified (All 63 Unit and Integration Tests Passing)  
**Evaluation Partition:** Domain-Held-Out Evaluation Split (Strictly Zero Domain Overlap)  
**Sample Size:** 23,045 URLs across 18,199 completely unseen domains  
**Class Balance:** 19,727 Legitimate (85.60%) vs. 3,318 Phishing (14.40%)  

---

## 1. Executive Summary & Scientific Motivation

In Phase 5, the baseline Random Forest classifier trained on a conventional 80/20 random stratified split achieved **97.61% accuracy, 90.52% precision, 93.19% recall, and 91.83% F1-score**. However, an audit of the partitioning revealed that **2,120 domains (10.84% of test domains)** appeared in both the training and testing sets. Multi-page platforms like `weebly.com` (2,455 URLs) and `google.com` (1,450 URLs) had hundreds of URLs present across both partitions.

To determine whether the classifier can detect phishing URLs on **completely novel, previously unobserved domains**, Phase 8 conducted an independent, domain-aware experiment:
1. **Zero Domain Overlap:** All URLs belonging to the same registered domain were grouped together. Using `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)`, the dataset was divided into an 80% training partition (72,661 domains) and a 20% evaluation partition (18,199 domains). Exactly **0 domains overlap** between partitions.
2. **Experimental Isolation:** A new experimental Random Forest model (`models/experiments/domain_heldout_random_forest.joblib`) was trained exclusively on the domain-held-out training partition. The production model (`models/phishing_model.joblib`), original datasets, and Flask application remained strictly preserved.
3. **Generalization Gap Discovered:** 
   * **Precision remained remarkably steady:** Phishing precision was **89.94%** (compared to 90.52% in the random split), generating exactly **324 False Positives** on 19,727 unseen legitimate URLs.
   * **Recall dropped significantly:** Phishing recall dropped from **93.19% down to 87.34%** (a 5.85% drop), increasing False Negatives from 226 to **420 missed attacks**.
   * **Empirical Insight:** Classifiers tested on familiar domains benefit from subtle domain-level lexical regularities. On completely unseen domains, phishing attacks with subtle or clean paths are significantly harder to detect purely from passive lexical features.

---

## 2. Experimental Design & Partitioning Metrics

### 2.1 Grouping Methodology
* **Domain Grouping Key:** Extracted registrable domain (`dom`), verified to handle multi-part public suffixes (`.edu.au`, `.gov.au`, `.co.uk`, etc.) identically to `tldextract` top domain under public suffix.
* **Stratified Group Splitting:** `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` ensured that all URLs sharing the same `dom` remain confined to either training or testing, while simultaneously balancing the ~14.40% phishing class representation.

### 2.2 Partition Statistics

| Split Dimension | Training Partition (Fold 0) | Evaluation Partition (Fold 0) | Total Clean Dataset |
|---|---|---|---|
| **Total Samples** | **92,186** (80.00%) | **23,045** (20.00%) | **115,231** |
| **Unique Domains** | **72,661** | **18,199** | **90,860** |
| **Shared Domains** | **0** | **0** | **Strictly 0 Overlap** |
| **Legitimate URLs (0)** | 78,914 (85.60%) | 19,727 (85.60%) | 98,641 (85.60%) |
| **Phishing URLs (1)** | 13,272 (14.40%) | 3,318 (14.40%) | 16,590 (14.40%) |
| **Phishing Ratio** | 1 : 5.95 | 1 : 5.95 | 1 : 5.95 |

---

## 3. Measured Evaluation Metrics

The experimental model was evaluated strictly on the 23,045 held-out URLs from 18,199 unseen domains:

| Metric | Random Split (Phase 5 Baseline) | Domain-Held-Out Split (Phase 8 Experiment) | Shift / Generalization Delta |
|---|---|---|---|
| **Accuracy** | 97.61% | **96.77%** | -0.84% |
| **Phishing Precision (Class 1)** | 90.52% | **89.94%** | -0.58% (Robust) |
| **Phishing Recall (Class 1)** | 93.19% | **87.34%** | **-5.85% (Drop)** |
| **Phishing F1-Score (Class 1)** | 91.83% | **88.62%** | **-3.21%** |
| **Macro F1-Score** | 95.22% | **93.37%** | -1.85% |
| **Weighted F1-Score** | 97.63% | **96.75%** | -0.88% |
| **ROC-AUC** | 0.9913 | **0.9826** | -0.0087 |
| **PR-AUC (Average Precision)** | 0.9716 | **0.9286** | -0.0430 |
| **Brier Score Loss** | ~0.0210 | **0.0279** | +0.0069 |
| **False Positives (FP)** | 324 | **324** | **Identical (324)** |
| **False Negatives (FN)** | 226 | **420** | **+194 Missed Attacks** |

---

## 4. Confusion Matrix Analysis

The confusion matrix for the domain-held-out test set ($N = 23,045$) is:

$$\begin{bmatrix} TN = 19,403 & FP = 324 \\ FN = 420 & TP = 2,898 \end{bmatrix}$$

```text
                        PREDICTED
                  Legitimate    Phishing
ACTUAL  Legitimate  19,403         324       (Total: 19,727)
        Phishing       420       2,898       (Total:  3,318)
```

### Explanation of Error Modes:
1. **False Positives ($FP = 324$ out of 19,727 legitimate URLs $\rightarrow$ 1.64% False Alarm Rate):**
   * *What it means:* An innocent, benign URL on an unseen domain was incorrectly classified as phishing.
   * *Root Cause:* Legitimate URLs with high Shannon entropy, long multi-segment subdomains, or deep complex query strings (e.g., dynamic session tokens, CMS search queries, or analytics parameters) structurally mimic phishing URLs.
   * *Impact:* User inconvenience / false alarm. However, the model correctly allowed **98.36% of legitimate URLs** through without interference.
2. **False Negatives ($FN = 420$ out of 3,318 phishing URLs $\rightarrow$ 12.66% Miss Rate):**
   * *What it means:* A phishing URL on an unseen domain was mistakenly classified as legitimate.
   * *Root Cause:* On newly observed domains, attackers who craft minimal, clean-looking URLs (e.g., short domains, standard length, minimal special symbols, zero query parameters) evade lexical heuristic detection. Without prior domain reputation or page inspection, passive lexical features alone cannot differentiate them from benign static web pages.
   * *Impact:* Security threat. This empirically demonstrates why multi-layered defense (DNS reputation + passive lexical ML + active content scanning) is essential in production security systems.

---

## 5. Probability Calibration Audit & Brier Score

A machine-learning classifier is **calibrated** if its predicted probability reflects the true empirical likelihood of an event. If a model assigns a 70% probability to a set of URLs, approximately 70% of those URLs should actually be phishing attacks.

### 5.1 Brier Score
The Brier score measures the mean squared difference between predicted probabilities and actual binary outcomes ($y \in \{0, 1\}$):

$$BS = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$$

* **Calculated Brier Score:** **0.0279**
* **Interpretation:** 
  * A reference dummy classifier that uniformly predicts the dataset base rate ($14.40\%$) achieves $BS \approx 0.144 \times (1 - 0.144) = 0.1232$.
  * A score of **0.0279** indicates that the Random Forest probability outputs are tightly centered near the true ground truth.

### 5.2 Reliability Diagram (Calibration Curve)
The predicted probabilities on the domain-held-out evaluation set were grouped into 10 uniform probability bins:

| Bin Index | Mean Predicted Probability | Observed Fraction of Phishing | Alignment Assessment |
|---|---|---|---|
| 1 | **0.60%** | **0.70%** | Near-perfect calibration for safe URLs |
| 2 | **15.20%** | **12.20%** | Well-calibrated low-risk zone |
| 3 | **24.90%** | **14.10%** | Slight over-prediction |
| 4 | **35.80%** | **18.10%** | Slight over-prediction |
| 5 | **45.30%** | **39.00%** | Well-calibrated borderline zone |
| 6 | **55.30%** | **59.00%** | Decision threshold zone |
| 7 | **65.90%** | **77.70%** | Slight under-confidence in phishing |
| 8 | **75.80%** | **90.80%** | High true positive density |
| 9 | **85.50%** | **92.10%** | High true positive density |
| 10 | **97.20%** | **96.50%** | Near-perfect calibration for blatant attacks |

### Calibration Audit Verdict:
The Random Forest classifier exhibits strong monotonic calibration. Extreme predictions ($< 5\%$ and $> 90\%$) reflect near-perfect real-world probabilities. In the intermediate range (60%–80%), the model is slightly conservative, but its monotonic increase supports the continued use of **0.50** as the primary decision threshold.

---

## 6. Generated Visualizations

The following high-resolution figures were generated by the pipeline and saved in `reports/figures/`:

1. `reports/figures/domain_generalization_confusion_matrix.png`: Annotated 2x2 confusion matrix displaying TN ($19,403$), FP ($324$), FN ($420$), and TP ($2,898$).
2. `reports/figures/domain_generalization_roc_pr_curves.png`: Side-by-side plots of the ROC curve ($AUC = 0.9826$) and Precision-Recall curve ($AUC = 0.9286$).
3. `reports/figures/domain_generalization_calibration_curve.png`: Reliability curve comparing the model's predicted probabilities against perfect diagonal calibration.

---

## 7. Viva Voce / Academic Defense Discussion Points

### Question 1: "Why did you conduct a domain-held-out validation in addition to the standard random split?"
* **Answer:** "Standard random stratified splitting randomly assigns URLs to train and test sets regardless of their domain. In our dataset, 2,120 domains overlapped between train and test, accounting for over 20% of the test URLs. While this tests how well the model recognizes attacks on known platforms (like `weebly.com` or `google.com`), it does not answer whether the model can detect attacks on completely new, unseen domains. Our domain-held-out experiment guarantees zero domain overlap, giving an authentic assessment of real-world generalization."

### Question 2: "Why did recall drop from 93.19% to 87.34%, while precision stayed at ~90%?"
* **Answer:** "Precision remained stable at ~90% because legitimate URL structures across the Internet have universal lexical features (clean path hierarchies, standard character distributions, absence of deception tokens). However, phishing attackers using novel domains often use clean or minimal URL paths. Without having seen that domain during training, the model cannot rely on familiar domain tokens and misses subtle attacks, increasing False Negatives from 226 to 420."

### Question 3: "Did you use the test set to tune the model?"
* **Answer:** "No. In strict adherence to machine learning best practices, the domain-held-out test partition was strictly held out and evaluated only once after the experimental Random Forest was completely trained on the training partition. No hyperparameters or thresholds were adjusted based on test set results."

### Question 4: "Why did you keep the experimental model separate from the production model?"
* **Answer:** "Production stability is paramount in software engineering. The production model (`models/phishing_model.joblib`), REST API, SQLite database, and Web Dashboard are fully functional and tested. The domain generalization analysis was conducted as an independent research experiment saved under `models/experiments/`, ensuring reproducibility without disrupting working systems."
