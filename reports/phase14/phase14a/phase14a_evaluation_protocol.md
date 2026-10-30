# Phase 14A: Independent Evaluation Protocol & Error Analysis Plan

**Auditor:** Senior Machine Learning Engineer, Cybersecurity Researcher & Independent Evaluator  
**Phase:** 14A — Independent Evaluation Dataset Construction & Integrity Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & FORMALIZED  
**Evaluation Target:** [phase14a_verified_evaluation_set.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase14a/cleaned/phase14a_verified_evaluation_set.csv) ($N = 963$)

---

## 1. Executive Summary

This document specifies the formal mathematical evaluation protocol, metric formulas, statistical confidence bounds, slice definitions, and error-analysis workflows for evaluating **Candidate 4** (`cand04_rf_regularized_30f`) and **Candidate 6** (`cand06_hist_gbdt_30f`) during the upcoming Phase 14B evaluation.

Per the Phase 14A instructions, **no model performance is evaluated in this document**. This protocol establishes a locked, pre-registered testing methodology to prevent post-hoc metric cherry-picking.

---

## 2. Core Evaluation Metrics & Mathematical Definitions

All binary classification metrics will be computed at the fixed decision threshold $\tau = 0.50$ (where a predicted phishing probability $P(\text{phish}) \ge 0.50$ indicates a positive prediction):

### Primary Metric Matrix

| Metric | Mathematical Formula | Operational Interpretation |
| :--- | :--- | :--- |
| **Confusion Matrix** | $\begin{bmatrix} TN & FP \\ FN & TP \end{bmatrix}$ | $TN$: Clean benign; $FP$: False alarm; $FN$: Missed phish; $TP$: Caught phish. |
| **Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN}$ | Overall proportion of correct classifications across both classes. |
| **Precision** | $\frac{TP}{TP + FP}$ | Proportion of predicted phishing alerts that are genuinely malicious. |
| **Phishing Recall** | $\frac{TP}{TP + FN}$ | Proportion of total malicious URLs successfully intercepted. |
| **False Positive Rate ($FPR$)**| $\frac{FP}{FP + TN}$ | Proportion of legitimate URLs incorrectly flagged as phishing (target: minimize). |
| **False Negative Rate ($FNR$)**| $\frac{FN}{TP + FN}$ | Proportion of malicious attacks that evade detection ($1 - \text{Recall}$). |
| **F1-Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean balancing false positives against false negatives. |
| **ROC-AUC** | $\int_0^1 \text{TPR}(\text{FPR}^{-1}(t))\,dt$ | Discrimination ability across all possible operating thresholds. |
| **PR-AUC** | $\sum_k (R_k - R_{k-1}) P_k$ | Precision-Recall curve area; critical for class-imbalanced evaluation. |
| **Brier Score Loss** | $\frac{1}{N} \sum_{i=1}^N (P_i - y_i)^2$ | Probability calibration error (mean squared difference from truth). |

---

## 3. Statistical Confidence Intervals (Wilson Score Interval)

Given that the verified evaluation set contains $N_0 = 163$ legitimate URLs and $N_1 = 800$ phishing URLs, point estimates must be accompanied by 95% confidence intervals.

For binomial proportions (such as False Positive Rate and Recall), the **Wilson Score Interval** will be computed:

$$\hat{p} \pm \frac{z}{1 + \frac{z^2}{N}} \sqrt{\frac{\hat{p}(1 - \hat{p})}{N} + \frac{z^2}{4N^2}}$$

Where:
- $z = 1.95996$ for a 95% two-sided confidence level.
- $N$ is the sub-cohort denominator (e.g., $N_0 = 163$ for FPR; $N_1 = 800$ for Recall).

---

## 4. Pre-Registered Slice Evaluations

Aggregate metrics can conceal severe subgroup degradation. Phase 14B must report metrics across the following mandatory slices:

### Slice 1: URL Length Bins
- Short URLs: $[0, 50)$ characters ($N \approx 131$)
- Medium URLs: $[50, 90)$ characters ($N \approx 434$)
- Long URLs: $[90, 150)$ characters ($N \approx 302$)
- Very Long URLs: $[150, \infty)$ characters ($N \approx 96$)

### Slice 2: Query String Complexity
- **Query-Bearing URLs ($N = 145$):** 77 Legitimate, 68 Phishing.
  - *Primary Hypothesis to Test:* Does Candidate 6 maintain its query FPR advantage over Candidate 4 on this independent corpus?
- **Static URLs without Query ($N = 818$):** 86 Legitimate, 732 Phishing.

### Slice 3: Protocol Scheme
- **HTTPS Slice ($N = 153$):** 143 Legitimate, 10 Phishing.
- **HTTP Slice ($N = 810$):** 20 Legitimate, 790 Phishing.
  - *Primary Hypothesis to Test:* Does either model exhibit an inverted protocol bias on the 20 legitimate HTTP institutional URLs?

### Slice 4: Functional Category
Evaluate FPR and Recall separately across:
- `legit_documentation_deep_path` ($N = 79$)
- `legit_academic_search_query` ($N = 43$)
- `legit_community_technical_qa` ($N = 16$)
- `legit_government_portal` ($N = 15$)
- `legit_institutional_http` ($N = 10$)
- `phish_credential_harvesting_path` ($N = 702$)
- `phish_multi_parameter_token` ($N = 68$)
- `phish_free_hosting_builder` ($N = 30$)

---

## 5. Model-Only vs Layered Decision Engine Comparison

For each URL in the evaluation set, Phase 14B will generate two distinct evaluation outputs:
1. **Standalone Model Assessment:** Raw predicted probability $P(\text{phish})$ and binary prediction at $\tau = 0.50$ via `ModelInferenceAdapter`.
2. **Layered Decision Engine Assessment:** Structured verdict produced by `LayeredDecisionEngine.evaluate_url(url)`:
   - `CONFIRMED_MALICIOUS` (Critical Risk)
   - `HIGH_RISK` (High Risk)
   - `SUSPICIOUS` (Medium Risk)
   - `INCONCLUSIVE` (Medium Risk)
   - `NO_KNOWN_THREAT_DETECTED` (Low Risk)

### Layered Resolution Mapping
- A legitimate URL receiving an elevated ML score ($P > 0.50$) that is downgraded by the engine's query complexity contrast rule to `INCONCLUSIVE` will be classified as a **Mitigated False Positive**.
- A phishing URL receiving a low ML score ($P < 0.50$) that is caught by the engine's brand spoofing rule or direct IP filter and elevated to `HIGH_RISK` will be classified as an **Architecturally Intercepted Threat**.

---

## 6. Warnings on Metric Limitations for Small Sub-cohorts

To maintain statistical rigor, the following rules apply during reporting:
1. **ROC-AUC & PR-AUC on One-Class Subsets:** ROC-AUC and PR-AUC are mathematically undefined when a slice contains only one class (e.g. `legit_government_portal` with 0 phishing URLs). Analysts must NOT report ROC-AUC on single-class slices; report exact False Positive counts and rates instead.
2. **High-Variance Small Slices:** On sub-cohorts with fewer than 20 samples (e.g. `legit_institutional_http` with $N=10$), percentage-based metrics can fluctuate by 10% on a single error. Exact integer counts ($FP/N$) must be presented alongside percentages.
3. **Class-Imbalanced Accuracy Caution:** Because phishing URLs represent 83.07% of the dataset, a trivial model predicting all URLs as phishing would achieve 83.07% accuracy. **Macro F1-Score, Balanced Accuracy, and FPR are the definitive primary metrics.**
