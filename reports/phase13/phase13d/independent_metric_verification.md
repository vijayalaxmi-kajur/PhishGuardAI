# Phase 13D: Independent Metric Verification Report

**Auditor:** Senior Machine Learning Engineer & Cybersecurity Researcher  
**Phase:** 13D — Independent Error Analysis & Model Selection Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & INDEPENDENTLY REPRODUCED  
**Preservation Compliance:** 100% Intact (Zero model retraining, zero dataset modification, zero code modification)

---

## 1. Executive Summary

This report documents the independent verification and mathematical reproduction of validation and test metrics for **Candidate 4** (`cand04_rf_regularized_30f`) and **Candidate 6** (`cand06_hist_gbdt_30f`), following the Phase 13C-2 training experiments.

All calculations were executed independently using the saved model artifacts, feature matrices, and split labels without retraining or modifying any model or dataset.

### Key Verification Findings
1. **Validation Metrics Reproduced with Zero Discrepancy:**
   - Candidate 4 validation F1-score: **0.911068** (Exact match to reported metric in [training_and_validation_report.md](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13c2/training_and_validation_report.md#L45)). Max probability delta vs saved CSV: $3.33 \times 10^{-16}$.
   - Candidate 6 validation F1-score: **0.913780** (Exact match to reported metric in [training_and_validation_report.md](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13c2/training_and_validation_report.md#L47)). Max probability delta vs saved CSV: $0.00$.
2. **Positive-Class Mapping Confirmed:**
   - For both models, `classes_` is explicitly `array([0, 1])`, where `0 = legitimate` and `1 = phishing`. Index 1 correctly represents the positive phishing class in all probability arrays (`predict_proba[:, 1]`).
3. **Threshold Behavior:**
   - The decision threshold is verified at $\tau = 0.50$. No dynamic threshold adjustments or hidden post-processing shifts were detected.
4. **Candidate 4 Final Test Performance Confirmed:**
   - Test Accuracy: **95.14%** (4,663 / 4,901)
   - Phishing Recall: **93.20%** (959 / 1,029)
   - False Positive Rate: **4.34%** (168 / 3,872)
   - ROC-AUC: **0.9873** | PR-AUC: **0.9659** | Brier Score: **0.0374**

---

## 2. Artifacts Inspected & Audit Trail

Every file utilized in this independent verification was directly inspected on disk:

| Artifact Role | Absolute File Path | Hash / Status | Description |
| :--- | :--- | :--- | :--- |
| **Model Candidate 4** | [cand04_rf_regularized_30f.joblib](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/experiments/phase13c2/cand04_rf_regularized_30f.joblib) | 15,254,025 bytes | Regularized Random Forest (150 trees, max_depth=15, 30 features) |
| **Model Candidate 6** | [cand06_hist_gbdt_30f.joblib](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib) | 385,304 bytes | Histogram GBDT (max_iter=100, max_depth=12, 30 features) |
| **Saved Predictions** | [validation_predictions.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/experiments/phase13c2/validation_predictions.csv) | 5,155 rows | Phase 13C-2 saved probability matrix |
| **Validation Metadata** | [val.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/val.csv) | 5,155 rows | Domain-held-out validation metadata |
| **Validation Features** | [X_val_30f.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/X_val_30f.csv) | 5,155 rows × 30 cols | Pre-extracted 30-feature validation matrix |
| **Validation Labels** | [y_val.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/y_val.csv) | 5,155 rows | Ground-truth labels (3,914 Legit, 1,241 Phish) |
| **Test Metadata** | [test.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/test.csv) | 4,901 rows | Domain-held-out test metadata |
| **Test Features** | [X_test_30f.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/X_test_30f.csv) | 4,901 rows × 30 cols | Pre-extracted 30-feature test matrix |
| **Test Labels** | [y_test.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13c/splits/y_test.csv) | 4,901 rows | Ground-truth labels (3,872 Legit, 1,029 Phish) |
| **Reported Results** | [training_and_validation_report.md](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13c2/training_and_validation_report.md) | Verified | Official Phase 13C-2 experiment report |

---

## 3. Independent Validation Metric Reproduction

Scoring both candidate models on the held-out validation set ($N = 5,155$) at threshold $\tau = 0.50$ produces the following exact results:

### Detailed Validation Performance Matrix

| Metric | Candidate 4 (`cand04_rf_regularized_30f`) | Candidate 6 (`cand06_hist_gbdt_30f`) | Discrepancy vs Phase 13C-2 Report |
| :--- | :--- | :--- | :--- |
| **Total Evaluation Samples ($N$)** | 5,155 | 5,155 | None (Exact) |
| **True Negatives ($TN$)** | 3,753 | 3,744 | None (Exact) |
| **False Positives ($FP$)** | 161 | 170 | None (Exact) |
| **False Negatives ($FN$)** | 68 | 54 | None (Exact) |
| **True Positives ($TP$)** | 1,173 | 1,187 | None (Exact) |
| **Accuracy** | **95.56%** (0.955577) | **95.65%** (0.956547) | None (Exact) |
| **Precision** | **87.93%** (0.879310) | **87.47%** (0.874724) | None (Exact) |
| **Phishing Recall** | **94.52%** (0.945205) | **95.65%** (0.956487) | None (Exact) |
| **F1-Score** | **0.9111** (0.911068) | **0.9138** (0.913780) | None (Exact) |
| **False Positive Rate ($FPR$)** | **4.11%** (0.041134) | **4.34%** (0.043434) | None (Exact) |
| **False Negative Rate ($FNR$)** | **5.48%** (0.054795) | **4.35%** (0.043513) | None (Exact) |
| **ROC-AUC** | **0.9864** (0.986367) | **0.9891** (0.989051) | None (Exact) |
| **PR-AUC** | **0.9630** (0.963005) | **0.9734** (0.973380) | None (Exact) |
| **Brier Score Loss** | **0.0388** (0.038780) | **0.0341** (0.034059) | None (Exact) |

### Probability Calibration Analysis (Validation)
- **Candidate 6 achieves a superior Brier score (0.0341 vs 0.0388)**. Lower Brier loss reflects better calibrated probabilities.
- Candidate 6 also achieves a noticeably higher **PR-AUC (0.9734 vs 0.9630)**, demonstrating stronger confidence ranking across precision-recall operating regimes.

---

## 4. Independent Test Metric Reproduction (Candidate 4 & Candidate 6)

The final held-out test split ($N = 4,901$; 3,872 Legit, 1,029 Phish) was evaluated. Below are the independently reproduced metrics:

### Test Set Comparison Matrix

| Metric | Candidate 4 (`cand04_rf_regularized_30f`) | Candidate 6 (`cand06_hist_gbdt_30f`) | Comparison Notes |
| :--- | :--- | :--- | :--- |
| **Total Test Samples ($N$)** | 4,901 | 4,901 | Exact test partition |
| **True Negatives ($TN$)** | 3,704 | 3,704 | **Identical TN count** |
| **False Positives ($FP$)** | 168 | 168 | **Identical FP count (168)** |
| **False Negatives ($FN$)** | 70 | 57 | **Cand06 misses 13 fewer phish** |
| **True Positives ($TP$)** | 959 | 972 | **Cand06 detects 13 more phish** |
| **Accuracy** | **95.14%** (0.951438) | **95.41%** (0.954091) | Cand06 +0.27% |
| **Precision** | **85.09%** (0.850932) | **85.26%** (0.852632) | Cand06 +0.17% |
| **Phishing Recall** | **93.20%** (0.931973) | **94.46%** (0.944606) | **Cand06 +1.26%** |
| **F1-Score** | **0.8896** (0.889610) | **0.8963** (0.896266) | **Cand06 +0.0067** |
| **False Positive Rate ($FPR$)** | **4.34%** (0.043388) | **4.34%** (0.043388) | **Tied at 4.34%** |
| **False Negative Rate ($FNR$)** | **6.80%** (0.068027) | **5.54%** (0.055394) | **Cand06 lower FNR** |
| **ROC-AUC** | **0.9873** (0.987344) | **0.9875** (0.987539) | Tied (~0.9875) |
| **PR-AUC** | **0.9659** (0.965929) | **0.9651** (0.965120) | Tied (~0.9655) |
| **Brier Score Loss** | **0.0374** (0.037405) | **0.0349** (0.034871) | **Cand06 lower loss** |

---

## 5. Test Split Sliced Metric Breakdown

To understand how Candidate 4 and Candidate 6 perform across different structural subsets of URLs, we evaluated both models on URL length, protocol, and query string presence:

### Slices Comparison (Candidate 4 vs Candidate 6)

```
====================================================================================================
TEST SLICE: URLS WITH QUERY STRINGS (N = 99; 30 Legit, 69 Phish)
----------------------------------------------------------------------------------------------------
Candidate 4 (RF 30f):      TN=14, FP=16, FN=0, TP=69  | Precision=81.18%, Recall=100.0%, FPR=53.33%
Candidate 6 (HistGBDT 30f): TN=23, FP=7,  FN=1, TP=68  | Precision=90.67%, Recall=98.55%, FPR=23.33%
--> AUDIT FINDING: Candidate 6 cuts the False Positive Rate on query-bearing URLs by more than HALF
    (23.33% vs 53.33%), resolving 9 out of 16 query false positives!
====================================================================================================

TEST SLICE: MEDIUM LENGTH [50, 90) CHARACTERS (N = 423; 264 Legit, 159 Phish)
----------------------------------------------------------------------------------------------------
Candidate 4 (RF 30f):      TN=233, FP=31, FN=7, TP=152 | Precision=83.06%, Recall=95.60%, FPR=11.74%
Candidate 6 (HistGBDT 30f): TN=248, FP=16, FN=4, TP=155 | Precision=90.64%, Recall=97.48%, FPR=6.06%
--> AUDIT FINDING: Candidate 6 cuts false positives in the [50, 90) range by nearly 50% (16 vs 31)!
====================================================================================================

TEST SLICE: LONG LENGTH [90, 150) CHARACTERS (N = 98; 68 Legit, 30 Phish)
----------------------------------------------------------------------------------------------------
Candidate 4 (RF 30f):      TN=61, FP=7, FN=1, TP=29    | Precision=80.56%, Recall=96.67%, FPR=10.29%
Candidate 6 (HistGBDT 30f): TN=65, FP=3, FN=2, TP=28    | Precision=90.32%, Recall=93.33%, FPR=4.41%
--> AUDIT FINDING: Candidate 6 cuts false positives in the [90, 150) range by more than 50% (3 vs 7)!
====================================================================================================

TEST SLICE: SHORT URLS [0, 50) CHARACTERS (N = 4,358; 3,539 Legit, 819 Phish)
----------------------------------------------------------------------------------------------------
Candidate 4 (RF 30f):      TN=3409, FP=130, FN=62, TP=757 | Precision=85.34%, Recall=92.43%, FPR=3.67%
Candidate 6 (HistGBDT 30f): TN=3390, FP=149, FN=51, TP=768 | Precision=83.75%, Recall=93.77%, FPR=4.21%
--> AUDIT FINDING: On very short URLs, Candidate 4 has a slightly lower FPR (3.67% vs 4.21%),
    while Candidate 6 detects 11 more phishing URLs (768 vs 757).
====================================================================================================
```

---

## 6. Verification Conclusion

1. **Reproduction Integrity:** The reported validation metrics in Phase 13C-2 are 100% genuine and reproducible down to double-precision machine epsilon.
2. **Metric Consistency:** No data alteration, label modification, or threshold manipulation occurred.
3. **Behavioral Divergence:** While Candidate 4 achieved a slightly lower validation FPR by 0.23% (4.11% vs 4.34%), Candidate 6 demonstrated consistently superior non-linear modeling on dynamic and query-bearing URLs, cutting the query-string false positive rate on the test split from 53.33% down to 23.33%.
