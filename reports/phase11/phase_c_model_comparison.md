# Phase C Model Comparison & Benchmark Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Scope:** Phase C4 & Phase C5 - Systematic Evaluation of Production and Experimental Models  
**Project:** PhishGuardAI  

---

## 1. Experimental Setup & Model Configurations

To ensure a fair, rigorous, and leakage-free evaluation, all models were evaluated side-by-side using fixed random seeds (`random_state=42`) on the identical held-out partitions created in Phase C2:
- **Evaluation Partition:** [`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv) ($N=22,871$ URLs, 10,302 unseen registered domains, strictly 0 training domain overlap, strictly 0 near-duplicate overlap).
- **Realistic Complexity Benchmark:** [`data/realistic_evaluation_set.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/realistic_evaluation_set.csv) ($N=41$ URLs: 26 complex legitimate URLs, 15 diverse phishing attacks).

### Model Descriptions:
1. **Production RF (22f):** The serialized production model ([`models/phishing_model.joblib`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib)) trained on unaugmented baseline data with unconstrained tree depth.
2. **Model 1: RF Augmented (22f):** Random Forest (`n_estimators=100`, unconstrained depth, `class_weight="balanced"`) trained on [`phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv) using the 22 baseline features.
3. **Model 2: RF Experimental (30f):** Random Forest (`n_estimators=100`, `max_depth=16`, `min_samples_leaf=5`, `max_features="sqrt"`, `class_weight="balanced"`) trained on [`phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv) using the 30 component-isolated features.
4. **Model 3: RF Calibrated (30f):** Platt sigmoid calibration (`CalibratedClassifierCV(method='sigmoid', cv=5)`) applied over Model 2.

---

## 2. Comprehensive Metric Comparison

### Table 1: Performance on Held-Out Domain-Partitioned Evaluation Set ($N=22,871$)

| Metric | Production RF (22f) | Model 1: Augmented (22f) | Model 2: Experimental (30f) | Model 3: Calibrated (30f) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Evaluation Samples** | 22,871 | 22,871 | 22,871 | 22,871 |
| **True Negatives (TN)** | 19,449 | 19,217 | 19,230 | 19,372 |
| **False Positives (FP)** | 175 | 407 | 394 | 252 |
| **False Negatives (FN)** | 47 | 289 | 117 | 235 |
| **True Positives (TP)** | 3,200 | 2,958 | 3,130 | 3,012 |
| **Accuracy** | **99.03%** | 96.96% | 97.77% | 97.87% |
| **Precision** | **94.81%** | 87.90% | 88.82% | 92.28% |
| **Phishing Recall** | **98.55%** | 91.10% | 96.40% | 92.76% |
| **F1-Score** | **96.65%** | 89.47% | 92.45% | 92.52% |
| **False Positive Rate (FPR)** | **0.89%** | 2.07% | 2.01% | 1.28% |
| **False Negative Rate (FNR)** | **1.45%** | 8.90% | 3.60% | 7.24% |
| **ROC-AUC** | **0.9985** | 0.9885 | 0.9945 | 0.9942 |
| **PR-AUC** | **0.9951** | 0.9448 | 0.9715 | 0.9713 |
| **Brier Score (Calibration)** | **0.0086** | 0.0236 | 0.0211 | 0.0167 |

> [!NOTE]
> On the large held-out split, all models maintain >96.9% accuracy and <2.1% false-positive rates. The production model exhibits lower FNR here primarily because 97.8% of the legitimate URLs in this split are shallow URLs matching its training distribution.

---

### Table 2: Performance on Realistic Complexity Benchmark ($N=41$)

| Metric | Production RF (22f) | Model 1: Augmented (22f) | Model 2: Experimental (30f) | Model 3: Calibrated (30f) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Evaluation Samples** | 41 | 41 | 41 | 41 |
| **Legitimate Samples** | 26 | 26 | 26 | 26 |
| **True Negatives (TN)** | 4 | **11** | 5 | 8 |
| **False Positives (FP)** | 22 | **15** | 21 | 18 |
| **False Positive Rate (FPR)** | 84.62% | **57.69%** | 80.77% | 69.23% |
| **Phishing Samples** | 15 | 15 | 15 | 15 |
| **False Negatives (FN)** | 4 | **0** | **0** | 1 |
| **True Positives (TP)** | 11 | **15** | **15** | 14 |
| **Phishing Recall** | 73.33% | **100.00%** | **100.00%** | 93.33% |
| **F1-Score** | 45.83% | **66.67%** | 58.82% | 59.57% |
| **ROC-AUC** | 0.4872 | **0.8859** | 0.7590 | 0.7308 |
| **Brier Score** | 0.4198 | **0.2502** | 0.3356 | 0.3225 |

---

### Table 3: Targeted Sub-Slice Evaluations

#### Sub-Slice A: Legitimate URLs with Query Parameters ($N=368$ in Evaluation Split)
- **Production RF (22f):** FP = 12, TN = 356, **FPR = 3.26%**
- **Model 1: Augmented (22f):** FP = 33, TN = 335, **FPR = 8.97%**
- **Model 2: Experimental (30f):** FP = 24, TN = 344, **FPR = 6.52%**
- **Model 3: Calibrated (30f):** FP = 18, TN = 350, **FPR = 4.89%**

#### Sub-Slice B: Phishing URLs with Simple Structures ($N=3,036$ in Evaluation Split)
- **Production RF (22f):** TP = 2,992, FN = 44, **Recall = 98.55%**
- **Model 1: Augmented (22f):** TP = 2,765, FN = 271, **Recall = 91.07%**
- **Model 2: Experimental (30f):** TP = 2,932, FN = 104, **Recall = 96.57%**
- **Model 3: Calibrated (30f):** TP = 2,823, FN = 213, **Recall = 92.98%**

---

## 3. Detailed Inspection of Realistic Benchmark Predictions

Tracing individual URL predictions across the 4 models highlights key behavioral shifts:

```text
TYPE    | URL                                                | PROD   | M1(22f) | M2(30f) | M3(cal)
------------------------------------------------------------------------------------------
LEGIT   | https://www.youtube.com/watch?v=9l3IBjqJdFI&list   | 0.94   | 0.57    | 0.79    | 0.85   
LEGIT   | https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42   | 0.71   | 0.48*   | 0.57    | 0.37*  
LEGIT   | https://arxiv.org/search/cs?query=graph+neural+n   | 0.83   | 0.41*   | 0.72    | 0.77   
LEGIT   | https://scholar.google.com/scholar?hl=en&as_sdt=   | 0.73   | 0.37*   | 0.82    | 0.81   
LEGIT   | https://stackoverflow.com/questions/11227809/why   | 0.61   | 0.40*   | 0.67    | 0.63   
LEGIT   | https://medium.com/@author/deep-learning-in-prod   | 0.55   | 0.38*   | 0.78    | 0.70   
LEGIT   | https://developer.mozilla.org/en-US/docs/Web/API   | 0.50   | 0.41*   | 0.58    | 0.43*  
LEGIT   | https://service.vic.gov.au/services/renew-vehicl   | 0.50   | 0.48*   | 0.77    | 0.67   
LEGIT   | https://www.amazon.com/dp/B08N5WRWNW?ref_=cm_sw_   | 0.62   | 0.64    | 0.51    | 0.35*  
LEGIT   | https://www.coursera.org/learn/machine-learning/   | 0.66   | 0.51    | 0.48*   | 0.32*  
PHISH   | http://login-account-update.xyz/verify             | 0.19!  | 0.71*   | 0.64*   | 0.43   
PHISH   | http://netflix-billing-alert.com/login             | 0.12!  | 0.96*   | 0.67*   | 0.52*  
PHISH   | https://paypal.com.account-verification-notice.o   | 0.19!  | 0.96*   | 0.73*   | 0.68*  
PHISH   | http://192.241.220.14/portal/admin/login.php       | 0.23!  | 0.98*   | 0.72*   | 0.64*  

(* denotes correct prediction at threshold 0.50; ! denotes false negative in production)
```

### Critical Observations:
1. **Phishing Recall Fix:** Production missed `login-account-update.xyz` (0.19), `netflix-billing-alert.com` (0.12), `paypal.com...` (0.19), and `192.241.220.14` (0.23). **Model 1 detected all 4 successfully**, raising phishing recall from 73.33% to 100.00%.
2. **False Positive Relief in Model 1:** Model 1 successfully recovered 7 major complex legitimate URLs that Production misclassified: Google Scholar (0.37 vs 0.73), Stack Overflow (0.40 vs 0.61), ArXiv (0.41 vs 0.83), Medium (0.38 vs 0.55), MDN Docs (0.41 vs 0.50), VicGov (0.48 vs 0.50), and Rick Astley YouTube (0.48 vs 0.71).
3. **The Target YouTube Lecture URL:**
   - Production: **94.00% Phishing**
   - Model 1: **57.00% Phishing** (a massive 37 percentage point drop towards legitimate, but still above the 50% threshold).
   - Model 2: **78.72% Phishing**
   - Model 3: **84.66% Phishing**

---

## 4. Key Takeaways

1. **Model 1 (RF Augmented 22f)** is the best overall performer among experimental models, achieving the highest ROC-AUC on the realistic benchmark (0.8859 vs 0.4872), reducing FPR by 27 percentage points, and catching 100% of phishing URLs.
2. **Feature Expansion (Models 2 & 3)** did not resolve the problem and actually elevated false-positive probabilities on URLs with multiple query parameters. Decision trees learned that `query_param_cnt >= 2` was heavily correlated with phishing due to residual training data imbalance.
3. Neither Model 1, Model 2, nor Model 3 completely classifies the target YouTube lecture URL as legitimate (P < 0.50), demonstrating that **more representative legitimate data is strictly required**.
