# PhishGuardAI — Baseline Model Training & Evaluation Report

**Project:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Pipeline Module:** `src/train.py`  
**Execution Date:** 2026-10-28 12:55:45  
**Evaluation Dataset:** Untouched 20% Stratified Test Split (`data/processed/X_test.csv`, `y_test.csv`)  
**Test Sample Size:** 23,047 URLs (19,729 Legitimate, 3,318 Phishing)  

---

## 1. Executive Summary & Benchmark Comparison

Two baseline supervised machine learning models were trained on the 80% training set (92,184 samples) and rigorously evaluated on the untouched 20% test split (23,047 samples).

| Metric | Logistic Regression (StandardScaler) | Random Forest Classifier (100 Trees) | Variance / Delta |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 92.80% | **97.61%** | +4.82% |
| **Phishing Precision (Class 1)** | 68.63% | **90.52%** | **+21.89%** |
| **Phishing Recall (Class 1)** | 92.04% | **93.19%** | +1.15% |
| **Phishing F1-Score (Class 1)** | 78.63% | **91.83%** | **+13.20%** |
| **Macro F1-Score** | 87.15% | **95.22%** | +8.07% |
| **ROC-AUC** | 0.9766 | **0.9913** | +0.0147 |
| **PR-AUC (Avg Precision)** | 0.8982 | **0.9716** | **+0.0734** |
| **False Positives (False Alarms)** | 1,396 | **324** | **-76.8% false alarms** |
| **False Negatives (Missed Attacks)** | 264 | **226** | -38 missed attacks |

---

## 2. Confusion Matrix Breakdown

### Confusion Matrix Definitions for Phishing Detection:
* **True Negative (TN):** Legitimate URL correctly recognized as safe.
* **False Positive (FP) [False Alarm]:** Legitimate URL wrongly blocked as phishing (disrupts user experience).
* **False Negative (FN) [Missed Cyber Attack]:** Phishing URL wrongly allowed through as safe (causes security breach).
* **True Positive (TP):** Phishing URL correctly intercepted and blocked.

| Model | True Negatives (TN) | False Positives (FP) | False Negatives (FN) | True Positives (TP) |
| :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | 18,333 | 1,396 | 264 | 3,054 |
| **Random Forest** | **19,405** | **324** | **226** | **3,092** |

---

## 3. Detailed Model Analysis

### 1. Logistic Regression Pipeline
* **Preprocessing:** `StandardScaler` fitted strictly on training data ($X_{train}$), preserving zero leakage into test data ($X_{test}$).
* **Hyperparameters:** `solver='lbfgs'`, `class_weight='balanced'`, `random_state=42`, `max_iter=1000`.
* **Observations:** 
  Logistic Regression achieved strong recall (92.04%), but suffered from moderate precision (68.63%), generating **1,396 false alarms**.
  Because linear boundaries cannot model complex non-linear feature interactions (such as the joint relationship between `entropy`, `path_len`, and `digit_ratio`), it over-predicts phishing on complex legitimate URLs.

### 2. Random Forest Classifier
* **Architecture:** Ensemble of 100 randomized decision trees (`n_estimators=100`, `class_weight='balanced'`, `n_jobs=-1`, `random_state=42`).
* **Observations:**
  Random Forest decisively outperformed Logistic Regression across all metrics. It reduced false alarms by **76.8%** (from 1,396 down to **324**), while catching **3,092 phishing attacks** (93.19% recall).
  The resulting Phishing F1-Score of **91.83%** and PR-AUC of **0.9716** establish it as the superior baseline model.

---

## 4. Evaluation Visualizations

The following plots were generated and saved in `reports/figures/`:
1. `reports/figures/confusion_matrices_comparison.png`: Side-by-side comparison of TN, FP, FN, and TP counts.
2. `reports/figures/roc_curves_comparison.png`: Demonstrates discrimination capacity across thresholds (RF: 0.9913 vs. LR: 0.9766).
3. `reports/figures/precision_recall_curves_comparison.png`: Evaluates trade-offs on the imbalanced minority phishing class.

---

## 5. Candidate Model Recommendation

**Selected Candidate:** **Random Forest Classifier** (`models/phishing_model.joblib`)

**Rationale for Defense:**
1. **False Alarm Mitigation:** In cybersecurity systems, frequent false alarms cause user fatigue and rejection. Random Forest achieves 90.52% precision (vs. 68.63% for Logistic Regression).
2. **High Threat Interception:** Achieves 93.19% recall, catching 3,092 out of 3,318 phishing attacks.
3. **Inference Latency:** Despite having 100 trees, evaluating a single 22-element feature vector takes less than 1.5 milliseconds, making it suitable for live Flask API inference.
