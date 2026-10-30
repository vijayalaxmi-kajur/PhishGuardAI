# PhishGuardAI — Machine Learning Model Training Handbook & Technical Guide

**Project:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Pipeline Module:** `src/train.py`  
**Target:** Binary Classification ($0 = \text{Legitimate}, 1 = \text{Phishing}$)  
**Evaluation Dataset:** Untouched 20% Stratified Test Split (`data/processed/X_test.csv`, `y_test.csv`)  
**Test Sample Size:** 23,047 URLs (19,729 Legitimate, 3,318 Phishing)  

---

## 1. What is Supervised Machine Learning?

In cybersecurity, **Supervised Machine Learning** is a paradigm where an algorithm learns a mapping function from input feature vectors to known ground-truth labels using historical examples:

$$\hat{y} = f(X; \theta)$$

* **Input Vector ($X \in \mathbb{R}^{22}$):** The 22 numerical features extracted from the URL (e.g., character counts, entropy, domain length, ratio metrics).
* **Target Label ($y \in \{0, 1\}$):** $0$ represents a verified Legitimate URL; $1$ represents a verified Phishing URL.
* **Goal:** Learn optimal parameters $\theta$ during training that minimize prediction error on unseen web addresses.

---

## 2. Model Concept 1: Logistic Regression Pipeline

### Conceptual Mechanics:
Despite its name, **Logistic Regression** is a linear classifier for binary classification. It calculates a weighted linear combination of input features and passes it through the non-linear **Sigmoid (logistic) activation function** $\sigma(z)$ to map the output into a probability interval $[0, 1]$:

$$z = w_0 + \sum_{j=1}^{22} w_j x_j = w^T x + b$$

$$P(y=1 \mid x) = \sigma(z) = \frac{1}{1 + e^{-z}}$$

If $P(y=1 \mid x) \ge 0.5$, the URL is classified as Phishing ($1$); otherwise, it is classified as Legitimate ($0$).

### Why StandardScaler is Mandatory:
Features in our dataset possess vastly differing scales:
* `url_len` ranges from $12$ to $1,202$.
* `letter_ratio` ranges from $0.14$ to $0.94$.
* `is_ip` is binary $\{0, 1\}$.

Without feature standardization, features with larger magnitudes dominate the gradient descent updates regardless of their true predictive power.
$$\tilde{x}_j = \frac{x_j - \mu_j}{\sigma_j}$$
**Data Leakage Prevention:** The `StandardScaler` was fitted **strictly on the training data** ($X_{train}$) and transformed both $X_{train}$ and $X_{test}$ using the training statistics $(\mu_{train}, \sigma_{train})$. Test statistics were never exposed to the scaler.

---

## 3. Model Concept 2: Random Forest Classifier

### Conceptual Mechanics:
**Random Forest** is an **ensemble learning method** based on **Bootstrap Aggregating (Bagging)** and randomized decision trees:
1. **Bootstrapping:** Creates $B = 100$ distinct decision trees, each trained on a random bootstrap sample (sampling with replacement) of the training dataset.
2. **Feature Subsampling:** At each node split in each tree, only a random subset of features (typically $\sqrt{22} \approx 4$ or $5$ features) is considered. This decorrelates individual trees, preventing dominant features from dictating every split.
3. **Ensemble Aggregation (Majority Voting):**
   $$\hat{y}_{RF} = \text{mode}\left(T_1(x), T_2(x), \dots, T_{100}(x)\right)$$
   $$P_{RF}(y=1 \mid x) = \frac{1}{B} \sum_{b=1}^{B} P_b(y=1 \mid x)$$

### Why Random Forest Outperformed Logistic Regression:
URL phishing properties are inherently non-linear and conditional. For instance:
* A high digit count (`digit_cnt`) on a long URL path is dangerous *only if* the domain length is short or the TLD is disposable.
* Logistic Regression evaluates features independently as a linear sum ($w_1 x_1 + w_2 x_2$).
* Decision trees in Random Forest naturally capture these multi-way **hierarchical feature interactions** through recursive conditional splitting ($x_1 > \theta_1 \land x_2 < \theta_2$), drastically reducing false positives.

---

## 4. Why `class_weight="balanced"` is Mandatory

The clean dataset contains an authentic class imbalance of **~6 : 1** (85.6% Legitimate vs. 14.4% Phishing).

### The Inherent Problem:
Standard loss functions treat every misclassification equally. A naive model that always predicts Class 0 achieves **85.6% accuracy** while completely failing to detect any phishing attack.

### The Solution:
`class_weight="balanced"` computes class penalties inversely proportional to class frequencies:

$$w_k = \frac{N_{total}}{2 \times N_k}$$

* **Weight for Legitimate ($w_0$):** $\frac{92,184}{2 \times 78,912} \approx 0.584$
* **Weight for Phishing ($w_1$):** $\frac{92,184}{2 \times 13,272} \approx 3.473$

The loss function penalizes missing a phishing URL almost **6 times more heavily** than misclassifying a legitimate URL, forcing the algorithms to build robust decision boundaries around the minority phishing distribution.

---

## 5. Why the Test Set Must Remain Untouched

1. **Unbiased Generalization Estimate:** The test set ($23,047$ samples) represents future, unseen URLs. If parameters, feature scalers, or decision thresholds are adjusted using the test set, the evaluation becomes overly optimistic and invalid.
2. **Strict Protocol Followed:**
   * Scalers fitted strictly on $X_{train}$.
   * Model estimators fitted strictly on $(X_{train}, y_{train})$.
   * Zero hyperparameter tuning performed on $X_{test}$.
   * The test set was accessed only once for the final unbiased performance benchmark.

---

## 6. Evaluation Metrics Explained

| Metric | Mathematical Formula | Meaning in Phishing Defense |
| :--- | :--- | :--- |
| **Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN}$ | Overall percentage of correct predictions (deceptive under imbalance). |
| **Phishing Precision** | $\frac{TP}{TP + FP}$ | Out of all URLs flagged as phishing, how many were truly phishing? High precision means **minimal false alarms** for users. |
| **Phishing Recall** | $\frac{TP}{TP + FN}$ | Out of all actual phishing URLs, how many did the system successfully catch? High recall means **minimal missed security breaches**. |
| **Phishing F1-Score** | $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean balancing precision and recall. Primary comparison benchmark. |
| **ROC-AUC** | Area under TPR vs. FPR curve | Overall discrimination power across all possible probability thresholds ($0.5$ = random, $1.0$ = perfect). |
| **PR-AUC** | Area under Precision vs. Recall curve | Evaluator for minority classes; measures precision across recall levels without being skewed by large true negative counts. |

---

## 7. Actual Measured Experimental Results

Evaluated on the 23,047 test samples:

```text
================================================================================
MODEL BENCHMARK TABLE
================================================================================
Metric                      Logistic Regression    Random Forest Classifier
--------------------------------------------------------------------------------
Accuracy                    92.80%                 97.61%
Phishing Precision (1)      68.63%                 90.52%  (+21.89%)
Phishing Recall (1)         92.04%                 93.19%  (+1.15%)
Phishing F1-Score (1)       78.63%                 91.83%  (+13.20%)
Macro F1-Score              88.58%                 95.22%
ROC-AUC                     0.9766                 0.9913
PR-AUC                      0.8982                 0.9716
--------------------------------------------------------------------------------
CONFUSION MATRIX
True Negatives (Legit OK)   18,333                 19,405
False Positives (Alarm)      1,396                    324  (-76.8% alarms!)
False Negatives (Missed)       264                    226
True Positives (Blocked)     3,054                  3,092
================================================================================
```

---

## 8. Limitations & Viva Defense Discussion

To demonstrate engineering maturity during your project viva:

1. **Domain Overlap in Static Datasets:**
   While URL overlap was confirmed at strictly $0\%$, $10.84\%$ of domains in the test set share a registered domain with the training set (e.g. `google.com`, `github.io`, multi-page universities). In a real-world zero-day attack, phishers register brand new domains. Recommending a secondary **GroupKFold by domain** evaluation demonstrates deep understanding of threat dynamics.
2. **Static vs. Dynamic Analysis:**
   The model relies purely on static URL lexical, host, and entropy features. It does not inspect HTTP response body content or execute JavaScript. While this enables sub-millisecond classification without risky page visits, sophisticated attackers using cloaking or compromised clean domains may require complementary dynamic heuristic verification.
3. **Temporal Threat Drift:**
   Phishing tactics evolve rapidly (e.g., emerging disposable TLDs). Periodic retraining on fresh feeds (PhishTank/OpenPhish) is necessary in production.

---

## 9. How to Reproduce Training

Run these commands in PowerShell:

```powershell
# 1. Run all unit tests:
python -m unittest discover -s tests -v

# 2. Run the training pipeline:
python src/train.py
```
