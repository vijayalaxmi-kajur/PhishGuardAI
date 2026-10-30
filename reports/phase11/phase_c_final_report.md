# Phase C Final Comprehensive Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Scope:** Phase C Final Synthesis, Acceptance Criteria Audit, and Strategic Recommendations  
**Project:** PhishGuardAI  

---

## 1. Executive Summary & Objective Review

The Phase C engineering investigation addressed the critical issue where PhishGuardAI's production Random Forest model incorrectly classified legitimate complex URLs—such as YouTube video links—as phishing with high confidence (~94% probability).

### Core Directives Followed:
- **Strict Read-Only Preservation:** The live application ([`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py)), production dataset ([`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)), and production model ([`models/phishing_model.joblib`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib)) were preserved with cryptographic verification.
- **Zero Safe-List Hardcoding:** No domains (YouTube or otherwise) were exempted or hardcoded as safe. All predictions stem strictly from mathematical feature calculations and tree decisions.
- **Leakage-Free Experimental Design:** All experimental training and evaluation partitions were decoupled with zero domain overlap and zero near-duplicate leakage.
- **Honest Metric Reporting:** Findings are presented transparently without statistical distortion or inflated claims.

---

## 2. Experimental Deliverables Summary

| Artifact Type | File Path | Status / Description |
| :--- | :--- | :--- |
| **Pre-Phase C Hashes** | [`data/experiments/pre_phase_c_baseline_hashes.json`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/pre_phase_c_baseline_hashes.json) | SHA-256 hashes of all 16 production files |
| **Experimental Training Data** | [`data/experiments/phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv) | 91,486 de-duplicated URLs, 41,208 domains |
| **Experimental Evaluation Data**| [`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv) | 22,871 de-duplicated URLs, 10,302 domains |
| **Feature Extractor** | [`src/experiments/phase_c_features.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/phase_c_features.py) | 22 baseline + 8 component-isolated features |
| **Training Pipeline** | [`src/experiments/phase_c_train.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/phase_c_train.py) | Reproducible training and multi-slice evaluation |
| **Model 1 Artifact** | `models/experiments/phase_c/rf_augmented_22f.joblib` | RF on augmented data with 22 features |
| **Model 2 Artifact** | `models/experiments/phase_c/rf_experimental_30f.joblib` | RF on augmented data with 30 features |
| **Model 3 Artifact** | `models/experiments/phase_c/rf_calibrated_30f.joblib` | Platt-calibrated RF with 30 features |
| **Evaluation Metrics JSON** | [`models/experiments/phase_c/phase_c_evaluation_results.json`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/experiments/phase_c/phase_c_evaluation_results.json) | Complete machine-readable benchmark metrics |
| **Baseline Report** | [`reports/phase11/phase_c_baseline.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/phase_c_baseline.md) | Baseline reproduction and SHA-256 state |
| **Dataset Report** | [`reports/phase11/phase_c_dataset.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/phase_c_dataset.md) | Provenance, deduplication, and partitioning |
| **Feature Report** | [`reports/phase11/phase_c_feature_comparison.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/phase_c_feature_comparison.md) | 22f vs 30f schema comparison & tree splits |
| **Model Report** | [`reports/phase11/phase_c_model_comparison.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/phase_c_model_comparison.md) | Benchmark comparison across all 4 models |
| **Final Report** | [`reports/phase11/phase_c_final_report.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/phase_c_final_report.md) | This document |

---

## 3. Investigation of the Target YouTube Video URL

**Target URL:**
```text
https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4
```

### Model Prediction Comparison:
- **Production RF (22f, unaugmented):** P(Phishing) = **94.00%**, P(Legitimate) = 6.00% -> **Phishing** (Incorrect, FP).
- **Model 1: RF Augmented (22f, baseline arch):** P(Phishing) = **57.00%**, P(Legitimate) = 43.00% -> **Phishing** (Incorrect, FP, but a **37 percentage point drop** towards legitimate).
- **Model 2: RF Experimental (30f, regularized):** P(Phishing) = **78.72%**, P(Legitimate) = 21.28% -> **Phishing** (Incorrect, FP).
- **Model 3: RF Calibrated (30f, platt scaled):** P(Phishing) = **84.66%**, P(Legitimate) = 15.34% -> **Phishing** (Incorrect, FP).

### Engineering Diagnosis:
1. Adding 74 curated examples shifted Model 1 from 94% down to 57%, demonstrating that supplying legitimate complex URLs actively softens the tree splits.
2. However, because 78,495 legitimate training URLs were overwhelmingly shallow institutional pages (only 2.11% with queries), the empirical prior odds of a URL with `entropy > 5.2` and `amp_cnt >= 2` remains over 80% phishing in the dataset.
3. In Model 2 and Model 3, explicitly extracting `query_param_cnt` caused decision trees to learn a high-information-gain split: `query_param_cnt >= 2` -> branch to Phishing (because 1,630 phishing URLs had multiple parameters vs only 350 legitimate URLs).
4. **Root Conclusion:** A machine learning model cannot reliably distinguish benign query IDs from malicious tokens using lexical features alone when benign query URLs are virtually absent from the training distribution.

---

## 4. Evaluation Against Phase C7 Acceptance Criteria

| Criterion | Requirement | Empirical Result | Status |
| :--- | :--- | :--- | :---: |
| **1. Meaningful Reduction in False Positives** | Demonstrable drop in FPR on realistic complex URLs | Model 1 reduced FPR on realistic benchmark from **84.62% to 57.69%** (recovering 7 major sites: Google Scholar, Stack Overflow, ArXiv, Medium, MDN Docs, VicGov, and Rick Astley YouTube). | **PARTIALLY MET** (Improved by 27%, but 57.7% FPR is still unacceptable for production) |
| **2. Preservation of Phishing Recall** | No unacceptable loss of attack detection | Phishing recall on realistic benchmark rose from **73.33% to 100.00%** (0 false negatives in Model 1 and Model 2). On 22k held-out split, recall was 91.10% (Model 1) and 96.40% (Model 2). | **FULLY MET** |
| **3. Generalization to Unseen Domains** | Reliable performance on out-of-distribution domains | Evaluated on 10,302 completely unseen registered domains. Accuracy remained at **96.96% - 97.87%**, and FPR remained at **1.28% - 2.07%**. | **FULLY MET** |
| **4. Zero Data Leakage** | No domain or near-duplicate overlap between train and test | Evaluated with `StratifiedGroupKFold` by domain. Exact domain overlap = **0**. Near-duplicate overlap = **0**. | **FULLY MET** |
| **5. Correct Feature Extraction** | Exact calculation, offline safety, no network dependencies | Mathematical parity verified on baseline; component isolation verified on experimental schema. Zero network calls. | **FULLY MET** |
| **6. Reproducibility** | Fixed random seeds, deterministic outputs, saved artifacts | Fixed seed 42 used throughout. All data, models, and metadata dumped to disk. | **FULLY MET** |
| **7. Target YouTube URL Resolution** | Correctly classified as legitimate (P < 0.50) without cheating | Probability dropped from 94% to 57% in Model 1, but did not cross below 50%. | **NOT MET** |

### Acceptance Verdict: **DO NOT DEPLOY TO PRODUCTION**

While Model 1 represents an improvement over the Production RF baseline in recall (100% vs 73.3%) and achieves a substantial probability reduction on complex legitimate sites, it **fails the acceptance criteria** because its false positive rate on complex legitimate URLs remains at 57.69%, and the target YouTube URL remains misclassified at the default 0.50 threshold (57.00% probability).

---

## 5. Unresolved Limitations & Strategic Recommendations

### Unresolved Limitations:
1. **Severe Dataset Sampling Asymmetry:** The legacy base dataset ([`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)) has 100,000 legitimate URLs that are 98% shallow homepages. Injecting 45 complex legitimate URLs is statistically insufficient to counter-balance 16,600 phishing URLs with deep paths and parameters.
2. **Lexical Feature Ceiling:** Pure lexical analysis cannot inspect SSL certificates, DNS age, WHOIS registration, or page DOM content. When an attacker and a legitimate developer both use a URL structure like `domain.com/path?id=XyZ9`, lexical features alone cannot definitively separate them without external reputation signals.

### Recommended Next Steps (For User Explicit Approval):
1. **Large-Scale Benign Web Ingestion:** Ingest 25,000+ legitimate dynamic URLs with query strings from public web-crawl datasets (e.g., Common Crawl or Tranco deep-link crawls) into the experimental training set.
2. **Dual-Threshold / Abstention Architecture:** Introduce a multi-tier threshold policy in `src/predict.py`:
   - $P \ge 0.70$: High Confidence Phishing
   - $0.35 \le P < 0.70$: Suspicious / Needs Verification (Avoids hard blocking legitimate video/catalog links)
   - $P < 0.35$: Low Risk Legitimate
3. **Optional External Signals:** Incorporate domain age / reputation lookups for URLs with high query entropy to confirm domain legitimacy before flagging.

---

## 6. Strict Stop Notice

In strict accordance with project instructions:
- **No production files were modified.**
- **`app.py` was not edited.**
- **`models/phishing_model.joblib` was not replaced.**
- **The live production server continues to run undisturbed.**
- **Execution is stopped awaiting the user's explicit instructions.**
