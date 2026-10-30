# Phase 14A: Dataset Coverage & Bias Analysis Report

**Auditor:** Senior Machine Learning Engineer, Cybersecurity Researcher & Independent Evaluator  
**Phase:** 14A — Independent Evaluation Dataset Construction & Integrity Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & EMPIRICALLY AUDITED  
**Dataset Analyzed:** [phase14a_verified_evaluation_set.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase14a/cleaned/phase14a_verified_evaluation_set.csv) ($N=963$)

---

## 1. Executive Summary

This report evaluates the structural coverage, anatomical diversity, and potential sampling biases within the **Phase 14A Verified Evaluation Set** ($N = 963$).

To prevent evaluation overfitting, an evaluation corpus must not consist solely of clean homepage URLs or uniform length distributions. It must challenge the detection system across realistic variations in URL length, query parameter complexity, protocol schemes, path depths, and domain architectures.

### Primary Coverage Findings
1. **Length Diversity:** URL lengths span from **19 characters** (minimalist root paths) up to **507 characters** (deep multi-parameter tokens). Mean length is **86.30 chars**; median is **81.0 chars**.
2. **Query Complexity Representation:** **145 URLs (15.06%)** contain dynamic query parameters, providing an uninfluenced test bed for evaluating the query-parameter false positive issue.
3. **Class Distribution:** The verified evaluation set contains **163 Legitimate URLs (16.93%)** and **800 Phishing URLs (83.07%)**. We deliberately report this real-world imbalance rather than manufacturing an artificial 50/50 split by inventing records.
4. **Protocol Distribution:** **153 URLs (15.89%)** use HTTPS, while **810 URLs (84.11%)** use HTTP. The high HTTP proportion in the phishing cohort reflects the widespread deployment of phishing pages on unencrypted, legacy-compromised shared hosting accounts (`000webhostapp.com`).

---

## 2. Structural Dimension Distributions

Below are the measured empirical distributions for the 963 verified records:

### 2.1 URL Length Distribution

```
====================================================================================================
URL LENGTH DISTRIBUTION (N = 963)
----------------------------------------------------------------------------------------------------
  Minimum Length:          19 characters
  25th Percentile:         61 characters
  Median (50th):           81 characters
  Mean:                    86.30 characters
  75th Percentile:        108 characters
  Maximum Length:         507 characters
----------------------------------------------------------------------------------------------------
  Bins:
    Short URLs [0, 50) chars:       131 URLs (13.60%)
    Medium URLs [50, 90) chars:     434 URLs (45.07%)
    Long URLs [90, 150) chars:      302 URLs (31.36%)
    Very Long URLs [150+) chars:     96 URLs  (9.97%)
====================================================================================================
```

### 2.2 Protocol and Query String Breakdown by Class

| Dimension | Total Count ($N=963$) | Class 0 (Legitimate, $N=163$) | Class 1 (Phishing, $N=800$) | Representation Notes |
| :--- | :--- | :--- | :--- | :--- |
| **HTTPS Protocol** | 153 (15.89%) | **143 (87.73%)** | 10 (1.25%) | Legitimate URLs are modern encrypted portals. |
| **HTTP Protocol** | 810 (84.11%) | 20 (12.27%) | **790 (98.75%)** | Phishing feed heavily features free HTTP hosting. |
| **With Query Parameters**| 145 (15.06%) | 77 (47.24%) | 68 (8.50%) | Strong representation of benign dynamic queries. |
| **Without Query** | 818 (84.94%) | 86 (52.76%) | 732 (91.50%) | Standard paths and credential harvester pages. |

---

## 3. Functional and Anatomical Category Coverage

The evaluation set covers 8 distinct functional categories:

```
Category Representation Breakdown:
  1. phish_credential_harvesting_path : 702 URLs (72.90%)  [Active phishing credential harvesters]
  2. legit_documentation_deep_path    :  79 URLs  (8.20%)  [Rust, Go, Linux Kernel, IETF, PyPI docs]
  3. phish_multi_parameter_token      :  68 URLs  (7.06%)  [Phishing lures with complex tracking tokens]
  4. legit_academic_search_query      :  43 URLs  (4.47%)  [Europe PMC, Wiktionary, PyPI searches]
  5. phish_free_hosting_builder       :  30 URLs  (3.12%)  [Phishing on Pages.dev, Square.site, Weebly]
  6. legit_community_technical_qa     :  16 URLs  (1.66%)  [SuperUser, ServerFault, Unix Q&A threads]
  7. legit_government_portal          :  15 URLs  (1.56%)  [USGS, NOAA, UK Legislation, Data.gov.au]
  8. legit_institutional_http         :  10 URLs  (1.04%)  [Historical unencrypted academic mirrors]
```

---

## 4. Assessment of Sampling Biases and Real-World Relevance

### Bias 1: Class Imbalance (83% Phishing vs 17% Legitimate)
- **Observation:** The dataset contains roughly 4.9 times more phishing examples than legitimate examples.
- **Why this occurred:** In Phase 14A, we prioritized **high-integrity verification over volume**. While automated streaming from active threat feeds yielded 800 clean, verified phishing lures rapidly, legitimate URLs were curated individually from official documentation repositories, government portals, and academic registries to ensure zero label noise.
- **Methodological Impact:** When evaluating models in Phase 14B, class imbalance means that aggregate accuracy will be skewed toward phishing recall. Therefore, **balanced metrics (Macro F1-Score, False Positive Rate, False Negative Rate, and PR-AUC)** must be reported alongside accuracy.

### Bias 2: Protocol Imbalance in Phishing Feed (HTTP Dominance)
- **Observation:** 98.75% of the streamed phishing URLs utilize plain `http://`.
- **Root Cause:** A large portion of active phishing links in `Phishing.Database` are deployed on legacy compromised websites and free staging tiers of hosting services (e.g. `000webhostapp.com`) that do not enforce SSL redirection.
- **Diagnostic Value:** This provides an authentic test of whether the model has unlearned the inverted HTTPS bias (which assumed HTTP meant phishing). The inclusion of 20 verified legitimate plain HTTP URLs ensures the model cannot simply classify all HTTP sites as malicious.

### Bias 3: Free Web Host Clustering in Phishing Lures
- **Observation:** 412 phishing URLs are subdomains of `000webhostapp.com`.
- **Root Cause:** Threat actors frequently generate disposable, automated subdomains on free hosting providers to host credential-harvesting forms.
- **Diagnostic Value:** Evaluates how the model and the `LayeredDecisionEngine` handle multi-tenant hosting abuse when each subdomain is a distinct attack campaign.

---

## 5. Coverage Audit Verdict

1. **Diversity Assessment:** **ACCEPTABLE & FIT FOR PURPOSE.**
   The dataset provides diverse structural challenges across length, path depth, query presence, and institutional categories.
2. **Scientific Honesty:** No synthetic examples were invented to create a false balance. The real-world distribution is documented transparently.
3. **Execution Guidance for Phase 14B:** When evaluating Candidate 4 and Candidate 6, analysts must evaluate performance separately on the **Query-Bearing Slice ($N=145$)** and the **Plain HTTP Legitimate Slice ($N=20$)** to measure genuine generalization.
