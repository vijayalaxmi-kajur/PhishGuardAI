# PhishGuardAI — Realistic Evaluation Methodology & Dataset Construction Protocol

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Document Type:** Security Research & Evaluation Methodology Specification  
**Phase:** Phase 11 — Real-World False Positive Investigation  
**Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Target Dataset Created:** `data/realistic_evaluation_set.csv` (41 curated samples)  
**Preservation Status:** Strictly Isolated (Zero Overwrite of Original Training Data)  

---

## 1. Executive Summary & Purpose

Traditional academic phishing datasets (such as Mendeley URL-Phish, 2025) evaluate machine learning models using randomly partitioned splits of historic web crawls. While models trained on these datasets frequently report test accuracy exceeding 97%, they suffer catastrophic degradation when deployed against modern web applications. 

The purpose of this methodology is to define and establish a **Realistic Evaluation Protocol** that measures model resilience against real-world legitimate URLs exhibiting high structural complexity (long query strings, video identifiers, tracking parameters, pagination, and multi-tiered paths) while maintaining detection sensitivity against diverse phishing architectures.

---

## 2. Ethical, Operational & Safety Constraints

In accordance with strict security engineering standards:
1. **Zero Browser Execution / Passive String Analysis Only:**
   * Phishing URLs must never be opened or rendered in a standard web browser.
   * All feature extraction and evaluation operate strictly offline on the raw URI string (`urllib.parse`, `tldextract`, and character counting).
   * No HTTP requests, socket connections, or live DNS queries are transmitted to untrusted destinations.
2. **Provenance & Source Transparency:**
   * Every evaluated sample must record its collection source, date of ingestion, category, and verification status.
3. **No Ground-Truth Imputation from Model Predictions:**
   * Under no circumstances may an evaluation sample be labeled based on the prediction of the model under test.
4. **Separation of Verified Benchmarks from Unverified Stress Tests:**
   * URLs lacking definitive third-party corroboration must be labeled as `unverified_stress_case` and reported independently from verified performance metrics.

---

## 3. Structural Archetypes & Representation Requirements

To eliminate the legacy bias of evaluating only short, static root domains, the realistic evaluation set incorporates 12 structural archetypes across both classes:

```text
Class          Archetype Category                    Key Structural Features
---------------------------------------------------------------------------------------------------------------------
Legitimate     legit_video_and_playlist             Video IDs (`?v=`), playlist tokens (`list=`), timestamps (`t=`)
Legitimate     legit_search_and_pagination          Search terms (`?q=`, `?term=`), pagination (`page=`, `offset=`)
Legitimate     legit_ecommerce_and_catalog          Product ASINs, category slugs, catalog variant parameters
Legitimate     legit_analytics_and_tracking         UTM parameters (`utm_source`, `utm_medium`), session referral tokens
Legitimate     legit_academic_multi_subdomain       Multi-tiered institutional subdomains (`library.med.unsw.edu.au`)
Legitimate     legit_government_deep_path           Multi-level public suffixes (`.gov.au`), deep campaign paths
Legitimate     legit_documentation_deep_path        Nested directory structures, localized paths, anchor fragments
Legitimate     legit_http_enterprise_university     Legacy HTTP enterprise and university endpoints (no HTTPS)
Phishing       phish_short_clean_path               Evasive minimal paths on disposable TLDs (`.xyz`, `.top`)
Phishing       phish_multi_parameter                Spear-phishing harvesters pre-populating victim emails and session keys
Phishing       phish_free_hosting_builder           Exploit lures hosted on Weebly, Wix, Cloudflare Pages, Firebase
Phishing       phish_brand_subdomain_spoofing       Brand keywords embedded in subdomains (`paypal.com.account-update...`)
Phishing       phish_dga_subdomain                  Randomized, algorithmically generated high-entropy subdomains
Phishing       phish_direct_ip                      Direct IPv4/IPv6 host addressing with custom port numbers
Unverified     unverified_stress_case               Enterprise intranets, unexpanded shorteners, ambiguous startups
```

---

## 4. Evaluation Dataset Schema (`data/realistic_evaluation_set.csv`)

The realistic evaluation set is stored in `data/realistic_evaluation_set.csv` and contains the following standardized columns:

| Field Name | Type | Description |
|---|---|---|
| `url` | `string` | The complete, unparsed URL string under evaluation. |
| `label` | `int` | Binary ground-truth target: `0` (Legitimate) or `1` (Phishing). |
| `category` | `string` | Structural archetype (e.g., `legit_video_and_playlist`, `phish_short_clean_path`). |
| `source` | `string` | Authoritative provenance (e.g., `YouTube Educational Lecture`, `PhishTank ID #829104`). |
| `collection_date` | `string` | ISO 8601 date of observation (`2026-10-28`). |
| `verification_status` | `string` | Verification level: `verified_legitimate`, `verified_phishing`, or `unverified_stress_case`. |
| `verification_notes` | `string` | Cryptographic, DNS, or threat-intelligence verification justification. |

---

## 5. Statistical Partitioning & Dual-Benchmark Evaluation Framework

To prevent reporting metrics from small samples as proof of generalizability, all future evaluations must report results across two distinct benchmarks:

### Benchmark A: Large-Scale Benchmark (In-Distribution & Out-of-Distribution)
* **Dataset:** Clean processed splits from `Dataset.csv` ($N = 23,047$ random test split; $N = 23,045$ domain-held-out test split).
* **Purpose:** Ensures statistical significance and detects performance regressions across tens of thousands of samples.

### Benchmark B: Realistic Complexity Benchmark (Stress & Dynamic Validation)
* **Dataset:** `data/realistic_evaluation_set.csv` ($N = 41$; 38 verified, 3 unverified).
* **Purpose:** Specifically diagnoses model behavior on modern dynamic web services, parameter-heavy URLs, and evasive clean-path phishing attacks that are absent from legacy crawls.

---

## 6. Formal Evaluation Metrics Definitions

Models must be scored across both benchmarks using the following equations:

1. **Confusion Matrix Elements:**
   * $\text{True Negatives (TN)}$: Legitimate URLs correctly allowed as safe.
   * $\text{False Positives (FP)}$: Legitimate URLs incorrectly blocked as phishing (false alarm).
   * $\text{False Negatives (FN)}$: Phishing URLs incorrectly allowed through (security failure).
   * $\text{True Positives (TP)}$: Phishing URLs correctly intercepted and blocked.
2. **False Positive Rate (FPR):**
   $$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
3. **False Negative Rate (FNR / Miss Rate):**
   $$\text{FNR} = \frac{\text{FN}}{\text{FN} + \text{TP}}$$
4. **Precision (Phishing Class):**
   $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
5. **Recall (Phishing Class):**
   $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
6. **F1-Score (Phishing Class):**
   $$\text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
7. **Brier Score (Probabilistic Calibration):**
   $$\text{BS} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$$

---

## 7. Evidentiary Distinctions

* **Verified Facts from Actual Files:** The evaluation set `data/realistic_evaluation_set.csv` has been physically generated and populated with 41 records.
* **Measured Results:** Ground truth verification was completed for 38 out of 41 samples (23 legitimate, 15 phishing); 3 samples were isolated as unverified stress cases.
* **Hypotheses Needing Testing:** Evaluating models across both Benchmark A (large-scale) and Benchmark B (complexity stress) will prevent overfitting to simple academic heuristics.
* **Limitations:** The complexity benchmark contains 41 curated samples; expanding it to 500+ verified URLs during Phase C will increase statistical power.
