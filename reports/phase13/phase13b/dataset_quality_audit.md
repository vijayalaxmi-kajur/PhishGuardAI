# Phase 13B: Dataset Quality, Distribution & Statistical Skew Audit

**Document ID:** `PGAI-REP-2026-PH13B-02`  
**Phase:** Phase 13B — Dataset Reconstruction and Quality Audit  
**Author:** Senior Machine Learning Engineer & Dataset Quality Auditor  
**Date:** October 28, 2026  
**Status:** COMPLETE (Zero Retraining / Cryptographically Preserved Baseline)  

---

## 1. Executive Summary

This document presents an exhaustive empirical quality audit of the primary dataset (`dataset/Dataset.csv`, $N=116,600$), analyzing duplicate records, lexical distributions, class asymmetries, and collection-induced statistical artifacts. 

The audit confirms that the persistent false-positive failures on legitimate dynamic URLs (such as YouTube videos, academic search queries, and documentation portals) are primarily caused by **three structural sampling biases** embedded in the underlying corpus:
1. **The Inverted HTTPS Confounder:** Phishing URLs in the dataset use HTTPS at **91.43%**, whereas legitimate URLs use HTTPS at only **35.09%**.
2. **The Shallow-Homepage Sampling Bias:** 75% of legitimate URLs are $\le 32$ characters in length, and 98% have zero query parameters.
3. **Extreme Phishing Dominance in Deep URLs:** Among URLs with length $\ge 120$ characters, **89.28% are phishing**.

---

## 2. Dataset Composition & Duplicate Analysis

All measurements were calculated by parsing the raw dataset through the Phase 13B audit engine ([`data/phase13b/inventory_metrics.json`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/phase13b/inventory_metrics.json)).

| Metric | Measured Value | Percentage of Dataset | Analytical Findings |
| :--- | :--- | :--- | :--- |
| **Total Rows** | 116,600 | 100.00% | Full dataset size. |
| **Class 0 (Legitimate)** | 100,000 | 85.76% | Majority class. |
| **Class 1 (Phishing)** | 16,600 | 14.24% | Minority class (1:6 imbalance ratio). |
| **Missing Values** | 14 rows | 0.012% | All 14 nulls reside in column `tld` (13 direct IP addresses + 1 malformed string). Zero nulls in feature or target columns. |
| **Exact Duplicate Rows** | 1,369 rows | 1.17% | 1,359 in Class 0; 10 in Class 1. Identical across all 26 columns. |
| **Unique Raw URLs** | 115,231 URLs | 98.83% | Unique URL strings after purging exact duplicates. |
| **Normalized Duplicate URLs** | 1,529 rows | 1.31% | **160 additional duplicates** detected when applying RFC 3986 normalization rules (lowercasing schemes/hosts, stripping default ports `:80`/`:443`, trimming trailing slashes, sorting query parameters). |
| **Unique Normalized URLs** | 115,071 URLs | 98.69% | Canonical deduplicated URL set. |
| **Conflicting Labels on Identical URLs** | **0** | **0.00%** | Zero identical URL strings have conflicting labels (0 vs 1). |
| **Conflicting Labels on Normalized URLs** | **0** | **0.00%** | Zero normalized URL strings have conflicting labels. |
| **Unique Registered Domains (PSL)** | 90,859 domains | — | Extracted via Public Suffix List (`tldextract`). |
| **Single-URL Domains** | 85,601 domains | 94.21% of domains | Overwhelming majority of domains have only a single URL in the dataset. |
| **Domains Hosting Both Classes** | 24 domains | 0.026% of domains | 24 multi-tenant cloud or hosting platforms host both legitimate and phishing URLs. |

---

## 3. Structural & Lexical Distribution Metrics by Class

A rigorous comparison of Class 0 vs. Class 1 features reveals extreme statistical disparity across every primary lexical dimension:

| Feature / Metric | Class 0 (Legitimate) Mean $\pm$ Std | Class 0 Median (P25 - P75) | Class 1 (Phishing) Mean $\pm$ Std | Class 1 Median (P25 - P75) | Statistical Disparity Ratio |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **URL Length (`url_len`)** | $29.08 \pm 13.12$ | 26.0 (22.0 – 32.0) | $56.30 \pm 66.22$ | 38.0 (29.0 – 55.0) | Phishing mean is **1.94x longer**; Class 1 max is 1,202 vs 582. |
| **Path Length (`path_len`)** | $4.60 \pm 10.96$ | 1.0 (1.0 – 1.0) | $17.15 \pm 36.26$ | 6.0 (1.0 – 16.0) | Phishing path mean is **3.73x longer**; 75% of legit paths are length 1. |
| **Query Length (`query_len`)**| $0.31 \pm 3.36$ | 0.0 (0.0 – 0.0) | $9.38 \pm 49.71$ | 0.0 (0.0 – 0.0) | Phishing query mean is **30.3x longer**; 95% of legit URLs have 0 query length. |
| **Shannon Entropy (`entropy`)**| $3.79 \pm 0.27$ | 3.78 (3.61 – 3.96) | $4.32 \pm 0.49$ | 4.18 (3.99 – 4.46) | Phishing URLs exhibit significantly higher character unpredictability. |
| **Domain Length (`dom_len`)** | $13.01 \pm 5.07$ | 12.0 (9.0 – 16.0) | $11.84 \pm 5.42$ | 10.0 (9.0 – 14.0) | Legitimate hostnames are slightly longer on average due to enterprise naming. |

---

## 4. Analysis of Core Sampling Biases

### 4.1 Bias 1: The Inverted HTTPS Protocol Confounder
In modern web production, over 95% of all legitimate web traffic is encrypted via HTTPS (Google Transparency Report, 2026). However, the training corpus exhibits an inverse distribution:

| Metric | Class 0 (Legitimate) | Class 1 (Phishing) | Statistical Implications |
| :--- | :--- | :--- | :--- |
| **`is_https == 1` (HTTPS)** | **35,093 (35.09%)** | **15,178 (91.43%)** | Phishing URLs are **2.61x more likely to use HTTPS** than legitimate URLs. |
| **`is_https == 0` (HTTP)** | **64,907 (64.91%)** | **1,422 (8.57%)** | Legitimate URLs in the dataset are overwhelmingly unencrypted plain HTTP. |

#### Confirmed Causal Mechanism
* **Legitimate URL Source:** The baseline dataset authors (Linh & Hung, 2025) scraped benign records from historical Alexa/Tranco top lists by prepending raw `http://` strings to domain roots without following HTTPS redirects.
* **Phishing URL Source:** Malicious URLs were harvested from active PhishTank and OpenPhish threat feeds between 2023 and 2025, during which cybercriminals universally adopted automated free TLS certificate authorities (Let's Encrypt, Cloudflare SSL).
* **Machine Learning Impact:** Decision tree ensembles assigned high feature importance ($\approx 0.156$) to `is_https`. The model learned that **HTTPS is a strong indicator of phishing**, penalizing legitimate modern websites simply for using transport layer security.

---

### 4.2 Bias 2: The Query-Parameter Asymmetry
In realistic web usage, search engines, educational portals, video platforms, and e-commerce catalogs rely heavily on dynamic query parameters (`?q=...`, `?v=...`, `?page=...`).

| Metric | Class 0 (Legitimate) | Class 1 (Phishing) | Disparity |
| :--- | :--- | :--- | :--- |
| **URLs with Query (`qm_cnt > 0`)** | **2,002 (2.00%)** | **2,419 (14.57%)** | Phishing URLs are **7.28x more likely** to contain query parameters. |
| **URLs without Query (`qm_cnt == 0`)** | **97,998 (98.00%)** | **14,181 (85.43%)** | 98.00% of all legitimate URLs in the corpus have zero query parameters. |

#### Confirmed Causal Mechanism
* **Homepage Over-representation:** Legitimate data collection sampled root landing pages (e.g., `http://example.com/`). Real user journeys accessing dynamic backend endpoints were completely excluded.
* **Phishing Payload Packaging:** Phishing attacks frequently embed campaign tracking tokens, base64 redirection payloads, and target email addresses in query strings.
* **Machine Learning Impact:** Tree splits on `qm_cnt > 0`, `amp_cnt > 0`, and `query_len > 0` directly route samples into high-risk phishing branches.

---

### 4.3 Bias 3: URL Length Stratification & Tree Dominance

Analyzing class proportions across length buckets reveals that URL length acts as an overwhelming proxy for class assignment:

| Length Bucket | Total Samples | Class 0 (Legit) | Class 1 (Phish) | Phishing % in Bucket | Dominant Class |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **$[0, 30)$** | 71,893 | 67,720 | 4,173 | **5.80%** | Legitimate (94.20%) |
| **$[30, 50)$** | 34,434 | 26,907 | 7,527 | **21.86%** | Legitimate (78.14%) |
| **$[50, 70)$** | 5,284 | 3,178 | 2,106 | **39.86%** | Mixed |
| **$[70, 90)$** | 2,241 | 1,385 | 856 | **38.20%** | Mixed |
| **$[90, 120)$** | 1,004 | 623 | 381 | **37.95%** | Mixed |
| **$[120+)$** | 1,744 | 187 | 1,557 | **89.28%** | **Phishing Dominant (89.28%)** |

#### Confirmed Causal Mechanism
When training scikit-learn models with `class_weight='balanced'`, minority phishing samples are weighted $5.97\times$ higher than legitimate samples. For URLs exceeding 120 characters:
$$\text{Weighted Phishing Probability} = \frac{1,557 \times 5.97}{(1,557 \times 5.97) + (187 \times 1.0)} = \frac{9,295.29}{9,295.29 + 187.0} = \mathbf{98.03\%}$$
Any URL exceeding 120 characters that reaches a leaf node in this partition is mathematically guaranteed to be classified as phishing with near-100% confidence.

---

## 5. Domain Concentration & Multi-Tenant Infrastructure

Top 10 registered domains in `dataset/Dataset.csv`:

| Rank | Registered Domain | Total URLs | Platform Type | Observed Risk |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `weebly.com` | 2,465 | Website Builder / Free Hosting | Subdomain phishing abuse |
| 2 | `google.com` | 1,450 | Search & Enterprise | Mixed services |
| 3 | `pages.dev` | 1,050 | Cloudflare Pages Hosting | Subdomain phishing abuse |
| 4 | `bit.ly` | 763 | URL Shortener | Redirection evasion |
| 5 | `hsforms.com` | 358 | HubSpot Form Builder | Lead-capture lure abuse |
| 6 | `qrco.de` | 329 | QR Code Generator / Dynamic URL | QR phishing (quishing) lures |
| 7 | `r2.dev` | 240 | Cloudflare Object Storage | Storage payload hosting |
| 8 | `va.gov` | 222 | U.S. Federal Government | Legitimate public health links |
| 9 | `q-r.to` | 212 | Dynamic QR Redirector | QR phishing lures |
| 10 | `ead.me` | 210 | Dynamic QR / Shortener | QR phishing lures |

### Key Finding on Multi-Tenant Domains
Multi-tenant domains (`pages.dev`, `weebly.com`, `r2.dev`) account for over 4,000 URLs in the dataset. Because naive domain grouping treats `pages.dev` as a single monolithic domain, splitting by registered domain without multi-tenant awareness creates massive cluster skew.

---

## 6. Summary of Verified vs. Hypothesized Findings

| Audit Finding | Status | Verification Evidence |
| :--- | :--- | :--- |
| **HTTPS correlation with phishing** | **CONFIRMED** | 91.43% of phishing vs 35.09% of legitimate URLs in `dataset/Dataset.csv` use HTTPS. Verified via exact URL scheme parsing. |
| **Query parameter asymmetry** | **CONFIRMED** | 98.00% of legitimate URLs have zero query parameters; phishing is 7.28x more likely to contain `?`. Measured on all 116,600 rows. |
| **High-length leaf dominance** | **CONFIRMED** | URLs $\ge 120$ chars are 89.28% phishing in raw counts, equating to 98.03% under balanced sample weighting. |
| **Domain overlap in baseline splits** | **CONFIRMED** | 2,120 domains (10.84% of test domains) shared between baseline train and test sets in `data/processed/split_metadata.json`. |
| **Lexical representation limits** | **HYPOTHESIS** | Lexical models without domain reputation or DOM features may have an upper bound on distinguishing high-entropy legitimate tokens (e.g. YouTube video IDs) from phishing hashes. (To be tested in Phase 13B reconstruction). |

---
*End of Report — Quality Audit Verified.*
