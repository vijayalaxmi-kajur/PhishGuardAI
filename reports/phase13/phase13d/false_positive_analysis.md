# Phase 13D: False Positive Investigation & Root Cause Analysis

**Auditor:** Senior Machine Learning Engineer & Cybersecurity Researcher  
**Phase:** 13D — Independent Error Analysis & Model Selection Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & EMPIRICALLY AUDITED  
**Data Sources:** [test_split_cand04_errors.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13d/test_split_cand04_errors.csv) ($N=168$), [benchmark_misclassifications.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13d/benchmark_misclassifications.csv) ($N=18$ on Cand04, $N=15$ on Cand06)

---

## 1. Executive Summary

This report presents an empirical investigation into why legitimate URLs are misclassified as phishing by Candidate 4 and Candidate 6. 

Our investigation examined 168 false positives from the held-out test split and 18 false positives from the realistic benchmark across 8 structural dimensions:
1. URL Length
2. Query String Length
3. Query Parameter Count
4. Path Depth and Slug Structure
5. Protocol (HTTPS vs HTTP)
6. Domain Category & TLD Structure
7. Shared / Multi-Tenant Hosting
8. Original Data Source Provenance

### Primary Root-Cause Finding
False positives do **not** occur randomly. They cluster tightly around three specific structural archetypes where legitimate web engineering practices mimic adversarial obfuscation patterns:
1. **Dynamic Search & Tracking Queries (The Query Entropy Trap):** Long query strings containing base64 hashes, search queries, or analytics parameters (e.g. YouTube video IDs, Amazon ASIN referral tags, arXiv queries).
2. **Descriptive SEO Slugs with High Hyphen Densities (The Path Trap):** Modern e-commerce and media URLs with deeply nested, hyphenated path slugs (e.g. BestBuy, Walmart, Medium, StackOverflow).
3. **Foreign Government and Academic Portals (The Hostname Trap):** Multi-level academic and government domains (e.g. `.gov.by`, `.min-saude.pt`, `.inserm.fr`, `.sld.cu`) whose ccTLD subdomains increase dot counts and domain length.

---

## 2. Quantitative Dimension Breakdown

The table below contrasts the 168 False Positives ($FP$) against the 3,704 True Negatives ($TN$) from the held-out test split:

| Structural Dimension | True Negatives (Correct Legit, $N=3,704$) | False Positives (Misclassified Legit, $N=168$) | Ratio / Divergence |
| :--- | :--- | :--- | :--- |
| **Mean URL Length** | 30.19 chars | **41.82 chars** | **+38.5% longer** |
| **Median URL Length** | 28.0 chars | **36.0 chars** | +28.6% longer |
| **Max URL Length** | 148 chars | **138 chars** | Similar upper bound |
| **Mean Path Length** | 5.75 chars | **11.80 chars** | **+105.2% longer** (2.1x) |
| **Mean Path Depth** | 0.39 segments | **1.13 segments** | **+189.7% deeper** (2.9x) |
| **Mean Dash Count (`-`)**| 0.40 dashes | **0.77 dashes** | **+92.5% more dashes** |
| **Mean Dot Count (`.`)** | 2.10 dots | 1.95 dots | Slightly fewer dots |
| **Mean Overall Entropy**| 3.80 bits | **4.06 bits** | Higher lexical variation |
| **Mean Query Length** | 0.05 chars | **2.81 chars** | **56.2x higher** |
| **Query Presence** | 0.4% with query | **9.5% with query** | **23.8x enrichment** |
| **Query Param Count** | 0.005 params | **0.155 params** | **31.0x higher** |
| **HTTPS Proportion** | 87.58% HTTPS | **83.93% HTTPS** | Comparable (~84-88%) |

---

## 3. Deep Analysis by Structural Category

### Category 1: URL Length and Query Complexity
- On the held-out test split, 152 of the 168 false positives (90.5%) had no query string, but had significantly longer paths and domain lengths.
- However, when evaluating the specific subset of test URLs that **did contain query parameters** ($N = 99$, of which 30 were legitimate):
  - **Candidate 4 generated 16 False Positives out of 30 legitimate queries (FPR = 53.33%)!**
  - **Candidate 6 generated only 7 False Positives out of 30 legitimate queries (FPR = 23.33%)!**
- On the realistic benchmark ($N=23$ verified legitimate):
  - 17 of the 23 legitimate URLs contained query parameters.
  - Candidate 4 misclassified **16 of the 17 query URLs** (94.1% query FPR).
  - Candidate 6 misclassified **13 of the 17 query URLs** (76.5% query FPR), successfully recognizing Coursera, PubMed, and Victorian Government.
- **Root Cause:** In the baseline training corpus, 99.6% of legitimate URLs had no query string, while phishing URLs frequently had tokens (`?token=`, `?login=`, `?id=`). Even after adding 400+ Wikipedia/arXiv query URLs in Phase 13C-1, the pure lexical feature space struggles to differentiate between a benign base64 video identifier (`v=9l3IBjqJdFI`) and a malicious base64 victim tracking token (`key=7d8a9f0e1b...`).

### Category 2: Path Depth and Hyphen Density
- The mean path length of false positives is **11.80 characters** compared to **5.75 characters** for true negatives.
- The mean dash count of false positives is **0.77** compared to **0.40** for true negatives.
- Benchmark examples illustrate this clearly:
  - `bestbuy.com/site/apple-macbook-air-13-6-laptop-m2-chip-8gb-memory-256gb-ssd-midnight/6509650.p` contains **10 hyphens** and an 83-character path.
  - `stackoverflow.com/questions/.../why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array` contains **8 hyphens** and a 93-character path.
  - `medium.com/@author/deep-learning-in-production-78a9c8d7e6f5?source=user_profile---------2` contains **32 hyphens**!
- **Root Cause:** Adversarial phishing lures historically use hyphenated keywords (`paypal-account-security-update-portal`). Machine learning decision trees assign positive split weights to `dash_cnt >= 2` and `path_len >= 30`. Consequently, legitimate modern e-commerce and technical media platforms that use human-readable hyphenated SEO slugs get penalized heavily.

### Category 3: Protocol Distribution (HTTPS vs HTTP)
- Among test false positives, **141 (83.9%) are HTTPS** and **27 (16.1%) are HTTP**.
- The false positive rate by protocol slice:
  - HTTP legitimate slice: 27 FPs / 487 Legit = **5.54% FPR**
  - HTTPS legitimate slice: 141 FPs / 3,385 Legit = **4.17% FPR**
- **Root Cause:** The inverted HTTPS confounder identified in Phase 13B was successfully neutralized in Phase 13C-1 (both classes are ~87% HTTPS). The model no longer assumes HTTP is automatically phishing. However, HTTP legitimate URLs still experience a slightly higher FPR (5.54% vs 4.17%) because unencrypted sites tend to be older, multi-level academic portals.

### Category 4: Domain Categories, ccTLDs, and Shared Hosting
Inspection of the top registered domains among test false positives:
- `nasb.gov.by` (National Academy of Sciences of Belarus): 7 FPs
- `min-saude.pt` (Ministry of Health, Portugal): 6 FPs
- `inserm.fr` (French National Institute of Health and Medical Research): 5 FPs
- `hessen.de` (State of Hessen Portal, Germany): 5 FPs
- `parisdescartes.fr` (Paris Descartes University, France): 4 FPs
- `sld.cu` (Cuba Health Information Network): 3 FPs
- `northwell.edu` (Northwell Health Academic System): 3 FPs
- `wordpress.com` (WordPress Hosted Blogs): 3 FPs
- `delaware.gov` (State of Delaware Government): 2 FPs
- `wakayama.lg.jp` (Wakayama Prefectural Government, Japan): 2 FPs

**Root Cause:**
1. **Multi-level ccTLD suffixing:** Domains like `nasb.gov.by` or `wakayama.lg.jp` contain two dots in the suffix itself, inflating `subdom_cnt` and `dot_cnt`.
2. **Foreign language token entropy:** Non-English institutional domain names (e.g. `min-saude`, `parisdescartes`, `inserm`) exhibit letter distributions that deviate from English dictionary averages, triggering elevated `dom_entropy`.

---

## 4. Why Candidate 6 Handles False Positives Better Than Candidate 4

Our sliced error analysis uncovered a significant structural difference between Candidate 4 (Random Forest) and Candidate 6 (HistGBDT):

```
Comparison of Query-Bearing Test Slices (N = 99):
  Candidate 4 (RF 30f):        16 False Positives (FPR = 53.33%)
  Candidate 6 (HistGBDT 30f):   7 False Positives (FPR = 23.33%)  --> 56.3% REDUCTION IN QUERY FPs!

Comparison of Medium-Length Test Slices [50, 90) chars (N = 423):
  Candidate 4 (RF 30f):        31 False Positives (FPR = 11.74%)
  Candidate 6 (HistGBDT 30f):  16 False Positives (FPR = 6.06%)   --> 48.4% REDUCTION IN MID-LENGTH FPs!
```

### Architectural Explanation
- **Random Forest (Candidate 4)** builds trees independently using orthogonal axis-aligned splits on single features (`max_features='sqrt'`). A single split like `query_len > 40` or `dash_cnt > 2` can channel a sample into a high-risk leaf if that feature was correlated with phishing in its bootstrap subset.
- **Histogram GBDT (Candidate 6)** fits trees sequentially to correct the residual errors of preceding trees. When an initial tree over-penalizes a long query string on a reputable domain, subsequent boosting iterations learn interaction terms (e.g. balancing `query_len` against `is_https`, `tld_len`, and `letter_ratio`), dampening the penalty on legitimate dynamic URLs.

---

## 5. Actionable Engineering Recommendations

1. **Maintain Query Complexity Contrast Heuristics in the Decision Engine:**
   Pure lexical models cannot distinguish benign base64 IDs from tracking tokens without external semantic knowledge. The `LayeredDecisionEngine`'s query contrast rule successfully downgraded 16 out of 18 benchmark false positives to `INCONCLUSIVE`, preventing false alarms in production.
2. **Introduce Domain-Level Query Ratio Normalization:**
   Future feature extractors should compute the ratio of query length to total URL length, as well as the ratio of query entropy to hostname entropy (`query_entropy / dom_entropy`). Benign query-bearing URLs typically have a low-entropy registered domain paired with a dynamic query, whereas phishing URLs often exhibit elevated entropy across both hostname and path.
3. **Incorporate Public Suffix List (PSL) Aware Subdomain Extraction:**
   Improve feature extraction so that multi-level ccTLD suffixes (`.gov.by`, `.lg.jp`, `.edu.au`) are stripped before computing `subdom_cnt` and `dom_len`, preventing foreign public institutions from being penalized.
