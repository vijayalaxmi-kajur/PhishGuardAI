# Phase C Feature Engineering & Comparison Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Scope:** Phase C3 - Comparative Analysis of 22-Feature Baseline vs. 30-Feature Component-Isolated Pipeline  
**Project:** PhishGuardAI  

---

## 1. Feature Representation Dilemma

The production feature extractor ([`src/features.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/features.py)) calculates 22 features across the entire raw URL string. While this design is computationally lightweight, it suffers from a fatal architectural flaw: **global information pooling without structural component isolation**.

### The Flaw of Global Aggregation:
When a feature extractor computes metrics like `entropy`, `digit_cnt`, or `special_cnt` on the entire URL:
1. **DGA Detection vs. Video Identifiers:** High Shannon entropy in a registered domain (e.g., `x89qj2m-auth.top`) is a classic indicator of Domain Generation Algorithms (DGA) or phishing disposable hosting. However, high entropy in a query parameter (e.g., YouTube video ID `v=9l3IBjqJdFI` or Amazon ASIN `dp/B08N5WRWNW`) is standard behavior for content-addressable systems.
2. **Digit Conflation:** Digits in a domain name (`chase247-security.com`) frequently signal brand impersonation. Digits in a query string (`&index=4`, `&t=42s`) merely signify catalog offsets or playback timestamps.
3. **Delimiter Penalization:** Characters like `=`, `?`, and `&` are essential syntax for legitimate dynamic web applications.

---

## 2. Experimental Feature Pipeline Architecture

To evaluate whether structural component isolation resolves this problem, [`src/experiments/phase_c_features.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/experiments/phase_c_features.py) was developed with strict backward-compatible preservation of the 22 baseline features and 8 new component-isolated features.

### Schema Comparison Table

| Feature Name | Baseline (22f) | Experimental (30f) | Component Scope | Rationale & Security Semantic |
| :--- | :---: | :---: | :--- | :--- |
| `url_len` | Yes | Yes | Entire URL | Overall string length |
| `dom_len` | Yes | Yes | Registered Domain | Registered domain length |
| `is_ip` | Yes | Yes | Hostname | Binary indicator: IPv4/IPv6 direct address |
| `tld_len` | Yes | Yes | Public Suffix | Top-level domain length |
| `subdom_cnt` | Yes | Yes | Subdomain | Count of dot-separated subdomain labels |
| `letter_cnt` | Yes | Yes | Entire URL | Count of alphabetic characters |
| `digit_cnt` | Yes | Yes | Entire URL | Total digits across entire URL |
| `special_cnt` | Yes | Yes | Entire URL | Total non-alphanumeric characters |
| `eq_cnt` | Yes | Yes | Entire URL | Count of `=` characters |
| `qm_cnt` | Yes | Yes | Entire URL | Count of `?` characters |
| `amp_cnt` | Yes | Yes | Entire URL | Count of `&` characters |
| `dot_cnt` | Yes | Yes | Entire URL | Count of `.` characters |
| `dash_cnt` | Yes | Yes | Entire URL | Count of `-` characters |
| `under_cnt` | Yes | Yes | Entire URL | Count of `_` characters |
| `letter_ratio` | Yes | Yes | Entire URL | Alphabetic density |
| `digit_ratio` | Yes | Yes | Entire URL | Numeric density |
| `spec_ratio` | Yes | Yes | Entire URL | Special character density |
| `is_https` | Yes | Yes | Scheme | Binary indicator: HTTPS scheme presence |
| `slash_cnt` | Yes | Yes | Entire URL | Count of `/` characters |
| `entropy` | Yes | Yes | Entire URL | Global character Shannon entropy |
| `path_len` | Yes | Yes | Path | Total character length of path segment |
| `query_len` | Yes | Yes | Query | Total character length of query string |
| **`host_len`** | **No** | **Yes** | Hostname | Complete host length including subdomains |
| **`subdom_len`** | **No** | **Yes** | Subdomain | Character length of subdomain string |
| **`dom_entropy`** | **No** | **Yes** | Registered Domain | **Shannon entropy restricted to registered domain** |
| **`dom_digit_cnt`** | **No** | **Yes** | Registered Domain | **Digits present strictly in registered domain** |
| **`path_depth`** | **No** | **Yes** | Path | Count of directory hierarchical levels |
| **`query_param_cnt`**| **No** | **Yes** | Query | Count of structured key-value query parameters |
| **`query_entropy`** | **No** | **Yes** | Query | **Shannon entropy calculated across query string** |
| **`query_digit_cnt`**| **No** | **Yes** | Query | **Digits present strictly inside query parameters** |

---

## 3. Case Study: Feature Vectors of the Target YouTube URL

URL: `https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`

### Direct Value Comparison

```text
Global Features (Baseline 22f):
  entropy            : 5.4733  (Very high -> flagged by tree splits at > 4.618)
  digit_cnt          : 6       (Flagged by tree splits at > 5)
  eq_cnt             : 3       (Flagged by tree splits at > 1)
  amp_cnt            : 2       (Flagged by tree splits at > 0)
  url_len            : 91      (Flagged by tree splits at > 68)

Component-Isolated Features (Experimental 30f):
  dom_entropy        : 3.0958  (NORMAL / LOW: 'youtube.com' has balanced english entropy)
  dom_digit_cnt      : 0       (CLEAN: Zero digits in the domain)
  subdom_len         : 3       ('www')
  path_depth         : 1       ('/watch')
  query_param_cnt    : 3       (3 distinct keys: 'v', 'list', 'index')
  query_entropy      : 5.2583  (Confined strictly to parameters, where base64 IDs reside)
  query_digit_cnt    : 6       (Digits '3', '0', '2', '4', etc. live entirely in query)
```

---

## 4. Empirical Behavior & Unexpected Tree Dynamics

While component isolation successfully proved that `dom_entropy = 3.0958` and `dom_digit_cnt = 0` (proving the domain itself was completely benign), an unexpected machine learning dynamic emerged during tree fitting:

### The Query Feature Trap:
In the underlying training set ([`data/experiments/phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv)):
- Legitimate URLs with `query_param_cnt >= 2`: **350 samples** (0.45% of legitimate data).
- Phishing URLs with `query_param_cnt >= 2`: **1,630 samples** (12.55% of phishing data).
- Empirical class ratio when `query_param_cnt >= 2`: **82.32% Phishing**.

Because the training corpus retained an overwhelming base-rate imbalance in multi-parameter URLs, the Decision Trees in Model 2 immediately seized upon `query_param_cnt >= 2` as a high-information-gain split for Class 1!
- In **Model 1 (22f)**: P(phishing) on YouTube URL dropped from **94.00% to 57.00%** (a 37 percentage point drop).
- In **Model 2 (30f)**: Adding `query_param_cnt` gave the tree an explicit shortcut, pushing P(phishing) to **78.72%**.

### Conclusion:
Component-isolated features are theoretically sound and mathematically correct, but **feature engineering cannot overcome extreme dataset sampling bias**. If legitimate complex query URLs are virtually absent from the training corpus, the model will inevitably treat the isolated query features as indicators of attack.
