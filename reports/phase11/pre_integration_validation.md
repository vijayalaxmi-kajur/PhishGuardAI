# Pre-Integration Validation Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Status:** Pre-Integration Audit & Hardening Complete  
**Scope:** Verification of `LayeredDecisionEngine`, Threat Intelligence Subsystem, Evaluation Integrity, and Verdict Semantics  
**Deliverable:** Pre-Integration Decision Gate Report for PhishGuardAI  

---

## 1. Executive Summary

This report establishes the verified pre-integration validation findings for the **Layered Phishing Detection Architecture** before any modifications are introduced into the live production Flask application ([`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py)) or production model ([`models/phishing_model.joblib`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib)).

### Summary of Key Audit Results:
1. **Implementation Verification:**
   - The threat intelligence subsystem ([`src/threat_intelligence/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/)) and decision engine ([`src/decision_engine/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/)) were inspected and verified against the claims in [`reports/phase11/layered_architecture_plan.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/layered_architecture_plan.md).
   - Identified and corrected two unsafe assumptions: (a) boolean coercion of string values (`"n"`) in PhishTank responses, and (b) missing heuristic checks for shared-hosting platforms and misleading brand subdomains.
2. **Comprehensive Test Execution:**
   - **26 dedicated unit tests** across [`tests/test_threat_intelligence.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_threat_intelligence.py) (12 tests) and [`tests/test_decision_engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine.py) (14 tests) were executed with strictly mocked HTTP sessions. **100% passed (26/26)**.
   - The full project regression suite (**82 tests across 7 test modules**) passed in 26.31s with zero failures.
3. **Verdict Semantics Hardening:**
   - Audited the hazard of using `"LEGITIMATE"` as an output verdict. Calling a URL "legitimate" creates an unacceptable false sense of security.
   - Standardized a 5-tier security hierarchy: `CONFIRMED MALICIOUS`, `HIGH RISK`, `SUSPICIOUS`, `INCONCLUSIVE`, and `NO KNOWN THREAT DETECTED`.
4. **Experimental Benchmark Integrity Audit:**
   - Verified that `data/realistic_evaluation_set.csv` contains exactly **41 examples** (26 legitimate, 15 phishing).
   - Identified that drawing macro-level release conclusions from this small benchmark risks overinterpretation; 11 URLs from this benchmark were present in the Phase C training expansion set, creating in-sample evaluation contamination. True out-of-distribution evaluation must rely on the domain-held-out partition ([`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv), $N=22,871$, zero domain overlap).
5. **Strict Production Containment:**
   - All production files continue to match their baseline SHA-256 hashes recorded in [`data/experiments/pre_phase_c_baseline_hashes.json`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/pre_phase_c_baseline_hashes.json). No production code or model was overwritten.

---

## 2. Task 1 — Implementation Inspection & Gap Analysis

### 2.1 Files Actually Inspected
The following files were inspected directly on the filesystem:
- [`src/threat_intelligence/base.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/base.py): Core data models (`ThreatLookupResult`, `MultiProviderLookupResult`, `ThreatStatus`, `ThreatCategory`) and abstract provider interface.
- [`src/threat_intelligence/phishtank.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/phishtank.py): Cisco/OpenDNS PhishTank API provider.
- [`src/threat_intelligence/urlhaus.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/urlhaus.py): abuse.ch URLhaus API provider.
- [`src/threat_intelligence/manager.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/manager.py): Aggregator coordinating multi-provider lookups and logging degraded providers.
- [`src/decision_engine/engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py): Multi-tier synthesis engine.
- [`src/feature_extraction.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/feature_extraction.py): Production 22-feature lexical extractor.
- [`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py): Live production Flask backend application.
- [`tests/test_threat_intelligence.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_threat_intelligence.py): Provider unit tests.
- [`tests/test_decision_engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine.py): Decision engine unit tests.
- [`reports/phase11/layered_architecture_plan.md`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase11/layered_architecture_plan.md): Initial architectural specification report.

### 2.2 Discrepancies and Missing Files Discovered
1. **Absence of `src/features.py` and `src/predict.py`:**
   - Both the user prompt and prior architectural documentation referenced `src/features.py` and `src/predict.py`.
   - **Factual Reality:** Neither file exists in the active project.
     * The production feature extraction module is named [`src/feature_extraction.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/feature_extraction.py).
     * Prediction logic in production is embedded directly in [`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py) (`load_model_artifact()` and `/api/scan`). No decoupled `src/predict.py` service currently exists.
2. **PhishTank Boolean Parsing Hazard:**
   - In [`src/threat_intelligence/phishtank.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/phishtank.py), response values were parsed with `bool(results.get("verified", False))`.
   - In some PhishTank API versions, `verified` is returned as string `"y"` or `"n"`. In Python, `bool("n")` evaluates to `True`, which would incorrectly treat unverified entries as confirmed phishing.
   - **Resolution:** Replaced with a strict truthy parser: `val.strip().lower() in {"true", "1", "y", "yes"}`.
3. **Missing Shared-Hosting & Subdomain Spoofing Heuristics:**
   - The architectural plan discussed attacker abuse of cloud hosting (`firebaseapp.com`, `pages.dev`, `weebly.com`), but `_analyze_structure()` in `engine.py` lacked explicit rules detecting brand impersonation in subdomains or hosting abuse.
   - **Resolution:** Implemented `has_misleading_subdomain` (detecting targeted brand tokens like `paypal`, `apple`, `office365`, `dhl` in subdomains of unrelated registered domains) and `has_hosting_abuse` (detecting credential forms on public shared hosting).

---

## 3. Task 2 — Decision Engine Testing Matrix

All tests were executed with zero external network connectivity using Python's `unittest.mock`. The test matrix specifically validated the following required scenarios:

| Test Scenario | Module & Test Method | Input Archetype | Expected Result | Actual Result |
| :--- | :--- | :--- | :--- | :---: |
| **Confirmed Threat Intel Match** | `TestDecisionEngine.test_confirmed_threat_intel_match_overrides_low_ml_score` | `http://evasive-phish-kit.com/secure` (ML score = 0.05) | Overrides ML score $\rightarrow$ `CONFIRMED MALICIOUS`, `RiskLevel.CRITICAL` | **Passed** |
| **No Threat Intel Match** | `TestDecisionEngine.test_no_threat_intel_match_does_not_guarantee_safety` | `https://newly-registered-phish-portal.site/login` | Appends explicit warning that unlisted URLs may be zero-day phishing | **Passed** |
| **Provider Timeout** | `TestDecisionEngine.test_threat_intel_provider_timeout_and_outage_handling` | `https://example.com/check` (PhishTank timeout after 3s) | Records degraded provider, emits uncertainty warning, does not assume clean | **Passed** |
| **Provider Outage & Rate Limiting** | `TestDecisionEngine.test_threat_intel_rate_limiting_propagation` | `https://example.com/test-rate-limit` (HTTP 429) | Degraded status captured, rate-limit details attached | **Passed** |
| **Complex Legitimate Query URLs** | `TestDecisionEngine.test_youtube_video_url_entropy_contrast_prevents_false_positive` | YouTube lecture URL with playlist/index parameters (ML score = 0.94) | Entropy contrast prevents false-positive blocking $\rightarrow$ `INCONCLUSIVE` (Medium Risk) | **Passed** |
| **Multi-Parameter Dynamic Sites** | `TestDecisionEngine.test_multi_parameter_legitimate_urls` | Google Scholar and Amazon product URLs (ML score = 0.80) | Query complexity contrast prevents `CONFIRMED MALICIOUS` verdict | **Passed** |
| **Direct IP with Authentication** | `TestDecisionEngine.test_direct_ip_hostname_with_login_path` | `http://192.241.220.14/portal/admin/login.php` (ML score = 0.40) | Flagged as `HIGH RISK` due to direct IP hosting login portal | **Passed** |
| **Misleading Subdomains** | `TestDecisionEngine.test_misleading_subdomains_brand_spoofing` | `https://paypal.com.account-verification-notice.org/login` | Flagged as `HIGH RISK` due to brand spoofing in subdomain | **Passed** |
| **Shared Hosting Platform Abuse** | `TestDecisionEngine.test_suspicious_shared_hosting_abuse` | `dhl-package-tracking-alert.firebaseapp.com`, `office365-password-reset.pages.dev` | Flagged as `SUSPICIOUS` / `HIGH RISK` due to public hosting abuse | **Passed** |
| **High Model Score Spectrum** | `TestDecisionEngine.test_high_model_score_with_structural_red_flags` | `bank-security-verification-portal.xyz/login.php` ($P = 0.90$) | Flagged as `HIGH RISK` | **Passed** |
| **Ambiguous Model Score Spectrum**| `TestDecisionEngine.test_medium_model_score_ambiguous_zone` | Unfamiliar domain ($P = 0.55$) in $[0.35, 0.75]$ | Flagged as `INCONCLUSIVE` / `SUSPICIOUS` | **Passed** |
| **Low Model Score Spectrum** | `TestDecisionEngine.test_low_model_score_contains_mandatory_safety_disclaimer` | `https://www.rmit.edu.au/about` ($P = 0.05$) | `NO KNOWN THREAT DETECTED` + mandatory zero-day safety disclaimer | **Passed** |
| **Invalid Input Validation** | `TestDecisionEngine.test_invalid_and_empty_input` | Empty or whitespace-only URL strings | `INCONCLUSIVE`, `RiskLevel.UNKNOWN`, input validation warning | **Passed** |

---

## 4. Task 3 — Review of Verdict Semantics

### 4.1 The Security Hazard of "LEGITIMATE"
In automated cybersecurity tooling, labelling an unclassified URL as `"LEGITIMATE"` is a critical vulnerability:
- A user or security operations analyst seeing `Verdict: Legitimate` interprets it as an affirmative security guarantee that the website is safe to enter credentials.
- Lexical ML models only evaluate surface string properties. A newly registered domain, a compromised WordPress site, or an evasive phishing kit can easily present low lexical anomaly scores ($P < 0.35$).
- Threat intelligence feeds have ingestion latency; zero-day phishing attacks routinely operate for hours before being added to PhishTank or URLhaus.

### 4.2 Standardized 5-Tier Semantic Framework

To eliminate this ambiguity, [`src/decision_engine/engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py) has been standardized around five explicit tiers:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        PHISHGUARDAI VERDICT HIERARCHY                  │
├──────────────────────────┬──────────────┬──────────────────────────────┤
│ Standardized Verdict     │ Risk Level   │ Operational Meaning          │
├──────────────────────────┼──────────────┼──────────────────────────────┤
│ CONFIRMED MALICIOUS      │ CRITICAL     │ Active threat confirmed by   │
│                          │              │ verified threat feed.        │
├──────────────────────────┼──────────────┼──────────────────────────────┤
│ HIGH RISK                │ HIGH         │ Severe structural anomalies  │
│                          │              │ (IP login, brand spoofing).  │
├──────────────────────────┼──────────────┼──────────────────────────────┤
│ SUSPICIOUS               │ MEDIUM       │ Cloud hosting abuse, deep    │
│                          │              │ subdomains, ambiguous ML.    │
├──────────────────────────┼──────────────┼──────────────────────────────┤
│ INCONCLUSIVE             │ MEDIUM / UNK │ Query complexity contrast,   │
│                          │              │ provider outage, or conflict.│
├──────────────────────────┼──────────────┼──────────────────────────────┤
│ NO KNOWN THREAT DETECTED │ LOW          │ Clean structure & low score. │
│                          │              │ Mandatory zero-day caveat.   │
└──────────────────────────┴──────────────┴──────────────────────────────┘
```

> [!IMPORTANT]
> **Safety Rule:** Every `NO KNOWN THREAT DETECTED` verdict programmatically appends the mandatory disclaimer:  
> *"CRITICAL DISCLAIMER: A verdict of 'no known threat detected' is NOT proof that a URL is legitimate or safe. Zero-day phishing attacks, novel evasion kits, and clean-path impersonations frequently evade lexical scoring and may not yet be indexed in blocklists."*

---

## 5. Task 4 — Review of Experimental Evaluation & Artifact Integrity

### 5.1 Realistic Evaluation Dataset Audit ([`data/realistic_evaluation_set.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/realistic_evaluation_set.csv))
- **Total Rows:** Exactly **41 samples**.
  - **Class 0 (Legitimate):** 26 samples (63.4%).
  - **Class 1 (Phishing):** 15 samples (36.6%).
- **Label Provenance:**
  - Phishing URLs were established from verified public archives: PhishTank Threat IDs (`#829104`, `#774910`, `#812903`, `#799481`, `#830192`, `#804192`), OpenPhish threat feed captures, and Mendeley URL-Phish Class 1 entries.
  - Legitimate URLs were established from canonical production sites across streaming, search, e-commerce, developer docs, and academic portals.

### 5.2 Leakage & Overlap Audit
An automated cross-reference script ([`scratch/audit_realistic_eval.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/scratch/audit_realistic_eval.py)) was executed against the baseline and experimental datasets:
- **Overlap with original [`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv):**
  - **URL Overlap:** **0 URLs** (Zero exact duplicates).
  - **Domain Overlap:** **20 domains out of 37 overlapped** (e.g. `latrobe.edu.au`, `mit.edu`, `nih.gov`, `cdc.gov`, `firebaseapp.com`, `pages.dev`).
- **Overlap with experimental [`data/experiments/phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv):**
  - **URL Overlap:** **11 URLs overlapped** because the curated expansion set was included in Phase C training data creation.
  - **Domain Overlap:** **27 domains overlapped**.

### 5.3 Assessment of Benchmark Overinterpretation
> [!WARNING]
> **The 41-sample realistic benchmark must NOT be overinterpreted:**
> 1. In a dataset of $N=41$ (26 legitimate, 15 phishing), a single misclassification causes a **3.85% swing in FPR** and a **6.67% swing in Phishing Recall**.
> 2. Because 11 URLs from the realistic evaluation set were included in `phase_c_training.csv`, Model 1's performance on this set (recovering 100% phishing recall and reducing FPR to 57.69%) was partially influenced by **in-sample training exposure**.
> 3. True out-of-distribution evaluation must be judged on the **22,871-sample held-out partition** ([`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv)), which has **strictly zero domain overlap and zero URL overlap** with training data.

### 5.4 Reproducibility of Model Evaluation Findings
All reported model metrics are 100% reproducible from disk artifacts using [`scratch/inspect_realistic_preds.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/scratch/inspect_realistic_preds.py):
- **Production Model on Realistic Benchmark ($N=41$):**
  - Confusion Matrix: $\text{TN}=4, \text{FP}=22, \text{FN}=4, \text{TP}=11$
  - Accuracy: $36.59\%$, FPR: $84.62\%$, Phishing Recall: $73.33\%$.
- **Model 1 (RF Augmented 22f) on Realistic Benchmark ($N=41$):**
  - Confusion Matrix: $\text{TN}=11, \text{FP}=15, \text{FN}=0, \text{TP}=15$
  - Accuracy: $63.41\%$, FPR: $57.69\%$, Phishing Recall: $100.00\%$.
- **Target YouTube URL Probability Reproduction:**
  - Production Model: **94.00% phishing probability** (94 of 100 trees voted 1).
  - Model 1 (Augmented 22f): **57.00% phishing probability**.
  - Model 2 (Experimental 30f): **78.72% phishing probability**.
  - Model 3 (Calibrated 30f): **84.66% phishing probability**.

---

## 6. Remaining False-Positive and False-Negative Risks

1. **Zero-Day Phishing Threat Feed Latency:**
   - External feeds (PhishTank/URLhaus) have ingestion latency. A phishing campaign active for <6 hours will return `NO_MATCH`. If the URL also uses a clean lexical path (e.g. `chase-security-update.com/login`), the ML model might score it low.
   - *Mitigation:* The engine enforces that `NO_KNOWN_THREAT DETECTED` is not a guarantee and flags suspicious TLDs/keywords.
2. **Dynamic Legitimate URLs Outside Entropy Contrast Thresholds:**
   - If a legitimate URL has only 1 query parameter but that parameter has very high entropy (e.g., an encrypted session token), `has_entropy_contrast` may not trigger if it expects $\ge 2$ parameters.
   - *Mitigation:* Pre-integration threshold tuning has expanded `has_entropy_contrast` to trigger on `(query_param_cnt >= 2 or (query_entropy > 4.0 and query_len > 20))`.
3. **Lexical Training Data Imbalance (The 97.9% Problem):**
   - The underlying Random Forest model remains constrained by the 116,600-sample dataset's skew. Until 25,000+ legitimate URLs with query strings are ingested, the statistical prior odds of high entropy in queries will remain biased towards phishing.
   - *Mitigation:* The Layered Decision Engine overrides or abstains (`INCONCLUSIVE`) whenever query complexity is detected on a low-entropy domain.

---

## 7. Required Corrections Prioritized by Severity

| Priority | Issue / Risk | Severity | Correction Plan | Status |
| :---: | :--- | :---: | :--- | :---: |
| **P1** | Verdict semantic confusion (`LEGITIMATE` implying safety) | **HIGH** | Replace binary `LEGITIMATE` with `NO_KNOWN_THREAT_DETECTED` and attach mandatory caveats. | **Completed in `engine.py`** |
| **P1** | PhishTank boolean string parsing bug (`bool("n") == True`) | **HIGH** | Implement strict truthy helper `_to_bool()` validating explicit positive tokens. | **Completed in `phishtank.py`** |
| **P2** | Missing heuristics for shared hosting abuse & subdomain spoofing | **MEDIUM** | Implement `has_misleading_subdomain` and `has_hosting_abuse` structural checks. | **Completed in `engine.py`** |
| **P2** | In-sample benchmark contamination in `realistic_evaluation_set.csv` | **MEDIUM** | Re-evaluate experimental models strictly on `phase_c_evaluation.csv` ($N=22,871$) to prevent over-optimism. | **Documented in Report** |
| **P3** | Absence of decoupled `src/predict.py` service | **LOW** | Create a standalone `src/predict.py` before modifying `app.py` to keep Flask routes thin and testable. | **Pending Production Integration** |

---

## 8. Recommended Production Integration Plan

When authorized by user review, integration should proceed along the following staged path:

```
[Phase C Pre-Integration Audit] (COMPLETE - STOPPED HERE)
              │
              ▼ (Requires User Approval)
[Stage 1: Decouple Inference Engine]
   - Create src/predict.py encapsulating model loading and LayeredDecisionEngine.
   - Verify unit test isolation without touching app.py.
              │
              ▼
[Stage 2: Expand Training Data with Legitimate Query Crawl]
   - Ingest 25,000+ legitimate dynamic URLs (Common Crawl / Tranco deep links).
   - Retrain model to balance query parameter priors permanently.
              │
              ▼
[Stage 3: Backward-Compatible API Route Integration]
   - Update app.py /api/scan to invoke LayeredDecisionEngine.
   - Preserve legacy response fields (prediction, probability, status) while adding
     verdict, risk_level, matched_threat_intel_sources, and explanations.
              │
              ▼
[Stage 4: Frontend UI Enhancement]
   - Render multi-tier badge (CONFIRMED MALICIOUS, HIGH RISK, SUSPICIOUS, INCONCLUSIVE,
     NO KNOWN THREAT DETECTED).
   - Display evidence breakdown drawer and uncertainty disclaimers.
```

---

## 9. Strict Stop Confirmation

In accordance with user instructions:
- **`app.py` was NOT modified.**
- **The production model was NOT replaced.**
- **Production thresholds were NOT changed.**
- **Existing frontend files were NOT altered.**
- **The baseline dataset was NOT modified.**
- **The live application server continues running undisturbed.**

Execution is stopped awaiting your review of this report.
