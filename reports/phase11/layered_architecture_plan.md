# Layered Phishing Detection Architecture Plan: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Status:** Experimental Design & Validated Prototype  
**Scope:** Architecture Specification for Multi-Tiered Defense (ML + Heuristics + Threat Intelligence)  
**Target:** PhishGuardAI Defense-in-Depth Upgrade  

---

## 1. Executive Summary & Problem Context

PhishGuardAI previously relied on a single 22-feature lexical Random Forest classifier to classify URLs. The Phase 11 and Phase C investigations revealed two fundamental systemic failure modes inherent to any standalone lexical model:

1. **High False-Positive Rate on Complex Legitimate URLs (84.62% on realistic benchmark):**
   - The production training corpus ([`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)) suffers from severe sampling bias: **97.89% of legitimate URLs have zero query parameters and shallow paths**.
   - Conversely, 82.32% of URLs in the dataset with $\ge 2$ query parameters were phishing.
   - Consequently, the model learned to treat complex query parameters, digits, and high Shannon entropy as direct indicators of phishing, classifying a standard YouTube video lecture URL (`https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4`) as **94.00% phishing**.

2. **False Negatives on Clean-Path Phishing Attacks:**
   - Real-world phishing kits deployed on short paths or clean domains (e.g. `netflix-billing-alert.com/login`, `login-account-update.xyz/verify`, and direct IP hosts `192.241.220.14/login.php`) scored between **12% and 23% phishing probability** in the production model, evading detection because they lacked lexical complexity.

### Core Security Principle:
> [!CAUTION]
> **No single evidence source can make an authoritative determination:**
> - **A low ML score is NOT proof that a URL is legitimate.** Evasive or newly crafted phishing attacks routinely mimic clean lexical profiles.
> - **A missing threat-intelligence match is NOT proof that a URL is legitimate.** Threat feeds suffer from ingestion latency; newly launched zero-day campaigns take hours or days to be indexed.
> - **Popular domains must NEVER be hardcoded as safe.** Attackers routinely abuse legitimate hosting platforms (e.g., `firebaseapp.com`, `pages.dev`, `weebly.com`, Google Forms) and compromise trusted enterprise domains.

To resolve these vulnerabilities without corrupting production assets or hardcoding domains, this document specifies a **Layered Phishing Detection Architecture**.

---

## 2. Phase 1 — Machine Learning Audit & Baseline Verification Synthesis

### 2.1 Dataset Bias and Feature Parity Verification
- **Training Parity:** The production training script ([`src/train.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/train.py)) and inference script ([`src/predict.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/predict.py)) were verified to use identical 22-feature mathematical formulations via [`src/features.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/features.py).
- **Leakage Elimination:** Legacy 80/20 random splits leaked 2,120 registered domains between train and test. In Phase C2, a leakage-free dataset was constructed using `StratifiedGroupKFold` grouped strictly by registered domain (`dom`), guaranteeing **strictly zero domain overlap and zero near-duplicate overlap**.
- **Experimental Models Preserved Separately:** All experimental models are isolated in [`models/experiments/phase_c/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/experiments/phase_c/):
  - `rf_augmented_22f.joblib` (Model 1: 22 features, augmented data).
  - `rf_experimental_30f.joblib` (Model 2: 30 features, regularized).
  - `rf_calibrated_30f.joblib` (Model 3: 30 features, Platt calibrated).

### 2.2 Domain-Held-Out Evaluation Results ($N=22,871$)

| Metric | Production RF (22f, Baseline) | Model 1: Augmented (22f) | Model 2: Experimental (30f) | Model 3: Calibrated (30f) |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 99.03% | 96.96% | 97.77% | 97.87% |
| **Precision** | 94.81% | 87.90% | 88.82% | 92.28% |
| **Phishing Recall** | 98.55% | 91.10% | 96.40% | 92.76% |
| **F1-Score** | 96.65% | 89.47% | 92.45% | 92.52% |
| **False Positive Rate (FPR)** | 0.89% | 2.07% | 2.01% | 1.28% |
| **False Negative Rate (FNR)** | 1.45% | 8.90% | 3.60% | 7.24% |
| **ROC-AUC** | 0.9985 | 0.9885 | 0.9945 | 0.9942 |
| **Realistic Benchmark FPR ($N=41$)** | **84.62%** | **57.69%** | **80.77%** | **69.23%** |
| **Realistic Benchmark Phishing Recall**| 73.33% | **100.00%** | **100.00%** | 93.33% |
| **Target YouTube URL Probability** | **94.00%** | **57.00%** | **78.72%** | **84.66%** |

### 2.3 Synthesis of ML Limitations
Even after augmenting the training data with curated complex URLs and adding component-isolated features (domain vs query entropy), the YouTube lecture URL still produced a 57.00% - 84.66% phishing probability. This occurs because decision trees cannot distinguish between a high-entropy query token (video ID or catalog offset) and a tracking token when the training set has an 82% base rate of query parameters belonging to phishing URLs. 

**Conclusion:** Pure ML cannot solve this problem in isolation. A multi-layered architecture is strictly required.

---

## 3. Phase 2 — Threat Intelligence Subsystem Design

External threat feeds provide verified empirical ground truth on active phishing and malware campaigns, offsetting the blind spots of lexical ML models.

### 3.1 Threat Feed Specifications

| Specification | PhishTank (Cisco / OpenDNS) | URLhaus (abuse.ch) |
| :--- | :--- | :--- |
| **Official API Endpoint** | `https://checkurl.phishtank.com/checkurl/` | `https://urlhaus-api.abuse.ch/v1/url/` |
| **HTTP Method** | `POST` | `POST` |
| **Authentication** | Optional `app_key` via `PHISHTANK_API_KEY` | Optional `Auth-Key` via `URLHAUS_API_KEY` |
| **Payload Structure** | Form data: `url=<target>&format=json&app_key=<key>` | Form data: `url=<target>` |
| **Rate Limit Policy** | ~1 req / 5s unauth; higher with developer key | ~1 req / 1s unauth; higher with key |
| **Rate Limit Status Code** | HTTP 429 or HTTP 503 | HTTP 429 |
| **Supported Categories** | Phishing, credential harvesting, fraudulent portals | Malware downloads, exploit delivery, botnet C2 |
| **Latency Profile** | Variable (250ms – 3500ms); prone to timeouts | Low to moderate (150ms – 1200ms) |

### 3.2 Resilience & Graceful Degradation Architecture

Implemented in [`src/threat_intelligence/`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/):
- **Base Abstractions ([`base.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/base.py)):** Defines `ThreatStatus` (`MATCHED`, `NO_MATCH`, `TIMEOUT`, `UNAVAILABLE`, `RATE_LIMITED`, `INVALID_INPUT`, `ERROR`) and `ThreatCategory`.
- **PhishTank Provider ([`phishtank.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/phishtank.py)):** Encapsulates request timeouts (default 3.0s), User-Agent attribution, rate-limit isolation, and JSON validation.
- **URLhaus Provider ([`urlhaus.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/urlhaus.py)):** Encapsulates status code checks, malware tag mapping, and timeout isolation.
- **Multi-Provider Manager ([`manager.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/threat_intelligence/manager.py)):** Queries enabled feeds, aggregates results, and logs degraded providers.

### 3.3 Strict Operational Rules:
1. **Never Interpret Missing or Degraded Feeds as Clean:** If PhishTank times out or URLhaus is rate-limited, the system records `ThreatStatus.TIMEOUT` or `RATE_LIMITED`. It explicitly notes that **a missing result is not proof of safety**.
2. **Zero Credentials in Source Control:** API keys are dynamically loaded from `PHISHTANK_API_KEY` and `URLHAUS_API_KEY` environment variables.
3. **Safe Offline Testing:** All automated tests use mocked HTTP responses (`unittest.mock`), ensuring that **no malicious URLs are ever requested or downloaded during testing**.

---

## 4. Phase 3 — Layered Decision Engine Design

The Decision Engine ([`src/decision_engine/engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py)) synthesizes evidence across four distinct tiers.

### 4.1 Architecture Diagram

```mermaid
flowchart TD
    A[Target URL Input] --> B[URL Structural Analysis]
    A --> C[Threat Intelligence Feeds: PhishTank & URLhaus]
    A --> D[Machine Learning Model Inference]
    
    C -->|Verified Match Found| E[TIER 1: Threat Intel Override\nVerdict: PHISHING | Risk: CRITICAL]
    
    C -->|No Match or Degraded| F{TIER 2: Severe Structural Checks}
    B --> F
    
    F -->|Direct IP + Auth Path| G[TIER 2 Override\nVerdict: PHISHING | Risk: HIGH]
    F -->|Clean Structure| H{TIER 3: Machine Learning & Entropy Contrast}
    
    D --> H
    B -->|Entropy Contrast Data| H
    
    H -->|P >= 0.75 AND High Entropy Contrast| I[Verdict: INCONCLUSIVE | Risk: MEDIUM\nWarning: Query string underrepresented in training]
    H -->|P >= 0.75 AND Consistent Structural Anomaly| J[Verdict: PHISHING | Risk: HIGH]
    H -->|0.35 <= P < 0.75| K[Verdict: SUSPICIOUS or INCONCLUSIVE | Risk: MEDIUM]
    H -->|P < 0.35| L[Verdict: LEGITIMATE | Risk: LOW\nWarning: Low score is NOT proof of safety]
    
    E --> M[Consolidated Structured DecisionResult JSON]
    G --> M
    I --> M
    J --> M
    K --> M
    L --> M
```

### 4.2 Tiered Evaluation Details

#### Tier 1: Threat Intelligence (Ground Truth Override)
- **Condition:** Any verified provider returns `is_threat=True` and `status=MATCHED`.
- **Verdict:** `PHISHING`
- **Risk Level:** `CRITICAL`
- **Rationale:** External blocklists represent human or sandbox-verified malicious activity. They override any low score produced by a statistical model.

#### Tier 2: Structural Deterministic Indicators
- **Condition:** Hostname is a direct IP address (`is_ip=1`) and path contains authentication keywords (`/login`, `/signin`, `/verify`, `/account`).
- **Verdict:** `PHISHING`
- **Risk Level:** `HIGH`
- **Rationale:** Legitimate commercial and educational institutions do not serve production login interfaces over raw public IP addresses. This catches clean-path phishing that bypasses lexical entropy filters.

#### Tier 3: Statistical Machine Learning with Entropy Contrast & Confidence Zoning
- **High Risk ($P \ge 0.75$):**
  - **Query-Domain Entropy Contrast Check:** If the registered domain is low-entropy (`dom_entropy < 3.5`), but the query string is high-entropy (`query_entropy > 4.5`) with multiple parameters:
    - **Verdict:** `INCONCLUSIVE`
    - **Risk Level:** `MEDIUM`
    - **Evidence:** Explicitly explains that the elevated ML score is driven by query parameters, which are underrepresented in the training data.
  - **Otherwise:** `Verdict: PHISHING`, `Risk Level: HIGH`.
- **Ambiguous Confidence Zone ($0.35 \le P < 0.75$):**
  - **Verdict:** `SUSPICIOUS` (if deep subdomains or suspicious TLDs exist) or `INCONCLUSIVE`.
  - **Risk Level:** `MEDIUM`
  - **Evidence:** Explains that lexical URL features are inconclusive; live page inspection or domain age verification is required.
- **Low Risk ($P < 0.35$):**
  - **Verdict:** `LEGITIMATE`
  - **Risk Level:** `LOW`
  - **Mandatory Warning:** *"CRITICAL DISCLAIMER: A low machine learning score is NOT proof that a URL is legitimate. Zero-day phishing attacks, novel evasion kits, and clean-path impersonations frequently evade lexical scoring."*

#### Tier 4: Availability & Degradation Warnings
- Propagates explicit warnings whenever threat feeds time out, encounter HTTP 429/503, or when network connectivity is degraded.

### 4.3 Structured Output Contract (`DecisionResult`)

```json
{
  "url": "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4",
  "verdict": "inconclusive",
  "risk_level": "medium",
  "model_score": 0.94,
  "model_name": "RandomForest",
  "matched_threat_intel_sources": [],
  "evidence_based_explanation": [
    "Statistical ML model (RandomForest) estimated a phishing probability of 94.00%.",
    "Elevated ML score detected, but high lexical entropy is isolated strictly inside the query string while the registered domain displays normal, balanced character distribution. Because complex query strings are underrepresented in the ML training corpus, the model is likely over-penalizing legitimate dynamic parameter structures."
  ],
  "uncertainty_or_warnings": [
    "No threat intelligence matches found. Note: Zero-day phishing campaigns and newly registered domains frequently evade active blocklist feeds during early attack hours.",
    "Query-domain entropy contrast indicates potential lexical false-positive risk. Further external validation (e.g. domain age or content inspection) is advised."
  ],
  "structural_indicators": {
    "is_ip": false,
    "has_auth_path": false,
    "has_deep_subdomains": false,
    "has_suspicious_tld": false,
    "has_entropy_contrast": true,
    "dom_entropy": 3.096,
    "query_entropy": 5.258,
    "query_param_cnt": 3,
    "path_depth": 1
  },
  "threat_intel_summary": {
    "checked_providers": ["PhishTank", "URLhaus"],
    "matched": false
  },
  "timestamp": "2026-10-28T10:18:24Z"
}
```

---

## 5. Phase 4 — Testing & Empirical Validation

Two new dedicated test suites were implemented and verified with zero network access:

### 5.1 Test Suite 1: Threat Intelligence ([`tests/test_threat_intelligence.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_threat_intelligence.py))
- `test_phishtank_verified_phishing_match`: Verified parsing of active PhishTank phishing detections.
- `test_phishtank_no_match`: Verified clean handling when URL is not indexed.
- `test_phishtank_timeout`: Verified timeout exception caught; returns `ThreatStatus.TIMEOUT`.
- `test_phishtank_rate_limited`: Verified HTTP 429 returns `ThreatStatus.RATE_LIMITED`.
- `test_phishtank_service_unavailable`: Verified HTTP 503 returns `ThreatStatus.UNAVAILABLE`.
- `test_phishtank_malformed_json`: Verified handling of corrupted JSON response payloads.
- `test_urlhaus_verified_malware_match`: Verified parsing of URLhaus active malware threats.
- `test_urlhaus_no_results`: Verified `no_results` maps to `ThreatStatus.NO_MATCH`.
- `test_urlhaus_invalid_url`: Verified malformed target URLs map to `ThreatStatus.INVALID_INPUT`.
- `test_urlhaus_timeout`: Verified timeout exception caught cleanly.
- `test_manager_positive_threat_aggregation`: Verified multi-provider threat aggregation and metadata tracking.
- `test_manager_timeout_never_interpreted_as_clean`: Verified that feed failures emit explicit warnings and never produce a false "clean" verdict.

### 5.2 Test Suite 2: Decision Engine ([`tests/test_decision_engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine.py))
- `test_threat_intel_match_overrides_low_ml_score`: Verified that a confirmed threat match forces `verdict=PHISHING` and `risk=CRITICAL` even when ML model predicts 0.05.
- `test_direct_ip_hostname_with_login_path`: Verified direct IP with `/login.php` triggers `PHISHING` at `RiskLevel.HIGH`.
- `test_youtube_video_url_entropy_contrast_prevents_false_positive`: **Verified that the target YouTube video lecture URL is NOT classified as PHISHING; entropy contrast places it in INCONCLUSIVE with training underrepresentation warnings.**
- `test_suspicious_ambiguous_url`: Verified that moderate ML scores with suspicious subdomains return `SUSPICIOUS`.
- `test_low_ml_score_contains_mandatory_safety_disclaimer`: Verified that low ML score URLs include the mandatory disclaimer that ML is not proof of safety.
- `test_provider_timeout_attached_as_uncertainty_warning`: Verified that feed degradations are surfaced in output warnings.
- `test_invalid_and_empty_input`: Verified input validation on empty strings.

### 5.3 Test Suite Execution Summary
- **New Unit Tests:** 19 of 19 passed in 0.133s.
- **Full Project Regression Test Suite:** 57 of 57 passed in 30.686s.
- **Failures:** 0. **Errors:** 0.

---

## 6. Outstanding Risks & Security Realities

1. **Threat Intelligence Feed Latency:**
   - Active phishing attacks have an average lifespan of under 24 hours. The time between a campaign launch and its appearance on PhishTank or URLhaus can range from 1 to 12 hours. During this zero-day window, threat feeds will return `NO_MATCH`. The engine addresses this by issuing an explicit warning on all unlisted URLs.
2. **Public Hosting & Cloud Platform Abuse:**
   - Attackers frequently host phishing forms on legitimate infrastructure (`weebly.com`, `pages.dev`, `firebaseapp.com`, `google.com/forms`). Hardcoding these domains as safe would create an immediate critical vulnerability. The decision engine intentionally evaluates path, subdomain, and query features on these domains without whitelisting.
3. **Training Data Imbalance in ML Subsystem:**
   - Until tens of thousands of modern dynamic legitimate URLs with complex parameters are crawled and added to the training set, lexical models will remain biased against long query strings. The decision engine mitigates this via entropy contrast abstention.
4. **Third-Party API Outages & Rate Limits:**
   - Public threat intelligence APIs may be throttled or experience downtime. The decision engine degrades gracefully by falling back to structural heuristics and ML, while explicitly flagging the degraded state to the analyst.

---

## 7. Implementation Roadmap & Production Gate

| Step | Scope | Pre-requisites | Status |
| :---: | :--- | :--- | :---: |
| **1** | Machine Learning Audit & Leakage Elimination | Phase C dataset partitioning | **Complete** |
| **2** | Threat Intelligence Module Architecture | PhishTank & URLhaus API integration | **Complete (Tested)** |
| **3** | Multi-Tiered Decision Engine Prototype | Structural heuristics & abstention logic | **Complete (Tested)** |
| **4** | Comprehensive Mocked Unit Testing | Zero live network requests | **Complete (57/57 Passed)** |
| **5** | **User Explicit Authorization Gate** | Review of architectural plan | **Awaiting Approval** |
| **6** | Production Model Retraining | Ingestion of 25k+ legitimate dynamic crawl URLs | Pending Approval |
| **7** | Production Backend Integration | Wire `src/decision_engine` into `app.py` `/api/scan` | Pending Approval |
| **8** | Dashboard UI Layered Card Display | Render verdict, risk level, warnings, and feeds | Pending Approval |

> [!IMPORTANT]
> **Production Status:** The production application ([`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py)) and production model ([`models/phishing_model.joblib`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib)) remain strictly untouched. No unvalidated models or experimental endpoints have been integrated into live production.
