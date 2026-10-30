# PhishGuardAI — Phase 11 Phase B: Evidence-Based Improvement Plan & Recommendations

**Project Title:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Audit Phase:** Phase 11 — Lexical Machine Learning Improvement & False Positive Investigation  
**Sub-Phase:** Phase B — Recommendations: Evidence-Based Architectural Roadmap  
**Execution Date:** October 28, 2026  
**Auditor:** Senior Machine Learning Engineer & Cybersecurity Specialist  
**Status:** Strictly Architectural & Advisory (Zero Code Changes, Zero Retraining in Phase B)  

---

## 1. Executive Summary & Strategy Directives

Based on the empirical measurements conducted in Investigations 1 through 5, this report establishes a prioritized, evidence-based improvement plan to resolve the false-positive problem on complex legitimate URLs (such as YouTube playlist links) while maintaining robust phishing interception.

### Core Strategic Mandates:
1. **Strict Preservation of Production Artifacts:**
   * All recommendations must be evaluated in separate experimental branches (`models/experiments/`) without overwriting `models/phishing_model.joblib` or modifying `app.py`.
2. **Empirical Verification Required:**
   * No proposed feature or data addition shall be assumed to improve performance without rigorous metric comparison on domain-held-out benchmarks.
3. **No Implementation in Phase B:**
   * In compliance with project guidelines, **none of these recommendations are to be implemented during Phase B**. Execution is reserved for Phase C upon formal user approval.

---

## 2. Prioritized Recommendations Roadmap

```text
Priority Level          Recommendation Item                                  Primary Objective
-------------------------------------------------------------------------------------------------------------
Priority 1 (Highest)   Dataset Augmentation: Dynamic Benign URLs            Eliminate severe query-string sampling bias
Priority 2 (High)      Domain-Aware Evaluation Standard (SGKF)              Prevent over-optimistic evaluation leakage
Priority 3 (High)      Normalized URL Deduplication Pipeline                Eliminate 302 near-duplicate leakage pairs
Priority 4 (Medium)    Component-Isolated Feature Engineering               Decouple domain entropy from query parameters
Priority 5 (Medium)    Decision Tree Regularization & Tree Depth Pruning    Prevent brittle tree splits on HTTPS/Entropy
Priority 6 (Medium)    Post-Hoc Probability Calibration (Platt / Isotonic)   Pull borderline false positives below 0.50
Priority 7 (Lower)     Justified Lexical Feature Extensions                 Address clean-path evasion (FNR = 12.66%)
Priority 8 (Future)    Optional Threat-Intelligence / Reputation Check       Multi-layered defense for high-reputation domains
```

---

## 3. Detailed Evidence-Based Recommendations

### Recommendation 1: Dataset Augmentation with Complex Legitimate URLs (Highest Priority)
* **Empirical Justification:**
  * Investigation 2 proved that **97.99% of benign URLs have zero query string**, zero YouTube URLs exist in the dataset, and only 69 out of 98,641 benign URLs have `query_len >= 61`.
  * The model flags the YouTube lecture URL ($p = 0.94$) because it has never observed legitimate multi-parameter URLs with high Shannon entropy.
* **Proposed Action:**
  * Ingest a curated, verified partition of legitimate URLs from modern dynamic web services: video streaming platforms (`youtube.com`, `vimeo.com`), e-commerce catalogs (`amazon.com`, `ebay.com`), search engines (`google.com/search`, `bing.com`), academic portals with query parameters, and social platforms.
  * Ensure full provenance, cryptographic checksums, and strict verification to prevent label noise.
* **Advantages:**
  * Directly balances feature distributions in the continuous parameter space (`query_len`, `param_cnt`, `entropy`, `digit_ratio`).
  * Adjusts decision tree splitting thresholds naturally during training without ad-hoc rules.
* **Risks:**
  * Ingesting uncurated URLs risks introducing label noise (e.g., legitimate domains hosting compromised redirectors).
* **Expected Evaluation Criteria:**
  * Reduction of predicted phishing probability on the target YouTube URL from $0.94$ down to $< 0.15$.
  * False Positive Rate on domain-held-out test partition reduced from $1.64\%$ down to $< 0.80\%$.
  * Phishing recall must remain $\ge 87.0\%$ on novel domains.

---

### Recommendation 2: Domain-Aware Evaluation Standard (High Priority)
* **Empirical Justification:**
  * Investigation 5 proved that **2,120 domains (23.78% of test URLs)** overlap between train and test in the random split, masking a **5.85% drop in phishing recall** on novel domains.
* **Proposed Action:**
  * Adopt `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` grouped by registrable domain (`dom`) as the primary evaluation standard for all future candidate models.
* **Advantages:**
  * Guarantees zero domain overlap between training and testing.
  * Accurately reflects real-world defense against zero-day phishing campaigns on fresh domains.
* **Risks:**
  * Multi-tenant platforms (e.g., `weebly.com`) must be isolated carefully so that single-tenant domains are not distorted.
* **Expected Evaluation Criteria:**
  * Both in-distribution (random split) and out-of-distribution (domain split) metrics must be reported side-by-side.

---

### Recommendation 3: Normalized Preprocessing & Near-Duplicate Deduplication (High Priority)
* **Empirical Justification:**
  * Investigation 5 detected **302 near-duplicate URL pairs** shared between training and testing because deduplication relied on exact string equality.
* **Proposed Action:**
  * Enhance `DataPreprocessor.deduplicate()` to normalize URLs (lowercase, strip trailing slashes, strip protocol schemes, remove default ports) prior to splitting.
* **Advantages:**
  * Eliminates subtle train-test memorization leaks.
  * Guarantees strict cryptographic separation between splits.
* **Risks:**
  * Minimal risk; normalization preserves the underlying web destination.
* **Expected Evaluation Criteria:**
  * Near-duplicate overlap between train and test reduced to strictly 0.

---

### Recommendation 4: Component-Isolated Feature Engineering (Medium Priority)
* **Empirical Justification:**
  * Investigation 3 established that global features aggregate whole-URL tokens, allowing standard query parameters (`?v=...&list=...`) to artificially inflate `entropy` (5.47), `digit_ratio` (0.066), and `special_cnt` (13).
* **Proposed Action:**
  * Engineer features that separate domain characteristics from path and query characteristics:
    1. `dom_entropy` vs. `query_entropy`: Isolates randomized domain algorithms (DGA) from standard base64 parameter IDs.
    2. `dom_digit_cnt` vs. `query_digit_cnt`: Distinguishes digits inside domain names (often suspicious) from digits in query parameters (normal).
    3. `path_token_count` and `query_param_count`: Structured representations replacing raw character counts.
* **Advantages:**
  * Prevents high-entropy parameters on trusted domains from triggering domain-level phishing heuristics.
* **Risks:**
  * Expanding the feature space increases tree model complexity and training time.
* **Expected Evaluation Criteria:**
  * Improved feature importance distribution; reduction of false alarms on parameter-heavy URLs without lowering PR-AUC.

---

### Recommendation 5: Decision Tree Regularization & Tree Depth Pruning (Medium Priority)
* **Empirical Justification:**
  * Investigation 1 and 3 showed that the production Random Forest has unconstrained tree depth (`max_depth=None`, pure leaves), allowing individual decision trees to memorize brittle splits on `entropy > 4.1` or `is_https == 1`.
* **Proposed Action:**
  * Benchmark regularized ensemble configurations:
    * `max_depth` constrained to 15–20 levels.
    * `min_samples_leaf` increased from 1 to 5 or 10.
    * `max_features` evaluated across `sqrt` and `log2`.
* **Advantages:**
  * Reduces over-fitting to minor statistical artifacts in the training data.
  * Shrinks model serialized size on disk from 51.8 MB down to ~15–25 MB.
* **Risks:**
  * Over-regularization can slightly reduce recall on subtle phishing attacks.
* **Expected Evaluation Criteria:**
  * Phishing F1-score must remain $\ge 91.0\%$ while decreasing tree-level unanimous false-alarm voting.

---

### Recommendation 6: Probability Calibration (Platt Scaling / Isotonic Regression) (Medium Priority)
* **Empirical Justification:**
  * Investigation 4 revealed that **116 False Positives (35.0%)** land in the narrow probability band between $0.50$ and $0.60$.
  * Phase 8 calibration analysis demonstrated that between 20% and 50% predicted probability, the uncalibrated Random Forest systematically over-predicts phishing risk by up to 17%.
* **Proposed Action:**
  * Evaluate `CalibratedClassifierCV` (using Sigmoid / Platt scaling or Isotonic regression) fitted on a held-out validation fold.
* **Advantages:**
  * Corrects intermediate probability inflation, pulling borderline benign URLs below the 0.50 threshold.
  * Provides mathematically interpretable probabilities for downstream security operations.
* **Risks:**
  * Isotonic regression requires sufficient validation data to prevent overfitting the calibration curve.
* **Expected Evaluation Criteria:**
  * Brier score reduction below 0.025; elimination of the 116 borderline false alarms without shifting the global threshold.

---

### Recommendation 7: Justified Lexical Feature Extensions (Lower Priority)
* **Empirical Justification:**
  * In Phase 8, False Negatives jumped to 420 on unseen domains because attackers with short, clean paths evade existing counters.
* **Proposed Action:**
  * Test targeted lexical features with clear security rationale:
    * Ratio of vowels to consonants in domain name (detects algorithmic generation).
    * Count of consecutive consonants or hyphens.
    * Brand name substring occurrence inside subdomains or paths (detects brand spoofing on dynamic cloud services).
* **Advantages:**
  * Catches subtle phishing attacks that currently evade 22-feature counters.
* **Risks:**
  * Feature proliferation without clear benefit; must be validated strictly via cross-validation.
* **Expected Evaluation Criteria:**
  * Statistically significant improvement in PR-AUC ($p < 0.05$).

---

### Recommendation 8: Optional Threat-Intelligence / Reputation Check (Future Phase)
* **Empirical Justification:**
  * Passive lexical analysis cannot determine whether a domain is an internationally recognized service (e.g., `youtube.com`, `wikipedia.org`, `gov.uk`).
* **Proposed Action:**
  * In a future phase, evaluate an optional hybrid architecture:
    * Stage 1: Fast local offline lookup against a verified high-reputation domain whitelist (e.g., Tranco top 10k list cached locally).
    * Stage 2: 22-feature ML classifier for non-whitelisted or multi-tenant subdomains.
    * Stage 3: Optional threat-intelligence API check (e.g., Google Safe Browsing, VirusTotal) for borderline probabilities ($0.45 \le p \le 0.55$).
* **Advantages:**
  * Completely eliminates false positives on top global web services while preserving lexical ML defense for novel domains.
* **Risks & Compliance:**
  * Whitelists can be abused if attackers compromise subdomains; API lookups introduce network latency and external privacy dependencies. Must adhere to strict rate limits and terms of service.
* **Expected Evaluation Criteria:**
  * 0 ms added latency for local caching; 100% false positive elimination on top 10,000 domains.

---

## 4. Phase C Execution Readiness Checklist

Before proceeding to Phase C implementation, the following gates must be satisfied:
- [x] Phase A Baseline Audit completed and cryptographically verified.
- [x] Phase B Data Quality, Representation, and Leakage Investigation completed.
- [x] All 7 Phase B reports documented in `reports/phase11/`.
- [x] Production artifacts verified as 100% untouched.
- [ ] Explicit user authorization to begin Phase C experimental implementation.

---

## 5. Evidentiary Distinctions

* **Verified Facts from Actual Files:** The existing production model is unregularized (100 trees, pure leaves), relies on 22 global features, and uses an uncalibrated default threshold of 0.50.
* **Measured Results:** 116 false positives (35.0%) are borderline ($0.50 \le p < 0.60$). 302 near-duplicates exist across splits.
* **Hypotheses Needing Further Testing:** Component-isolated entropy and dataset augmentation with dynamic legitimate URLs will resolve the YouTube false positive without harming recall.
* **Limitations:** Recommendations are strictly advisory during Phase B and must not be implemented until formal approval.
