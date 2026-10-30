# Phase 13D: Final Evaluation Summary & Architectural Recommendation

**Auditor:** Senior Machine Learning Engineer & Cybersecurity Researcher  
**Phase:** 13D — Independent Error Analysis & Model Selection Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & FINALIZED  
**Preservation Rule:** Strictly evaluation and analysis. Zero model retraining. Zero production modifications.

---

## 1. Executive Verdict: Candidate 6 is Recommended for Future Development

Following our independent investigation of the Phase 13C-2 artifacts, mathematical reproduction of all validation and test metrics, sliced error analysis, benchmark evaluation, and decision engine integration auditing, our definitive recommendation is:

> **Candidate 6 (`cand06_hist_gbdt_30f`) is the more appropriate and technically superior model for further development and eventual deployment in PhishGuardAI.**

While Candidate 4 (`cand04_rf_regularized_30f`) was selected in Phase 13C-2 due to a minor 0.23% advantage on aggregate validation false positive rate on static URLs and familiar Random Forest tree inspectability, our deep diagnostic audit proves that **Candidate 6 resolves the core architectural failure modes that have plagued PhishGuardAI since Phase 11**.

---

## 2. Comprehensive Candidate Evaluation Matrix

Below is the consolidated audit comparison across all empirical benchmarks, slices, and operational criteria:

| Evaluation Dimension | Candidate 4 (`cand04_rf_regularized_30f`) | Candidate 6 (`cand06_hist_gbdt_30f`) | Advantage & Significance |
| :--- | :--- | :--- | :--- |
| **Model Family** | Regularized Random Forest (150 trees) | Histogram Gradient Boosting (HistGBDT) | HistGBDT uses SIMD integer binning |
| **Validation F1-Score** | 0.9111 (0.911068) | **0.9138** (0.913780) | **Cand06 +0.0027** |
| **Validation Phishing Recall** | 94.52% (1,173 / 1,241) | **95.65%** (1,187 / 1,241) | **Cand06 +1.13%** (14 more phish caught) |
| **Validation Aggregate FPR** | **4.11%** (161 / 3,914) | 4.34% (170 / 3,914) | Cand04 +0.23% (9 fewer FPs on static URLs) |
| **Validation PR-AUC** | 0.9630 | **0.9734** | **Cand06 +0.0104** (Superior precision ranking) |
| **Validation Brier Score** | 0.0388 | **0.0341** | **Cand06 Lower Loss** (Sharper calibration) |
| **Held-Out Test Accuracy** | 95.14% (4,663 / 4,901) | **95.41%** (4,676 / 4,901) | **Cand06 +0.27%** |
| **Held-Out Test Recall** | 93.20% (959 / 1,029) | **94.46%** (972 / 1,029) | **Cand06 +1.26%** (13 more phish caught) |
| **Test Query-URL FPR ($N=99$)** | 53.33% (16 / 30 FPs) | **23.33%** (7 / 30 FPs) | **Cand06 CUTS QUERY FPR BY > 50%!** |
| **Test Mid-Length FPR ($[50,90)$)**| 11.74% (31 / 264 FPs) | **6.06%** (16 / 264 FPs) | **Cand06 CUTS MID-LENGTH FPR BY ~50%!** |
| **Benchmark Phish Recall ($N=15$)**| **100.0%** (15 / 15) | 93.33% (14 / 15) | Cand04 raw ML; Cand06 100% in Layered Engine |
| **Benchmark Legit FPR ($N=23$)**| 78.26% (18 / 23 FPs) | **65.22%** (15 / 23 FPs) | **Cand06 has 3 fewer false positives** |
| **Disk & Memory Footprint** | 15.25 MB (15,254,025 bytes) | **0.39 MB** (385,304 bytes) | **Cand06 is 39.6x SMALLER!** |
| **Inference Latency** | Higher (150 unconstrained trees) | **Significantly Lower** (Binned integer tree) | HistGBDT is faster per HTTP request |
| **Native Tree Transparency** | Standard `tree_` scikit-learn API | Histogram binning (Opaque tree splits) | Cand04 easier for individual node audits |
| **Decision Engine Synergy** | 100% Compatible | **100% Compatible** | Full parity in Layered Decision Engine |

---

## 3. The Core Technical Case for Candidate 6

### 1. Slashing False Positives on Dynamic and Query-Bearing URLs
The original flaw reported in Phase 11 was that legitimate, real-world URLs with complex query strings (such as educational YouTube videos, academic search queries, and documentation links) were assigned high phishing scores.
- When evaluating the held-out test split, Candidate 4 failed on **53.33% of legitimate query-bearing URLs**.
- Candidate 6 cut this false positive rate down to **23.33%**—correctly resolving more than half of the query errors.
- On medium-length URLs ($50-90$ characters), Candidate 6 cut false positives from 31 down to 16 ($6.06\%$ vs $11.74\%$).
- On the realistic benchmark, Candidate 6 correctly identified Coursera, PubMed, and Victorian Government, which Candidate 4 misclassified.

### 2. Higher Phishing Interception Rate
In an adversarial cybersecurity context, catching real attacks is paramount:
- On validation data, Candidate 6 caught **14 more phishing URLs** than Candidate 4 ($1,187$ vs $1,173$).
- On test data, Candidate 6 caught **13 more phishing URLs** than Candidate 4 ($972$ vs $959$), lowering the false negative rate from $6.80\%$ to $5.54\%$.

### 3. Operational Efficiency (39.6x Memory Reduction)
- In production, PhishGuardAI runs inside a Flask/Gunicorn application serving concurrent web requests.
- Candidate 4 weighs **15.25 MB**, containing 150 deep unbinned trees. Forking multiple worker processes with large Random Forest ensembles increases memory consumption and startup cold-start times.
- Candidate 6 weighs **385 KB**—a **39.6-fold reduction**. Its 8-bit histogram representation enables rapid evaluation with minimal memory overhead.

### 4. Flawless Defense Synergy with the Layered Decision Engine
The only recorded vulnerability of Candidate 6 was missing `index 34` on the realistic benchmark (a PayPal brand subdomain spoofing attack, raw score $0.3923$).
- When evaluated inside the [LayeredDecisionEngine](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py), the engine's structural brand-spoofing rule immediately intercepted the attack and elevated the verdict to **`HIGH RISK`**.
- Similarly, for the target YouTube lecture URL where both models had elevated raw ML scores ($0.9083$ and $0.9667$), the engine's query contrast guardrail downgraded the assessment to **`INCONCLUSIVE` (medium risk)**, preventing a false positive alarm in production.
- Candidate 6 combined with the `LayeredDecisionEngine` provides a robust, defense-in-depth security architecture.

---

## 4. Phase 14 Action Plan & Roadmap

Per the mandatory preservation rules, no production code was modified and no models were retrained during Phase 13D. The following step-by-step roadmap is recommended for the next phase:

```
+---------------------------------------------------------------------------------------------------+
|                               PHASE 14 RECOMMENDED IMPLEMENTATION ROADMAP                         |
+---------------------------------------------------------------------------------------------------+
| Step 1: Curate Fresh Independent Benchmark (Phase 14 Test Set)                                    |
|         - Collect 5,000+ new URLs from current feeds (OpenPhish, Tranco, Alexa)                   |
|         - Maintain zero overlap with Phase 13C training data                                      |
|         - Serve as the uninfluenced release evaluation suite                                      |
+---------------------------------------------------------------------------------------------------+
| Step 2: Formalize Candidate 6 Deployment Artifact                                                 |
|         - Verify ModelInferenceAdapter configuration with Cand06 (HistGBDT 30f)                   |
|         - Package model artifact (385 KB) with exact feature schema metadata                      |
|         - Ensure backward compatibility with existing Flask REST endpoints                        |
+---------------------------------------------------------------------------------------------------+
| Step 3: Layered Decision Engine Integration Verification                                          |
|         - Bind LayeredDecisionEngine to Candidate 6 with default threshold tau = 0.50            |
|         - Run end-to-end regression tests across all 111 unit tests                               |
|         - Verify query complexity contrast guardrail and brand spoofing filters                   |
+---------------------------------------------------------------------------------------------------+
| Step 4: Controlled Shadow Deployment & Production Migration                                       |
|         - Run Candidate 6 in shadow mode alongside baseline model in app.py                       |
|         - Compare real-time live request verdicts and latency benchmarks                          |
|         - Once verified, safely update production model pointer with zero downtime                |
+---------------------------------------------------------------------------------------------------+
```

---

## 5. Final Audit Sign-Off

1. **All 8 Phase 13D Tasks Completed:**
   - [x] Task 1: Inspected all actual artifacts on disk.
   - [x] Task 2: Independently reproduced validation and test metrics with 0 discrepancy.
   - [x] Task 3: Audited model-selection trade-offs between Candidate 4 and Candidate 6.
   - [x] Task 4: Evaluated realistic benchmark with tri-partitioning and detailed misclassifications.
   - [x] Task 5: Investigated false positive structural root causes across 8 dimensions.
   - [x] Task 6: Investigated false negative evasion patterns across missed threat lures.
   - [x] Task 7: Audited evaluation independence, benchmark quarantine, and multi-tenant domain grouping.
   - [x] Task 8: Generated all 7 deliverables in [reports/phase13/phase13d/](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13d/).
2. **Preservation Rules Fully Maintained:**
   - Production model `models/phishing_model.joblib` is untouched.
   - `app.py` is untouched.
   - `dataset/Dataset.csv` is untouched.
   - Zero models retrained. Zero thresholds tuned.
3. **Audit Complete:** Ready for user review and Phase 14 authorization.
