# Phase 13A: Inference Pipeline Hardening & Guardrail Audit Report

**Date:** October 28, 2026  
**Status:** COMPLETE (Zero Retraining / Cryptographically Preserved Baseline)  
**Author:** ML Infrastructure & Security Engineering Team  
**Scope:** Pipeline Hardening, Model-Specific Inference Adapter, Dynamic Class Index Resolution, Threshold Standardization, Decision Engine Guardrail Audit, and Full Regression Testing  

---

## 1. Executive Summary

In accordance with the findings of the Phase 12 Diagnostic Audit ([reports/phase12/error_analysis_audit.md](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase12/error_analysis_audit.md)), Phase 13A implements critical infrastructure-level hardening and non-breaking pipeline corrections. Prior to altering training corpora or retraining experimental models in Phase 13B, this phase establishes a type-safe, warning-free, reproducible inference interface and audits the defensive guardrails of the layered decision engine.

### Strict Safety Adherence
* **Zero Model Training:** No models were fitted, tuned, or serialized.
* **Baseline Preservation:** All 16 baseline production and experimental artifacts—including [models/phishing_model.joblib](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/models/phishing_model.joblib), [app.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py), and [dataset/Dataset.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)—were cryptographically verified via SHA-256 and remain 100% unmodified.
* **Test Suite Expansion:** The test suite expanded from 89 to **111 tests**, achieving a 100% pass rate with zero warnings.

---

## 2. Verified Defects from Phase 12 Diagnostic Audit

| Defect ID | Severity | Component | Verified Mechanism | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | High | Feature Vector Delivery | Production model was fitted with `feature_names_in_` ([pd.DataFrame](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/features.py)), but inference code delivered raw NumPy 2D arrays, causing scikit-learn `UserWarning: X does not have valid feature names...`. Conversely, experimental models fitted on NumPy arrays threw warnings if passed DataFrames. | Console warning spam, potential silent feature misalignment under schema drift. |
| **DEF-02** | Critical | Class Index Resolution | [src/decision_engine/engine.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py) hard-coded `proba[1]` as phishing probability without querying `model.classes_`. | If an estimator orders classes as `[1, 0]` or uses string labels (`['legitimate', 'phishing']`), `proba[1]` accesses the wrong class or crashes. |
| **DEF-03** | Medium | Threshold Policy & Tie-Breaking | Disparate threshold semantics across modules; no documented tie-breaking convention at exact boundary ($P = \tau$). | Inconsistent classification near decision boundaries; lack of deterministic tie handling. |
| **DEF-04** | High | Brand Spoofing Guardrail | Substring matching `any(brand in subdomain for brand in TOP_IMPERSONATED_BRANDS)` flagged legitimate community platforms (`apple.stackexchange.com`) and coincidental brand substrings (`pineapple-farms.com`). | Excessive false positives on legitimate multi-tenant and community platforms. |
| **DEF-05** | Critical | Query Entropy Contrast Bypass | Attackers could append 2+ high-entropy query parameters (`?utm_source=...&token=...`) to an active credential harvesting URL on a `.com` domain, triggering `has_entropy_contrast` and downgrading `HIGH_RISK` phishing to `INCONCLUSIVE`. | Adversarial evasion of high-risk phishing lures via query padding. |
| **DEF-06** | Medium | Shared Hosting Abuse Guardrail | Legitimate developer documentation paths (`/docs/`, `/guide/`, `/api/`) hosted on platforms like GitHub Pages (`*.github.io`) were flagged as hosting abuse. | False positives on developer documentation websites. |

---

## 3. Files Created and Modified

### Backup Archival
Prior to any modifications, pre-change backups were archived:
* `backups/phase13/engine.py.bak`
* `backups/phase13/init.py.bak`

### Inventory of Changed Files
1. **[src/decision_engine/adapter.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/adapter.py)** *(NEW)*
   - Implements `ModelInferenceAdapter` to handle schema detection (22-feature baseline vs 30-feature experimental), input formatting, dynamic class resolution, and standardized threshold decisions.
2. **[src/decision_engine/engine.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py)** *(MODIFIED)*
   - Integrates `ModelInferenceAdapter`.
   - Hardens brand spoofing detection using discrete tokenization and community platform exemptions.
   - Excludes documentation/API paths from shared hosting abuse rules.
   - Closes query entropy contrast bypass by strictly forbidding downgrade if credential paths or keywords are present.
3. **[src/decision_engine/__init__.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/__init__.py)** *(MODIFIED)*
   - Exports `ModelInferenceAdapter` alongside `LayeredDecisionEngine`.
4. **[tests/test_model_inference_adapter.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_model_inference_adapter.py)** *(NEW)*
   - 22 comprehensive unit tests covering adapter features, missing inputs, class resolution, threshold boundaries, and guardrail edge cases.

---

## 4. Exact Technical Corrections

### 4.1 Model-Specific Inference Adapter ([src/decision_engine/adapter.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/adapter.py))
To satisfy Step 2 and Step 3, `ModelInferenceAdapter` encapsulates all interaction with the underlying estimator:

```python
class ModelInferenceAdapter:
    """
    Standardized inference adapter for scikit-learn models.
    
    Guarantees:
    1. Exact feature ordering matching training schemas (22 or 30 features).
    2. Zero scikit-learn warnings: emits named pd.DataFrame if estimator has
       feature_names_in_, or np.ndarray if estimator expects positional arrays.
    3. Type validation: catches missing features, non-numeric values, or NaNs.
    4. Dynamic class resolution: resolves target phishing class from model.classes_.
    5. Standardized threshold evaluation: proba >= threshold.
    """
```

* **Feature Schema Detection & Formatting:**
  The adapter inspects `model.n_features_in_` and `model.feature_names_in_`. If `feature_names_in_` exists (such as on the 22-feature production model), the feature vector is delivered as a named `pd.DataFrame` with column names strictly matching training order. If `feature_names_in_` is absent (such as on candidate experimental models), features are converted to a 2D `np.ndarray`. This completely eliminates all scikit-learn `UserWarning` messages.
* **Strict Validation (No Silent Zero-Substitution):**
  If a dictionary or DataFrame is passed with missing features, the adapter raises an explicit `ValueError` detailing the exact missing columns. Silent substitution of zeros is strictly forbidden.
* **Dynamic Class Index Resolution:**
  The adapter dynamically locates the index of target label `1` (or string labels `'phishing'`, `'malicious'`) in `model.classes_`:
  ```python
  def _resolve_phishing_class_index(self) -> int:
      classes = getattr(self.model, "classes_", None)
      if classes is None:
          return 1  # Default for uninitialized or mock pipelines
      for idx, cls in enumerate(classes):
          if cls in (1, "1", "phishing", "malicious", "Phishing"):
              return idx
      raise ValueError(f"Model classes {classes} do not contain positive target label 1")
  ```
  This guarantees correct probability extraction whether `classes_` is `[0, 1]`, `[1, 0]`, or string-labeled.

### 4.2 Standardized Threshold Policy
To satisfy Step 4, threshold evaluation is centralized:
$$\text{is\_phishing} = 1 \iff P(\text{phishing}) \ge \tau$$
* Exact probability ties ($P = \tau$) are consistently classified as phishing (conservative security posture).
* The default decision engine threshold remains $\tau = 0.50$, preserving existing production behavior while supporting explicit per-instance configuration.

### 4.3 Decision Engine Guardrail Hardening ([src/decision_engine/engine.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py))

#### A. Brand Impersonation Guardrail Hardening
* **Discrete Tokenization:** Replaced naive substring matching with regex boundary splitting on `[\.\-_]`. For example, `apple` matches `apple.phish.com` or `login-apple.com`, but does NOT match `pineapple-farms.com`.
* **Community & Developer Platform Exclusion:** Added `COMMUNITY_PLATFORMS = ("stackexchange.com", "github.io", "gitlab.io", "wordpress.com", "medium.com")`. Subdomains such as `apple.stackexchange.com` are exempted from brand spoofing heuristics because subdomain creation is part of the platform's legitimate namespace architecture.

#### B. Query Entropy Contrast Bypass Sealed
* An adversary previously could add benign-looking, high-entropy query parameters to a phishing URL to exploit `has_entropy_contrast` and downgrade `HIGH_RISK` to `INCONCLUSIVE`.
* We added strict gates: `has_entropy_contrast` is **strictly disallowed** from triggering if:
  1. `has_auth_path` is True (e.g. `/login`, `/auth`, `/signin`, `/verify`).
  2. The query contains credential-harvesting tokens (`pass`, `pwd`, `token`, `session`, `email`, `user`, `account`).
  3. The host is a direct IP address.

#### C. Shared Hosting Abuse Exemption for Documentation
* Legitimate developer documentation paths (e.g. `/docs/`, `/documentation/`, `/guide/`, `/api/`, `/manual/`) on shared hosting (`github.io`, `pages.dev`) are exempted from the generic hosting-abuse rule, preventing false positives on developer tools.

---

## 5. Regression Testing & Verification

### 5.1 Test Suite Summary
* **Adapter Unit Tests ([tests/test_model_inference_adapter.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_model_inference_adapter.py)):** 22 tests executed in 1.45s.
* **Full Project Test Suite:** 111 tests executed across 9 test modules in 40.72s.
* **Status:** **100% Passed (111 / 111). Zero Failures. Zero Errors.**

```
...............................................................................................................
----------------------------------------------------------------------
Ran 111 tests in 40.719s

OK
```

### 5.2 Breakdown of New Targeted Tests (22 Tests)

| Category | Test Case | Target Behavior Verified | Result |
| :--- | :--- | :--- | :--- |
| **Input Formatting** | `test_production_model_receives_dataframe` | Formats input as named `pd.DataFrame` matching `feature_names_in_`; zero warnings emitted. | PASS |
| | `test_array_model_receives_ndarray` | Formats input as `np.ndarray` when model lacks `feature_names_in_`; zero warnings emitted. | PASS |
| | `test_feature_order_strictly_preserved` | Scrambled input dictionaries are realigned to exact schema feature ordering. | PASS |
| | `test_schema_30_extraction_and_prediction` | Experimental 30-feature schema extracts and predicts correctly. | PASS |
| **Error Handling** | `test_missing_features_raises_value_error` | Missing features raise explicit `ValueError` (no silent zeros). | PASS |
| | `test_nan_feature_values_raise_value_error` | NaN / Infinite inputs raise explicit `ValueError`. | PASS |
| | `test_invalid_url_type_raises_type_error` | Non-string URLs raise explicit `TypeError`. | PASS |
| | `test_unsupported_schema_size_raises_value_error`| Input arrays with invalid column counts are rejected. | PASS |
| **Class Resolution** | `test_standard_binary_classes` | Class index 1 correctly mapped when classes are `[0, 1]`. | PASS |
| | `test_inverted_binary_classes` | Class index 0 correctly mapped when classes are `[1, 0]`. | PASS |
| | `test_string_classes` | Class index correctly mapped for `['benign', 'phishing']`. | PASS |
| | `test_missing_positive_class_raises_value_error`| Models lacking target class raise explicit `ValueError`. | PASS |
| **Threshold Logic** | `test_probability_below_threshold` | $P < \tau \implies \text{Class } 0$. | PASS |
| | `test_probability_equal_threshold` | $P = \tau \implies \text{Class } 1$ (deterministic tie-breaking). | PASS |
| | `test_probability_above_threshold` | $P > \tau \implies \text{Class } 1$. | PASS |
| **Guardrails** | `test_legitimate_community_platform_not_flagged`| `apple.stackexchange.com` not flagged as brand spoofing. | PASS |
| | `test_coincidental_brand_substring_not_flagged` | `pineapple-farms.com` not flagged as brand spoofing. | PASS |
| | `test_brand_spoofing_in_subdomain_flagged` | `paypal.secure-login-portal.com` flagged as brand spoofing. | PASS |
| | `test_direct_ip_url_flagged` | Direct IPv4 URL flagged as `SUSPICIOUS` / `HIGH_RISK`. | PASS |
| | `test_entropy_contrast_cannot_bypass_credential_lure` | High-entropy query parameters on credential lure cannot downgrade classification. | PASS |
| | `test_shared_hosting_abuse_flagged` | Phishing lure on `pages.dev` flagged appropriately. | PASS |
| | `test_documentation_on_shared_hosting_not_flagged`| Documentation on `pages.dev/docs/guide` not flagged as abuse. | PASS |

---

## 6. Cryptographic Baseline Verification

All 16 baseline artifacts from [data/experiments/pre_phase_c_baseline_hashes.json](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/pre_phase_c_baseline_hashes.json) were verified using SHA-256:

| Artifact Name | Relative Path | Expected SHA-256 | Verification |
| :--- | :--- | :--- | :--- |
| `raw_dataset` | `dataset/Dataset.csv` | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | **MATCH** |
| `production_model` | `models/phishing_model.joblib` | `378033878b277ffec1e07b7b9f8f4a13fbf5f284eef13ffbaeeea4081604a8c9` | **MATCH** |
| `production_rf` | `models/random_forest_model.joblib` | `378033878b277ffec1e07b7b9f8f4a13fbf5f284eef13ffbaeeea4081604a8c9` | **MATCH** |
| `production_lr` | `models/logistic_regression_model.joblib` | `a1985c4cff113c5dd31bb4882dfc7042fe58d9eeb4932ea4fb0c9ffef58c70eb` | **MATCH** |
| `app_py` | `app.py` | `d4e5fca9b9d3e8e19d1bb3543d8383e20ec42a8bdfb13f1cfa3ba9456dcceae4` | **MATCH** |
| `feature_extraction_py` | `src/features.py` | `f31f9f234720e5088f1ce15770c0c66099dfd3d2cf54e3d939a3f28cf6903253` | **MATCH** |
| `preprocess_py` | `src/preprocess.py` | `fe331ea0ae29a39f60cb05c866d9c665798e169d2a632a4e98f0203f19eec9be` | **MATCH** |
| `train_py` | `src/train.py` | `2ea06efb086e730fc9c4f0da99767fa6f72dc6451664bf870f7d5497c6ce250d` | **MATCH** |
| `processed_train` | `data/processed/train.csv` | `db6360640510ea2b30b6b8449e06edaca14be4e8784573e3dce21fa3c5ab4294` | **MATCH** |
| `processed_test` | `data/processed/test.csv` | `8764066a97ec387126aa40f961d0bd6fdf6d045c344b7a93dd5df87f017e1955` | **MATCH** |
| `processed_X_train` | `data/processed/X_train.csv` | `a6595975c9d150880a351ce545e53de2ae19a7c7e6f7a7958af967982919362f` | **MATCH** |
| `processed_X_test` | `data/processed/X_test.csv` | `71c2beb3449c1947bec20a6e3d44f04405d32b30de7d88a66b8b9eaefb7ea2cc` | **MATCH** |
| `processed_y_train` | `data/processed/y_train.csv` | `009e4b9dcf61d71070d91492704d447d161f7309b9f4f10e677892b6d98d6b87` | **MATCH** |
| `processed_y_test` | `data/processed/y_test.csv` | `9bfa4a66a1a1f1074eef7da61559ee7f5112cb5989b52a5138f292397c7bc992` | **MATCH** |
| `split_metadata` | `data/processed/split_metadata.json` | `5c9f56598e98ec712526e03ea29141f173c38031e847c177dc5137553bfa59da` | **MATCH** |
| `realistic_eval_set` | `data/experiments/realistic_eval_set.csv`| `7072a2db9ae0062a4b8df4bc7ff58728562d53e7f960bcfe1d45c61ae33767f4` | **MATCH** |

**Confirmation:** Zero model retraining occurred. The production model and dataset are 100% intact.

---

## 7. Remaining Risks and Next Steps (Phase 13B)

1. **Model Representation Limitations:**
   The hardened inference adapter guarantees clean, warning-free, schema-compliant inference. However, the underlying models themselves (baseline Random Forest and candidate models) still inherit the limitations of pure lexical features and the historical training dataset biases identified in Phase 12 (100% HTTP phishing vs 100% HTTPS legitimate).
2. **Phase 13B Readiness:**
   With a hardened, type-safe inference pipeline and verified guardrails, PhishGuardAI is now prepared for Phase 13B:
   - Augmenting the training corpus with diverse, legitimate complex HTTPS URLs.
   - Retraining and evaluating experimental candidate models under domain-held-out cross-validation.
   - Evaluating final performance on the realistic benchmark without data leakage or feature mismatch.

---
*End of Report — Awaiting User Review before initiating Phase 13B.*
