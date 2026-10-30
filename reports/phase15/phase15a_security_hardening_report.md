# PhishGuardAI — Phase 15A Security Hardening Report
## Input Validation and Decision-Engine Security Hardening

**Date:** October 29, 2026  
**Auditor / Engineer:** Senior Python Backend Engineer & Cybersecurity Engineer  
**Status:** COMPLETE — ALL TESTS PASSING (129/129) — ALL PROTECTED ARTIFACTS PRESERVED  

---

## 1. Executive Summary

During the Phase 14C reliability and security audit, three critical architectural vulnerabilities were identified in the PhishGuardAI evaluation and inference pipeline:
1. **Malformed URLs receiving safe verdicts:** Inputs such as `http://` or `https://///` bypassed early filtering and were assigned `NO KNOWN THREAT DETECTED` (Risk `LOW`).
2. **Unsupported URL schemes entering classification:** Non-web protocols such as `file:///etc/passwd`, `javascript:alert(1)`, and `data:text/plain,test` were fed directly into lexical feature extraction and ML inference, receiving `NO KNOWN THREAT DETECTED`.
3. **Punycode domains receiving safe verdicts without risk handling:** Internationalized domain names (IDNs) and Punycode hostnames (`xn--...`), including visual homograph spoofing attacks (e.g., `аpple.com` with Cyrillic 'а'), received low ML anomaly scores and fell through to `NO KNOWN THREAT DETECTED`.

In **Phase 15A**, we implemented the smallest safe, non-breaking architectural changes consistent with the system's design:
- Developed a centralized, strictly offline URL validation and normalization engine ([`src/decision_engine/url_validation.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py)).
- Integrated pre-inference input validation into [`LayeredDecisionEngine`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L194) and [`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py#L180).
- Implemented a two-tier Punycode security policy: deceptive mixed-script homograph spoofing is escalated to Tier 2 [`HIGH_RISK`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L311), while legitimate single-script IDNs enforce a [`SUSPICIOUS`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L423) (Risk `MEDIUM`) floor, strictly prohibiting `NO KNOWN THREAT DETECTED`.
- Expanded the safety test suite in [`tests/test_decision_engine_safety.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine_safety.py) covering all target inputs.
- Executed the full regression test suite (129 tests, 0 failures, 0 errors, 66.996s).
- Verified bit-for-bit SHA-256 preservation across all protected models and datasets.

---

## 2. Root Cause Analysis

### 2.1 Malformed URLs Receiving Safe Verdicts
* **Mechanism:** In the prior implementation of [`LayeredDecisionEngine.evaluate_url`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py), raw URL strings were passed directly to `ExperimentalURLFeatureExtractor` without syntactic authority or hostname verification.
* **Failure Mode:** On inputs like `http://` or `https://///`, `urllib.parse` extracted an empty `netloc` and `path`. The resulting 30-feature vector was populated with default zeroes (e.g., length=0, entropy=0, dots=0). When evaluated by Candidate 4 or Candidate 6, this zero feature vector yielded a very low model probability ($P(\text{phishing}) \approx 0.05\text{--}0.15$). Because the score fell below the ambiguous lower threshold (0.35) and had no active threat-feed match, Tier 3 assigned `NO KNOWN THREAT DETECTED` with Risk `LOW`.

### 2.2 Unsupported URL Schemes Entering Classification
* **Mechanism:** The decision engine lacked scheme-level gating. Non-HTTP protocols (`file:`, `javascript:`, `data:`, `mailto:`, `ftp:`) were accepted as valid input strings.
* **Failure Mode:** Lexical models trained on HTTP/HTTPS URLs cannot reliably evaluate local system file paths or embedded JavaScript payloads. These inputs received low anomaly scores and were falsely marked safe.

### 2.3 Punycode Domains Lacking Appropriate Risk Handling
* **Mechanism:** The decision engine previously flagged `has_punycode` only as an informational warning note, but did not enforce a minimum risk floor or inspect the underlying Unicode scripts.
* **Failure Mode:** Attackers register Punycode domains such as `xn--pple-43d.com` (which renders as `аpple.com` using Cyrillic small letter 'а' U+0430). Lexically, the domain length, character entropy, and token structures appear normal. A machine learning model scoring such domains would output a low probability, erroneously declaring `NO KNOWN THREAT DETECTED`.

---

## 3. Architecture and Implementation Details

### 3.1 Centralized URL Validation Engine
We created [`src/decision_engine/url_validation.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py), defining [`URLValidationResult`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py#L32), [`detect_mixed_script`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py#L72), and [`validate_url`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py#L94).

#### Key Validation Rules:
1. **Scheme Whitelist:** Only `http` and `https` schemes are accepted. Non-web schemes (`file:`, `javascript:`, `data:`, `ftp:`, `mailto:`) are rejected with descriptive messages.
2. **Authority & Hostname Validation:** Empty hostnames, bare schemes (`http://`, `https://///`), and missing domain specifications (`https:///path/only`) are rejected.
3. **IPv4 Octet Boundary Verification:** Hostnames composed of digits and dots are parsed via `ipaddress.IPv4Address`. Malformed IPv4 strings (e.g., `256.256.256.256`, `1.2.3.4.5`) are rejected.
4. **IPv6 Authority Verification:** Bracketed IPv6 hosts (e.g., `[::1]`) are validated via `ipaddress.IPv6Address`. Malformed bracketed structures (e.g., `[invalid_ipv6]`, `[:::1]`) are rejected.
5. **Length and Structure Bounds:** URLs exceeding length limits (app.py: 2048, engine: 4096) or hostnames exceeding RFC 1035 limits (253 characters total, 63 characters per label, leading/trailing hyphens) are rejected.
6. **Strictly Offline:** Zero network requests, zero socket connections, and zero DNS queries are performed.

### 3.2 Decision Engine Hardening (`LayeredDecisionEngine`)
Modifications to [`src/decision_engine/engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py):
1. **Pre-Inference Gate:** [`evaluate_url`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L194) calls [`validate_url(url)`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py#L94) immediately. If invalid:
   - Returns [`DecisionVerdict.INCONCLUSIVE`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L39) with [`RiskLevel.UNKNOWN`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L52).
   - `model_score` is explicitly set to `None`.
   - Populates evidence-based explanation and warnings explaining rejection.
   - **Guarantees that an invalid or malformed URL never receives `NO KNOWN THREAT DETECTED`.**
2. **Tier 2 Mixed-Script IDN Homograph Defense:**
   - Detects whether any discrete label in a decoded Punycode domain mixes Latin characters with non-Latin scripts (Cyrillic, Greek, Arabic, etc.).
   - Mixed-script labels (e.g., `xn--pple-43d.com` -> `аpple.com`) immediately trigger Tier 2 [`DecisionVerdict.HIGH_RISK`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L37) (Risk `HIGH`).
3. **Punycode Downgrade Guardrail:**
   - Punycode domains are barred from invoking the query-domain entropy contrast risk downgrade (`not structural_indicators.get("has_punycode", False)` in `can_abstain_query`).
4. **Punycode Risk Floor:**
   - For legitimate single-script IDN domains (e.g., pure Cyrillic `пример.рф`), passive lexical models cannot certify authenticity without active certificates or visual rendering.
   - Even when the statistical model outputs a low phishing score ($< 0.35$), the decision engine assigns [`DecisionVerdict.SUSPICIOUS`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py#L38) (Risk `MEDIUM`), **strictly barring `NO KNOWN THREAT DETECTED`**.

### 3.3 Flask REST API Hardening (`app.py`)
In [`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py#L180), `scan_url()` was updated to route all input through `validate_url(raw_url, max_length=2048)`. Invalid URLs immediately return HTTP 400 with a detailed error message, preserving 100% compatibility with existing test suites.

---

## 4. Test Results and Verification

### 4.1 Step 4 Focused Safety Tests
We authored 13 targeted test methods in [`tests/test_decision_engine_safety.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine_safety.py) directly auditing the required failure modes:

| Test Input / Condition | Evaluator Result | Verdict | Risk Level | Model Score | Expected Behavior Met |
|---|---|---|---|---|---|
| `http://` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| `https://///` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| `file:///etc/passwd` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| `javascript:alert(1)` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| `data:text/plain,test` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Empty input `""` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Whitespace `"   "`, `"\t\n"` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Missing Hostname `https:///path/only` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Malformed IPv4 `http://256.256.256.256` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Malformed IPv4 `http://1.2.3.4.5/` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Malformed IPv6 `http://[invalid_ipv6]/` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Malformed IPv6 `http://[:::1]/` | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Valid HTTP `http://example.com/test` | Passed Validation | `NO_KNOWN_THREAT` | `LOW` | `0.05` | Yes (Analyzed) |
| Valid HTTPS `https://example.com/test` | Passed Validation | `NO_KNOWN_THREAT` | `LOW` | `0.05` | Yes (Analyzed) |
| Single-script IDN `https://xn--e1afmkfd.xn--p1ai/` | Evaluated | `SUSPICIOUS` | `MEDIUM` | `0.05` | Yes (Punycode Floor) |
| Mixed-script homograph `https://xn--pple-43d.com/login` | Evaluated | `HIGH_RISK` | `HIGH` | `0.05` | Yes (Tier 2 Trigger) |
| Long URL (>4096 chars) | Validation Rejected | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Never safe) |
| Model inference exception | Handled | `INCONCLUSIVE` | `UNKNOWN` | `None` | Yes (Fail-safe) |
| Missing threat-feed providers | Handled | `NO_KNOWN_THREAT` (warn) | `LOW` | `0.05` | Yes (Degradation tolerance) |
| NaN and infinite feature values | Adapter Rejected | `ValueError` | N/A | N/A | Yes (Fail-safe) |

Execution output:
```text
Ran 13 tests in 0.216s
OK
```

### 4.2 Locked Phase 14A Dataset Validation
All 963 verified URLs from the locked Phase 14A independent evaluation dataset were processed through `validate_url`:
- Total URLs tested: 963
- Valid HTTP/HTTPS URLs: 963 (100.0%)
- Rejection count: 0 (0.0%)
- **Confirmation:** The hardened validation policy introduces zero false rejections on legitimate or phishing URLs in the locked benchmark.

### 4.3 Full Regression Test Suite
Execution command: `python -m unittest discover -s tests`

```text
Ran 129 tests in 66.996s

OK
```
- **Total Tests Executed:** 129
- **Failures:** 0
- **Errors:** 0
- **Runtime:** 66.996s
- **Status:** PASS (100%)

---

## 5. Artifact Hash Verification

Pre-change and post-change SHA-256 cryptographic hashes were recorded for all protected models and evaluation datasets:

| Artifact Identifier | Relative File Path | Pre-Change SHA-256 | Post-Change SHA-256 | Bit-for-Bit Match |
|---|---|---|---|:---:|
| `production_model` | `models/phishing_model.joblib` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | **YES** |
| `cand04` | `models/experiments/phase13c2/cand04_rf_regularized_30f.joblib` | `bbc5763359bebbfdb2a47bad34bea6d69d703f5c54ba91a11c6cb4d29df57408` | `bbc5763359bebbfdb2a47bad34bea6d69d703f5c54ba91a11c6cb4d29df57408` | **YES** |
| `cand06` | `models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib` | `452d9e9a6687cf05a209fead54e5c6bb93fa628f93994437f8e018e9fead744b` | `452d9e9a6687cf05a209fead54e5c6bb93fa628f93994437f8e018e9fead744b` | **YES** |
| `dataset` | `dataset/Dataset.csv` | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | **YES** |
| `phase14a_eval_set` | `data/phase14a/phase14a_verified_evaluation_set.csv` | `c4eaadadbc3cfcd96494c08e36e46e2dea6b62f6b360fcefed8834e13e83621c` | `c4eaadadbc3cfcd96494c08e36e46e2dea6b62f6b360fcefed8834e13e83621c` | **YES** |
| `phase14a_X_eval` | `data/phase14a/X_eval_30f.csv` | `d80ad4520fd2ee4089a7174fedf2a695be32585db639f3a1e1c1f9bf093465c8` | `d80ad4520fd2ee4089a7174fedf2a695be32585db639f3a1e1c1f9bf093465c8` | **YES** |
| `phase14a_y_eval` | `data/phase14a/y_eval.csv` | `4ba53c34e49e034caa7f9a8f473acb2d9ba06e16061be1306a590ae4e83e1e2f` | `4ba53c34e49e034caa7f9a8f473acb2d9ba06e16061be1306a590ae4e83e1e2f` | **YES** |

**Conclusion:** Zero retraining was conducted, zero thresholds were altered, and zero evaluation sets were modified. All hashes are 100% identical.

---

## 6. Files Created and Modified

1. [`src/decision_engine/url_validation.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/url_validation.py) *(Created)*:
   - Centralized offline URL validation, scheme whitelisting, authority verification, IPv4/IPv6 boundary checks, and IDN/Punycode normalization.
2. [`src/decision_engine/__init__.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/__init__.py) *(Modified)*:
   - Exported `validate_url`, `URLValidationResult`, and `detect_mixed_script`.
3. [`src/decision_engine/engine.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/src/decision_engine/engine.py) *(Modified)*:
   - Integrated `validate_url` at the entry point of `evaluate_url`.
   - Updated `_analyze_structure` to accept `validation` and propagate `has_mixed_script`, `unicode_host`, and `original_host`.
   - Added Tier 2 rule for deceptive mixed-script IDN homograph attack detection (`HIGH_RISK` / `HIGH`).
   - Barred Punycode domains from query entropy contrast risk downgrade.
   - Enforced Punycode risk floor: single-script IDN domains receive `SUSPICIOUS` (Risk `MEDIUM`), never `NO KNOWN THREAT DETECTED`.
4. [`app.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/app.py) *(Modified)*:
   - Integrated centralized `validate_url(raw_url, max_length=2048)` in `/api/scan`.
5. [`tests/test_decision_engine_safety.py`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/tests/test_decision_engine_safety.py) *(Modified)*:
   - Added comprehensive Step 4 safety test cases covering malformed authorities, schemes, Punycode domains, long inputs, and missing feeds.

---

## 7. Known Limitations

1. **Passive vs. Active Homograph Inspection:**
   - Mixed-script detection accurately flags cross-script attacks (e.g., Cyrillic mixed with Latin). However, whole-script homographs (where an entire label is written in Cyrillic to impersonate a Latin brand, e.g. `xn--e1afmkfd.xn--...`) cannot be differentiated from legitimate international websites without active SSL certificate inspection, visual layout rendering, or WHOIS registration telemetry.
   - For this reason, PhishGuardAI safely assigns `SUSPICIOUS` (Risk `MEDIUM`) to single-script IDNs rather than falsely certifying them as safe.
2. **Offline Boundary:**
   - URL validation is strictly offline and syntactic. Syntactically valid URLs pointing to newly registered phishing kits or fast-flux domains rely on the downstream ML model and threat intelligence feeds.

---

## 8. Phase 15B Readiness Assessment

| Readiness Criteria | Status | Notes |
|---|:---:|---|
| Architectural weaknesses resolved | **READY** | Malformed URLs, unsupported schemes, and Punycode homographs safely handled |
| Model and dataset integrity preserved | **READY** | All 7 cryptographic SHA-256 hashes verified identical |
| Existing contracts preserved | **READY** | Decision verdicts, risk levels, and REST responses adhere to existing schema |
| Regression test suite clean | **READY** | 129/129 tests passed in 66.996s with 0 failures and 0 errors |
| Offline operation maintained | **READY** | Zero live HTTP requests or DNS queries during validation or testing |

**Final Recommendation:**  
Phase 15A security hardening is **COMPLETE and CERTIFIED**. The codebase is in a secure, stable state and fully prepared to advance to **Phase 15B (Shadow Deployment & Production Verification)**.
