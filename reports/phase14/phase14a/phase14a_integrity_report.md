# Phase 14A: System Integrity & Artifact Preservation Report

**Auditor:** Senior Machine Learning Engineer, Cybersecurity Researcher & Independent Evaluator  
**Phase:** 14A — Independent Evaluation Dataset Construction & Integrity Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & 100% VERIFIED  
**Preservation Rule:** Strict verification that baseline files, experimental models, and production logic remain unchanged.

---

## 1. Executive Summary

This report certifies the cryptographic integrity of all baseline and experimental artifacts before and after executing Phase 14A.

### Integrity Verification Highlights
1. **16 Baseline Files 100% Intact:** All 16 baseline files defined in `pre_phase_c_baseline_hashes.json` match their original SHA-256 hashes bit-for-bit.
2. **Experimental Models Untouched:** Candidate 4 (`cand04_rf_regularized_30f.joblib`) and Candidate 6 (`cand06_hist_gbdt_30f.joblib`) were not modified, retrained, or overwritten.
3. **Regression Test Suite Passing Cleanly:** Executing `python -m unittest discover -s tests` executed **111 tests in 44.298 seconds with 0 failures and 0 errors**.
4. **Isolated Storage:** All Phase 14A artifacts are strictly isolated in `data/phase14a/` and `reports/phase14/phase14a/`.

---

## 2. Baseline and Production Artifact Checksum Verification

Every critical project artifact was verified against its baseline checksum record:

| Artifact Name | File Path | Baseline SHA-256 Hash | Post-Phase 14A SHA-256 Hash | Verification Status |
| :--- | :--- | :--- | :--- | :---: |
| **Raw Dataset** | `dataset/Dataset.csv` | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1` | **MATCH (OK)** |
| **Processed Train** | `data/processed/train.csv` | `db6360640510ea2b30b6b8449e06edaca14be4e8784573e3dce21fa3c5ab4294` | `db6360640510ea2b30b6b8449e06edaca14be4e8784573e3dce21fa3c5ab4294` | **MATCH (OK)** |
| **Processed Test** | `data/processed/test.csv` | `8764066a97ec387126aa40f961d0bd6fdf6d045c344b7a93dd5df87f017e1955` | `8764066a97ec387126aa40f961d0bd6fdf6d045c344b7a93dd5df87f017e1955` | **MATCH (OK)** |
| **Processed X_train** | `data/processed/X_train.csv` | `a6595975c9d150880a351ce545e53de2ae19a7c7e6f7a7958af967982919362f` | `a6595975c9d150880a351ce545e53de2ae19a7c7e6f7a7958af967982919362f` | **MATCH (OK)** |
| **Processed X_test** | `data/processed/X_test.csv` | `71c2beb3449c1947bec20a6e3d44f04405d32b30de7d88a66b8b9eaefb7ea2cc` | `71c2beb3449c1947bec20a6e3d44f04405d32b30de7d88a66b8b9eaefb7ea2cc` | **MATCH (OK)** |
| **Processed y_train** | `data/processed/y_train.csv` | `009e4b9dcf61d71070d91492704d447d161f7309b9f4f10e677892b6d98d6b87` | `009e4b9dcf61d71070d91492704d447d161f7309b9f4f10e677892b6d98d6b87` | **MATCH (OK)** |
| **Processed y_test** | `data/processed/y_test.csv` | `4303dc0e2a3745a7d0a7523181af8cee8cd4cfe4bab55dd409499b559a2c14ed` | `4303dc0e2a3745a7d0a7523181af8cee8cd4cfe4bab55dd409499b559a2c14ed` | **MATCH (OK)** |
| **Split Metadata** | `data/processed/split_metadata.json` | `bd09e42ab78afe9b12e68104ba3d01db3140da9f806efff70a4ae0457e37e5ed` | `bd09e42ab78afe9b12e68104ba3d01db3140da9f806efff70a4ae0457e37e5ed` | **MATCH (OK)** |
| **Production Model** | `models/phishing_model.joblib` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | **MATCH (OK)** |
| **Production RF** | `models/random_forest.joblib` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | `fca66c3fadc73855fe4badde7ed47f0a37595720da3517af7e5c7ca02ee6aaa5` | **MATCH (OK)** |
| **Production LR** | `models/logistic_regression.joblib` | `fa5e785ce2fd5e60a1e70d526a060e840d0e51d2a50fc6570c73d41c9e25cc55` | `fa5e785ce2fd5e60a1e70d526a060e840d0e51d2a50fc6570c73d41c9e25cc55` | **MATCH (OK)** |
| **Flask App Code** | `app.py` | `c5173532339a9d21ddb2a6213587c72c5da986f53fdc1c43bbafda6a5f43ac14` | `c5173532339a9d21ddb2a6213587c72c5da986f53fdc1c43bbafda6a5f43ac14` | **MATCH (OK)** |
| **Feature Extraction** | `src/feature_extraction.py` | `0b2b9b2277914af12eb03953a8015870c44816292c9ef50e1defd01408a96742` | `0b2b9b2277914af12eb03953a8015870c44816292c9ef50e1defd01408a96742` | **MATCH (OK)** |
| **Preprocessing Py** | `src/preprocess.py` | `845ce2934b77b84658f4e61be1004fefad1d962554949ecf34817cb90e53c7bf` | `845ce2934b77b84658f4e61be1004fefad1d962554949ecf34817cb90e53c7bf` | **MATCH (OK)** |
| **Training Script** | `src/train.py` | `f5fa6a4197fc661269880be427014afe5a22755f430f1279de8c3c23c6ef63a0` | `f5fa6a4197fc661269880be427014afe5a22755f430f1279de8c3c23c6ef63a0` | **MATCH (OK)** |
| **Realistic Benchmark**| `data/realistic_evaluation_set.csv`| `eae89a8a6ae7bdee6d28dbe2e81c1dce769e4de7e1fc2ac647fa9b2fec80eca9` | `eae89a8a6ae7bdee6d28dbe2e81c1dce769e4de7e1fc2ac647fa9b2fec80eca9` | **MATCH (OK)** |

---

## 3. Experimental Candidate Model Checksums

The two leading experimental models from Phase 13C-2 were also confirmed untouched:

| Candidate Model | Artifact Path | File Size | SHA-256 Hash | Integrity Status |
| :--- | :--- | :--- | :--- | :---: |
| **Candidate 4** | `models/experiments/phase13c2/cand04_rf_regularized_30f.joblib` | 15,254,025 B | `15e8c18ec628a553c30ea515d6666ba8a1c97040445dbe7b9fc66e409ecdb480` | **VERIFIED INTACT** |
| **Candidate 6** | `models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib` | 385,304 B | `33ad4f93ee7c191a6d71b4a6fb70d6a2f7c0a969e00185e985b96798e847c210` | **VERIFIED INTACT** |

---

## 4. Regression Test Suite Execution Audit

To verify that the inference adapters, layered decision engine, threat intelligence feeds, and preprocessing pipelines remain fully operational, the complete test suite was executed:

- **Command Executed:** `python -m unittest discover -s tests`
- **Working Directory:** `c:\Users\yalla\OneDrive\Desktop\PhishGuardAI`
- **Execution Timestamp:** 2026-10-28T16:04:24Z (task-1028)
- **Duration:** 44.298 seconds
- **Total Tests Discovered:** 111
- **Passed Tests:** **111 (100.0%)**
- **Failed Tests:** **0**
- **Errors:** **0**
- **Test Result:** **OK**

### Test Module Breakdown
- `test_api.py`: REST API endpoints and payload handling (Passed).
- `test_decision_engine.py`: Multi-tier verdict generation, risk levels, and explainability rules (Passed).
- `test_domain_generalization.py`: Cross-domain lexical behavior (Passed).
- `test_feature_extraction.py`: 22-feature baseline parity (Passed).
- `test_frontend.py`: UI template rendering and API integration (Passed).
- `test_model_inference_adapter.py`: 22 new adapter tests for dynamic thresholding and class mapping (Passed).
- `test_preprocess.py`: Deduplication, splitting, and schema validation (Passed).
- `test_threat_intelligence.py`: Mocked multi-provider aggregation and timeout resilience (Passed).
- `test_train.py`: Pipeline training sanity checks (Passed).

---

## 5. Integrity Sign-Off

All mandatory preservation rules were honored:
- Zero lines of production code were altered.
- Zero models were retrained.
- Zero thresholds were adjusted.
- The evaluation dataset was constructed strictly as a locked, read-only evaluation asset in `data/phase14a/`.
