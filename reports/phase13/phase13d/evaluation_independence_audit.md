# Phase 13D: Evaluation Independence & Data Integrity Audit

**Auditor:** Senior Machine Learning Engineer & Cybersecurity Researcher  
**Phase:** 13D — Independent Error Analysis & Model Selection Audit  
**Date:** 2026-10-28  
**Status:** COMPLETE & TRANSPARENTLY DISCLOSED  
**Scope:** Dataset Partitioning, Test Set Holdout, Realistic Benchmark Quarantine, Multi-Tenant Domain Grouping, and Source Overlap Audit

---

## 1. Executive Summary

This audit evaluates the scientific validity, independence, and leakage resistance of the evaluation methodology across Phases 13C-1, 13C-2, and 13D.

In high-stakes cybersecurity applications, data leakage and benchmark contamination can artificially inflate performance metrics. We audited the dataset construction pipelines, git history, split keys, and feature extraction scripts to verify five core evaluation integrity criteria:
1. **Final Test Set Independence:** Was the test set held out strictly, or did it influence model selection?
2. **Prior Inspection of Test Set:** Were test predictions inspected during iterative development?
3. **Realistic Benchmark Quarantine:** Was the 41-URL benchmark quarantined from training data? Did it influence feature design?
4. **Domain Grouping & Multi-Tenant Hosting:** Does domain grouping prevent leakage across SaaS/PaaS multi-tenant hosts?
5. **Data Source Overlaps:** Are there duplicate records or cross-feed overlaps inflating performance?

---

## 2. Audit Finding 1: Final Test Set Independence & Prior Inspection

### Verified Historical Sequence
1. In **Phase 13C-1**, the experimental dataset ($N = 50,144$) was partitioned into:
   - **Train Split:** 40,088 samples (80.0%)
   - **Validation Split:** 5,155 samples (10.3%)
   - **Test Split:** 4,901 samples (9.7%)
2. In **Phase 13C-2**, seven candidate models were trained strictly on the train split and evaluated on the validation split.
   - All hyperparameter tuning, regularizations, feature-schema comparisons (22f vs 30f), and threshold selections ($\tau = 0.50$) were performed **exclusively using `val.csv`**.
   - Candidate 4 was selected based on validation metrics (lowest validation FPR and tree auditability).
3. **First Evaluation on Test Split:**
   - Once Candidate 4 was finalized, it was scored once on `test.csv` in Phase 13C-2 to establish final generalizability metrics for [training_and_validation_report.md](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/reports/phase13/phase13c2/training_and_validation_report.md).
   - The test set was **never used to tune hyperparameters or filter features**.

### Critical Audit Disclosure
- In **Phase 13D**, to perform the user-mandated comparison between Candidate 4 and Candidate 6, Candidate 6 was also evaluated on the final test set.
- Although Candidate 6 demonstrates superior performance on the test set (cutting query false positives from 53.33% to 23.33% and detecting 13 more phishing attacks), **Candidate 6 cannot be retroactively chosen as the "official Phase 13C-2 model" using test performance**, as doing so would violate the holdout integrity of the test set.
- **Formal Recommendation:** For any future production release or published claim, the current test set (`data/phase13c/splits/test.csv`) must be retired, and a **brand-new, independent, unseen evaluation set** must be collected.

---

## 3. Audit Finding 2: Realistic Benchmark Quarantine & Feature Influence

### Verification of Benchmark Quarantine
- The realistic evaluation set contains 41 URLs ([realistic_evaluation_set.csv](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/realistic_evaluation_set.csv)) representing 25 unique registered domains.
- In Phase 13C-1, the quarantine filter in [scratch/phase13c_build_dataset.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/scratch/phase13c_build_dataset.py#L126-L142) was executed:
  - Exact URL match: All 41 benchmark URLs were quarantined.
  - Normalized URL match: All variations were quarantined.
  - Registered domain match: **All 6,356 records** in the raw corpus sharing any registered domain with the benchmark (e.g. `youtube.com`, `wikipedia.org`, `amazon.com`) were permanently excluded.
- **Verification on Disk:** Cross-referencing `train.csv`, `val.csv`, and `test.csv` against `realistic_evaluation_set.csv` confirms:
  - **Zero benchmark URLs exist in train, validation, or test splits (0% overlap).**
  - **Zero benchmark registered domains exist in train, validation, or test splits (0% domain overlap).**

### Disclosure of Qualitative Feature Influence
While the benchmark data was strictly quarantined from model training, **the qualitative characteristics of the benchmark (specifically, the YouTube lecture URL's long query string and complex parameters) directly informed the selection of the 8 new experimental features** in Phase 13C-1:
- `query_len`
- `query_param_cnt`
- `query_entropy`
- `query_digit_cnt`
- `path_depth`
- `dom_entropy`
- `dom_digit_cnt`
- `subdom_len`

This is standard iterative engineering: failure modes observed in diagnostic audits inform feature engineering. However, it means that performance on the realistic benchmark cannot be claimed as an unbiased blind evaluation; it serves as a regression validation suite.

---

## 4. Audit Finding 3: Multi-Tenant Hosting & Domain Grouping

### The Public Suffix List & Multi-Tenant Partitioning
In web security, multi-tenant hosting platforms (e.g. GitHub Pages, Vercel, Netlify, Cloudflare Pages, Firebase, AWS S3) host thousands of unrelated users under a shared parent domain (`user1.github.io`, `user2.github.io`).

We audited how domain grouping was implemented in [scratch/phase13c_build_dataset.py](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/scratch/phase13c_build_dataset.py#L69-L92):
```python
MULTI_TENANT_DOMAINS = {
    "pages.dev", "weebly.com", "amazonaws.com", "azurewebsites.net",
    "firebaseapp.com", "wixsite.com", "blogspot.com", "github.io",
    "gitlab.io", "square.site", "framer.app", "herokuapp.com",
    "netlify.app", "vercel.app", "wordpress.com", "sites.google.com"
}

def extract_domain_and_group_key(url: str):
    ext = extractor(url)
    reg_dom = f"{ext.domain}.{ext.suffix}".lower()
    sub = ext.subdomain.lower() if ext.subdomain else ""
    
    # If multi-tenant, group key includes the subdomain tenant
    if reg_dom in MULTI_TENANT_DOMAINS and sub:
        tenant = sub.split(".")[-1]
        group_key = f"{tenant}.{reg_dom}"
    else:
        group_key = reg_dom
    return reg_dom, group_key
```

### Empirical Audit Results
1. **Group Key Overlap:**
   - Hashing `split_group_key` produces **0 overlapping group keys** between Train, Val, and Test splits:
     - `Overlap(Train, Val) = 0`
     - `Overlap(Train, Test) = 0`
     - `Overlap(Val, Test) = 0`
   - No individual tenant (e.g. `phish-portal.weebly.com`) appears in more than one partition.
2. **Parent Domain Overlap:**
   - Because `split_group_key` operates at the tenant level, 9 multi-tenant parent platforms appear across partitions:
     - `vercel.app`: Train=82, Val=12, Test=16
     - `wordpress.com`: Train=33, Val=3, Test=3
     - `blogspot.com`: Train=53, Val=4, Test=8
     - `square.site`: Train=23, Val=2, Test=4
     - `github.io`: Train=63, Val=7, Test=8
     - `framer.app`: Train=48, Val=7, Test=4
     - `azurewebsites.net`: Train=4, Val=1, Test=3
     - `netlify.app`: Train=48, Val=5, Test=4
     - `amazonaws.com`: Train=13, Val=1, Test=2

### Audit Evaluation of Multi-Tenant Strategy
- **Why this was necessary:** If multi-tenant domains were strictly grouped by registered domain (`github.io`), all GitHub Pages sites in the entire dataset would be forced into a single partition. This would starve the other splits of free-hosting phishing lures and documentation sites.
- **Potential Risk:** Shared platform characteristics (e.g. typical URL path styles or shared sub-suffixes) could theoretically provide weak correlation signals between train and test.
- **Audit Conclusion:** The tenant-aware grouping strategy is standard and justifiable, but future iterations should ensure that distinct threat actors and distinct campaigns are isolated across splits.

---

## 5. Audit Finding 4: Data Source Overlaps and Contamination

We verified the source distributions across the dataset splits:

| Split | Total URLs | Mendeley Benign Crawl | OpenPhish Active Feeds | Wiki / ArXiv / Docs Expansions | Duplicate Normalized URLs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | 40,088 | 31,480 (Legit) + 8,284 (Phish) | 162 (Phish) | 162 (Legit) | **0 duplicates** |
| **Validation** | 5,155 | 3,903 (Legit) + 1,219 (Phish) | 22 (Phish) | 11 (Legit) | **0 duplicates** |
| **Test** | 4,901 | 3,864 (Legit) + 1,009 (Phish) | 20 (Phish) | 8 (Legit) | **0 duplicates** |

- There are **zero exact or normalized URL duplicates** across any partition.
- The raw baseline duplicates and corrupted labels identified in Phase 13B were fully purged.

---

## 6. Audit Verdict and Governance Rules

1. **Evaluation Integrity Status:** **SOUND & AUDITED.**
   The validation-based candidate selection, test set holdout, and benchmark quarantine were implemented strictly according to reproducible ML protocols.
2. **Mandatory Independence Governance:**
   - The Phase 13D test findings (demonstrating Candidate 6's query superiority) must be treated as diagnostic research, **not as a license to perform retrospective selection**.
   - Before Phase 14 or any production release, PhishGuardAI must construct a **fresh evaluation dataset (Phase 14 Test Corpus)** from newly acquired feeds to evaluate the final model and Layered Decision Engine independently.
