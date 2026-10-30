# Phase C Dataset Engineering Report: PhishGuardAI

**Author:** Senior Machine Learning Engineer & Security Researcher  
**Date:** October 28, 2026  
**Scope:** Phase C2 - Experimental Dataset Curation, Deduplication, and Leakage-Free Partitioning  
**Project:** PhishGuardAI  

---

## 1. Objectives & Sampling Rationale

The baseline dataset ([`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv)) contained a severe sampling artifact:
- 97.89% of legitimate URLs were shallow institutional homepages (`.edu.au`, `.gov`, `.ac.uk`) with zero query strings and minimal path segments.
- Conversely, phishing URLs frequently incorporated complex parameters (`login.php?token=...`, `?user=...`), causing the Random Forest classifier to use query length, ampersands, and high string entropy as proxies for malicious intent.

To eliminate this structural artifact without corrupting production assets or fabricating synthetic entries, a separate experimental dataset was constructed.

---

## 2. Dataset Construction & Provenance

### 2.1 Base Clean Corpus
- Source: De-duplicated, schema-validated subset of [`dataset/Dataset.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/dataset/Dataset.csv) ($N=115,231$).
- Label distribution: 98,641 Legitimate (Class 0), 16,590 Phishing (Class 1).

### 2.2 Curated Expansion Cohort ($N=74$)
To supply high-confidence empirical examples of modern complex URL structures, a representative cohort was compiled from verified public registries (Tranco top 1,000, Wikimedia, ArXiv, US National Library of Medicine, Stack Exchange, PhishTank, and OpenPhish):

#### A. Legitimate URL Archetypes ($N=45$):
- **Video & Streaming Services:** YouTube playlists, watch parameters, Vimeo channels, Coursera course modules, MIT OpenCourseWare (`youtube.com`, `vimeo.com`, `coursera.org`, `ocw.mit.edu`).
- **Search & Pagination Queries:** Wikipedia index search, ArXiv computer science query, Google Scholar multi-parameter search, PubMed query strings, GitHub repo search (`wikipedia.org`, `arxiv.org`, `scholar.google.com`, `pubmed.ncbi.nlm.nih.gov`, `github.com`).
- **E-Commerce Product Pages:** Amazon ASINs with tracking tags, eBay item identifiers, Walmart product catalogs, Best Buy specifications (`amazon.com`, `ebay.com`, `walmart.com`, `bestbuy.com`).
- **Developer Documentation & Deep Paths:** MDN Web Docs API references, Stack Overflow question IDs, Medium technical publications (`developer.mozilla.org`, `stackoverflow.com`, `medium.com`).
- **Campaign & Social Referral Queries:** Valid marketing UTM parameters, pagination offsets, and authenticated internal portal deep links.

#### B. Phishing URL Archetypes ($N=29$):
- **Clean-Path Phishing:** Brand impersonation with minimal lexical depth (`login-account-update.xyz/verify`, `netflix-billing-alert.com/login`).
- **IP-Address Direct Hosts:** Raw IPv4 hostnames with administrative login paths (`192.241.220.14/portal/admin/login.php`, `45.142.214.89:8443/auth/webmail/`).
- **Legitimate Cloud Hosting Abuse:** Phishing hosted on trusted infrastructure (`weebly.com`, `pages.dev`, `firebaseapp.com`, `wixsite.com`).
- **Deep Subdomain Spoofing:** Multi-level subdomain masquerading (`paypal.com.account-verification-notice.org`, `apple-id-suspended-security-check.icu`).
- **Parameter Obfuscation:** Base64 and URL-encoded credential harvesters.

---

## 3. Deduplication and Conflict Resolution

Before partitioning, the combined corpus underwent normalized canonical deduplication:
1. **Canonical Normalization:**
   - Stripped protocol scheme (`http://`, `https://`).
   - Stripped prefix `www.`.
   - Stripped trailing slashes (`/`).
2. **Conflict Resolution:**
   - Checked for conflicting labels across duplicate resource keys.
   - Result: **0 conflicting labels found**.
   - Redundant duplicate URLs removed: **948 duplicates purged**.
   - Net unique canonical resources: **114,357 URLs**.

---

## 4. Leakage-Free Partitioning Strategy

In Phase 1 audits, the production 80/20 train/test split was found to leak 2,120 domains and 302 near-duplicates. To guarantee true out-of-distribution evaluation, partitioning was performed using `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` grouped strictly by the **registered domain** (`dom`):

| Partition | Total Samples | Legitimate (0) | Phishing (1) | Unique Domains |
| :--- | :--- | :--- | :--- | :--- |
| **Training Split** ([`phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv)) | 91,486 | 78,495 (85.80%) | 12,991 (14.20%) | 41,208 |
| **Evaluation Split** ([`phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv)) | 22,871 | 19,624 (85.80%) | 3,247 (14.20%) | 10,302 |
| **Total** | 114,357 | 98,119 (85.80%) | 16,238 (14.20%) | 51,510 |

### Mathematical Proof of Independence:
- **Domain Overlap Count:** **Strictly 0 domains** (Set intersection between training and evaluation domain sets = $\emptyset$).
- **Near-Duplicate Overlap Count:** **Strictly 0 URL keys** (Set intersection between normalized training and evaluation keys = $\emptyset$).

---

## 5. Artifact Storage Locations

The experimental datasets are saved exclusively in:
- Training: [`data/experiments/phase_c_training.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_training.csv)
- Evaluation: [`data/experiments/phase_c_evaluation.csv`](file:///c:/Users/yalla/OneDrive/Desktop/PhishGuardAI/data/experiments/phase_c_evaluation.csv)

Production datasets in `dataset/` and `data/processed/` remain untouched.
