# PhishGuardAI — Commercial Feature Specifications & Product Architecture

This document outlines the complete feature set, technical specifications, and commercial tier offerings for **PhishGuardAI** as an enterprise-grade anti-phishing SaaS and browser security platform.

---

## 1. Executive Product Overview

**PhishGuardAI** is an AI-powered, multi-layered threat intelligence and anti-phishing defense platform. It protects businesses, platforms, and end-users from credential harvesting, zero-day phishing campaigns, brand impersonation, and malicious web destinations.

Unlike legacy URL filters that rely solely on outdated blocklists, PhishGuardAI combines **sub-millisecond threat intelligence caching**, **calibrated machine learning with domain telemetry**, and **deep headless sandboxing** into a unified 3-tier detection pipeline.

---

## 2. Multi-Tier Detection Engine Architecture

PhishGuardAI utilizes an adaptive defense-in-depth pipeline to balance speed, cost, and classification accuracy:

```
                            [ Incoming URL ]
                                   │
      ┌────────────────────────────┴────────────────────────────┐
      ▼                                                         ▼
[ Tier 1: Instant Cache ]                              [ Tier 1: Live Threat Feeds ]
- Redis In-Memory Lookup (< 2ms)                       - URLhaus, PhishTank, OpenPhish (< 50ms)
- Top 100K Verified Whitelist                          - Known malicious hash database
      │                                                         │
      └────────────────────────────┬────────────────────────────┘
                                   │ (If Unknown / Cache Miss)
                                   ▼
[ Tier 2: AI Lexical Model & Infrastructure Telemetry ]
- 30-Feature Calibrated HistGradientBoosting Classifier
- Real-Time WHOIS Domain Age (< 14 days anomaly penalty)
- DNS MX/NS Record Verification & SSL Certificate Transparency
- Decision Engine Heuristic Guardrails & Entropy Contrast
                                   │
      ┌────────────────────────────┴────────────────────────────┐
      │ (High Confidence Clean / Phish)                         │ (Ambiguous / Inconclusive)
      ▼                                                         ▼
[ Immediate Verdict Delivered ]               [ Tier 3: Deep Sandbox & Visual AI ]
                                               - Headless Chrome (Playwright) Crawling
                                               - DOM Credential Harvesting Detection (<input type="password">)
                                               - Computer Vision / Brand Logo Impersonation
                                               - Obfuscated Script & Redirect Analysis
```

---

## 3. Detailed Feature Breakdown

### 3.1 Tier 1: Real-Time Intelligence & Instant Cache
* **Sub-Millisecond Cache Layer:** Repeated lookups of known safe or malicious URLs are resolved via Redis in `< 2ms`, minimizing compute costs and latency.
* **Top 100K Tranco / Umbrella Whitelist:** Known legitimate services (Google, Microsoft, GitHub, Amazon, Netflix, YouTube) are instantly marked safe, eliminating false alarms on major platforms.
* **Live Threat Feed Sync:** Background worker automatically polls open and commercial threat feeds (Abuse.ch URLhaus, OpenPhish, PhishTank) every 30 minutes, keeping the blocklist up to date.

### 3.2 Tier 2: Machine Learning & Infrastructure Telemetry
* **30-Feature Lexical Extractor:** Evaluates structural complexity, character ratios, Shannon entropy, path depth, query parameter density, and symbol anomalies.
* **Calibrated HistGradientBoosting Classifier:** Outputs reliable, well-calibrated class probabilities (Brier score `< 0.04`) rather than raw overconfident guesses.
* **Domain Age & RDAP Telemetry:** Automatically retrieves domain registration dates. Domains created within the last 72 hours to 14 days are penalized as high-risk anomalies.
* **DNS & SSL Health Audit:** Verifies whether the domain has valid DNS resolution, active mail exchange (MX) records, and legitimate SSL/TLS certificates.
* **Layered Decision Engine with Fail-Safe Protection:** Automatically suppresses over-aggressive alerts, abstains to `INCONCLUSIVE` on low-confidence inputs, and includes security disclaimers for zero-day awareness.

### 3.3 Tier 3: Deep Headless Inspection & Visual Brand Defense
* **Automated Headless Sandbox:** Spins up an isolated, headless Chromium container (via Playwright) to navigate suspicious URLs safely without exposing user systems.
* **DOM Credential Harvester Detection:** Scans the page DOM for unverified `<input type="password">`, credit card fields, and social engineering login prompts hosted on untrusted domains.
* **Visual Logo & Brand Impersonation Check:** Captures high-resolution page viewports and uses computer vision to detect forged login portals (e.g., a Microsoft 365 login screen running on a random `.xyz` domain).
* **Dynamic Cloaking & Redirect Unmasking:** Follows HTTP 3xx, meta refresh, and JavaScript redirects to identify the final malicious destination.

---

## 4. Product Delivery Channels

### 4.1 Developer REST API (B2B SaaS)
* **High-Throughput Endpoints:**
  * `POST /v1/scan` — Synchronous scan with Tier 1 and Tier 2 evaluation (latency `< 80ms`).
  * `POST /v1/scan/deep` — Asynchronous deep scan with full Tier 3 sandboxing and webhook callbacks.
  * `POST /v1/batch` — Bulk scan up to 1,000 URLs in a single request.
  * `GET /v1/reputation/{domain}` — Domain-level trust score and age history.
* **Official SDKs:** Pre-built client libraries for **Python**, **Node.js/TypeScript**, and **Go**.
* **Pre-built Webhooks:** Instant alerting integrations for Slack channels, Discord servers, and Microsoft Teams.

### 4.2 Real-Time Browser Extension (Chrome, Edge, Brave)
* **Zero-Latency In-Browser Guard:** Intercepts outgoing web requests before navigation occurs.
* **Instant Blocking Interstitial:** Displays a prominent, secure warning screen when navigating to verified phishing or malicious sites.
* **Safety Badge & Inspector:** Extension popup shows the current domain's trust score, age, SSL verification, and risk breakdown.
* **Whitelist & Bypass Controls:** Enterprise administrators can enforce strict blocking while allowing user overrides where appropriate.

### 4.3 Web Management Dashboard
* **Real-Time Analytics:** Interactive charts showing total scans, threat detection rate, top targeted brands, and attacking TLDs.
* **API Key & Quota Hub:** Self-service portal to generate, revoke, and monitor API keys and usage quotas.
* **Historical Audit Logs:** Detailed queryable log of past scans, including feature breakdowns, domain ages, and forensic screenshots.

---

## 5. Commercial Pricing & Tier Matrix (Powered by Razorpay)

| Feature | Community (Free) | Developer Pro (₹1,999 / \$29/mo) | Business SaaS (₹9,999 / \$149/mo) | Enterprise (₹34,999+ / Custom) |
| :--- | :---: | :---: | :---: | :---: |
| **Monthly Scans** | 1,000 scans | 50,000 scans | 300,000 scans | 10,000,000+ scans |
| **Rate Limit** | 20 req/min | 200 req/min | 1,000 req/min | 5,000 req/min Dedicated |
| **Payment Methods** | N/A | UPI, Cards, Netbanking | UPI, Corporate Cards, Netbanking | GST Invoicing / Wire |
| **Tier 1 (Feeds & Fast Cache)** | Included | Included | Included | Included |
| **Tier 2 (ML + Domain Age)** | Included | Included | Included | Included |
| **Tier 3 (Headless Sandbox)** | ❌ | 100 deep scans/mo | 2,500 deep scans/mo | Custom Quota |
| **Browser Extension Access** | Individual | Individual | Team (Up to 25 seats) | Unlimited Org Seats |
| **Webhooks & Alerting** | ❌ | Email Alerts | Slack, Discord, Webhooks | SIEM / Syslog / Webhooks |
| **Support SLA** | Community | Standard (48h) | Priority (8h) | 24/7 Dedicated (1h) |

---

## 6. Competitive Advantage Matrix

| Capability | PhishGuardAI | Google Safe Browsing | VirusTotal API | Traditional Antivirus |
| :--- | :---: | :---: | :---: | :---: |
| **Zero-Day ML Inference** | ✅ (30-Feature GBDT) | Heuristic / Feed-based | Multi-engine aggregator | Signature-heavy |
| **Real-Time Domain Age Telemetry** | ✅ (< 14 day penalty) | Partial | Via third-party feeds | ❌ |
| **Headless DOM & Password Audit** | ✅ (Tier 3 Sandbox) | Internal only | Paid enterprise tier | ❌ |
| **Developer API Latency** | **< 80 ms** | Variable | Slow (2–10s) | N/A |
| **Self-Hostable / Hybrid Option** | ✅ (Docker available) | ❌ | ❌ | ❌ |
| **Commercial Terms of Service** | Developer-friendly | Strict terms | Expensive enterprise tier | Per-endpoint licensing |

---

## 7. Security, Privacy & Compliance Specifications

* **Data Minimization:** Scan requests can be processed ephemerally with zero URL persistence upon customer request (`"store_logs": false`).
* **Encryption Standards:** TLS 1.3 in transit; AES-256 for all at-rest scan metadata and database storage.
* **API Security:** All API keys are cryptographically hashed using SHA-256 before storage; raw keys are displayed only once upon generation.
* **Legal Disclaimer & Safe Harbor:** All responses contain clear probabilistic indicators and security disclaimers ensuring legal protection against adversarial zero-day evasions.

