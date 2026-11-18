# PhishGuardAI — Commercial Product Development Roadmap (TODO)

This document tracks the engineering, architectural, and business tasks required to transform PhishGuardAI from an ML prototype into a commercial-grade, multi-tenant cybersecurity SaaS and browser security product.

---

## 🎯 High-Level Milestones

- [x] **Milestone 1:** Detection Engine Hardening (Domain Telemetry & Live Threat Feeds)
- [x] **Milestone 2:** Deep Inspection Pipeline (Headless Browser & DOM Crawler)
- [x] **Milestone 3:** Enterprise SaaS Architecture (PostgreSQL, Redis, API Key Auth, Rate Limiting)
- [x] **Milestone 4:** Client Delivery (Chrome/Edge Extension & Developer SDKs)
- [x] **Milestone 5:** Monetization, Compliance & Go-To-Market (Stripe, Legal, Docs, Launch)

---

## Phase 1: Detection Engine Hardening (P0 — Critical) [COMPLETED]
*Goal: Eliminate false negatives on zero-day attacks and reduce lexical false positives on legitimate complex URLs.*

- [x] **1.1 Real-Time Domain Age & WHOIS Telemetry**
  - [x] Implemented `src/threat_intelligence/whois_checker.py` using RDAP protocol.
  - [x] Automated flags for newly registered domains (`< 14 days` high-risk anomaly, `< 30 days` recent).
  - [x] In-memory TTL cache (24 hours) with graceful degradation on network timeouts.
- [x] **1.2 Live Threat Intelligence Feed Integration**
  - [x] URLhaus integration active in `src/threat_intelligence/urlhaus.py`.
  - [x] Implemented `src/threat_intelligence/openphish.py` with automatic 30-minute sync.
  - [x] PhishTank integration active in `src/threat_intelligence/phishtank.py`.
  - [x] Multi-provider aggregation in `src/threat_intelligence/manager.py`.
- [x] **1.3 DNS & SSL Certificate Verification**
  - [x] Verified DNS A/AAAA resolution & NXDOMAIN detection in `src/decision_engine/website_checker.py`.
  - [x] Live SSL handshake verification and status extraction.
- [x] **1.4 Decision Engine Calibration & Whitelisting**
  - [x] Implemented `src/threat_intelligence/whitelist.py` with verified platform registry (Google, YouTube, Microsoft, AWS, GitHub, etc.).
  - [x] Multi-tenant user content partitioning (e.g. `forms.gle`, `firebaseapp.com`, `workers.dev` guarded against blanket whitelisting).
  - [x] Updated `LayeredDecisionEngine` with weighted penalties combining domain age, threat feeds, and whitelist bypass for complex benign URLs.
  - [x] Comprehensive test suite (57 tests passing in `tests/test_domain_age.py`, `tests/test_whitelist.py`, `tests/test_openphish.py`, `tests/test_phase1_integration.py`).

---

## Phase 2: Deep Inspection & Live Sandboxing (P1 — High) [COMPLETED]
*Goal: Catch zero-day phishing hosted on legitimate cloud platforms (Google Docs, Cloudflare Workers, Notion, etc.).*

- [x] **2.1 Headless Browser & Deep Crawler Orchestrator**
  - [x] Implemented `src/sandbox/crawler.py` (`DeepSandboxCrawler`) with fast streaming and headless driver support.
  - [x] Triggered selectively on `SUSPICIOUS`, `INCONCLUSIVE`, or multi-tenant hosting platforms to balance latency and security.
- [x] **2.2 DOM & Credential Harvesting Analysis**
  - [x] Implemented `src/sandbox/dom_analyzer.py` parsing streaming HTML with zero external runtime dependencies.
  - [x] Password inputs, credit card numbers, CVV, SSN, and 2FA tokens detected in DOM.
  - [x] Form action destination mismatch checks (detects credential theft posted to external untrusted domains, raw IPs, Discord/Telegram webhooks, or mailto).
  - [x] Cloaked and zero-pixel iframe redirect inspection.
  - [x] Client-side obfuscated JavaScript detection (`eval`, `atob`, `unescape`, hex bytecode strings).
  - [x] Combosquatting-resistant Brand Identity Mismatch detection comparing declared brand identity against authoritative registry.
- [x] **2.3 Brand Impersonation & Logo Matching (Computer Vision)**
  - [x] Implemented `src/sandbox/visual_analyzer.py` with perceptual difference hashing (dHash) via Pillow.
  - [x] Visual comparison against reference brand login fingerprints (Microsoft, PayPal, Google, Apple).
- [x] **2.4 Layered Decision Engine Integration**
  - [x] Integrated Tier 3 Deep Sandboxing into `LayeredDecisionEngine` and `app.py`.
  - [x] 93 regression tests passing across all test suites (0 failures, 0 errors).

---

## Phase 3: Scalable SaaS Cloud Architecture (P0 — Critical) [COMPLETED]
*Goal: Move from a single-machine local Flask app to an enterprise multi-tenant API.*

- [x] **3.1 Backend Architecture Modernization**
  - [x] Implemented multi-tenant SaaS REST endpoints (`/api/v1/auth`, `/api/v1/keys`, `/api/v1/scan`, `/api/v1/user/usage`).
  - [x] Created `Dockerfile` with multi-stage build, non-root user, and Gunicorn WSGI runtime.
  - [x] Created `docker-compose.yml` orchestrating App, PostgreSQL 16, and Redis 7.
  - [x] Created `wsgi.py` production entry point.
- [x] **3.2 Database Migration & Schema Design**
  - [x] Implemented `src/saas/database.py` with multi-tenant relational schema: `users`, `api_keys`, `tenant_scan_logs`, and `audit_logs`.
  - [x] Seamless support for SQLite (local/dev) and PostgreSQL (cloud production via `DATABASE_URL`).
- [x] **3.3 High-Performance Caching & Rate Limiting**
  - [x] Implemented `src/saas/cache.py` with thread-safe LRU in-memory cache and Redis connectivity (`< 1ms` cached scan lookups).
  - [x] Implemented sliding window token bucket rate limiter tracking requests per minute per key and enforcing monthly quotas.
- [x] **3.4 Multi-Tenant Authentication & API Key Management**
  - [x] Implemented `src/saas/auth.py` with PBKDF2-HMAC-SHA256 password hashing (100,000 iterations).
  - [x] Cryptographic API key generation (`pg_live_...` / `pg_test_...`) with SHA-256 database hashing and prefix indexing.
  - [x] Implemented cryptographically signed bearer tokens (HMAC-SHA256) for session management.
  - [x] 103 regression tests passing across all test suites (0 failures, 0 errors).

---

## Phase 4: Client Products & Delivery Channels (P1 — High) [COMPLETED]
*Goal: Give end-users and developers direct access to PhishGuardAI protection.*

- [x] **4.1 Manifest V3 Browser Extension (Chrome, Edge, Brave)**
  - [x] Built background service worker (`extension/service-worker.js`) intercepting `webNavigation.onBeforeNavigate`.
  - [x] Sub-millisecond local in-memory and `chrome.storage.local` caching.
  - [x] Red interstitial security warning screen (`extension/blocked.html` & `extension/blocked.js`) with threat score, reasons, and safe bypass.
  - [x] Extension popup UI (`extension/popup.html` & `extension/popup.js`) displaying active tab security metrics, domain age, SSL status, and API key configuration.
  - [x] Complete developer installation guide in `extension/README.md`.
- [x] **4.2 Developer SDKs & Integrations**
  - [x] Official Python SDK (`sdk/python`) with zero external runtime dependencies (`urllib`), concurrent batch scanning, and full test suite (`tests/test_sdk_python.py`).
  - [x] Official Node.js / TypeScript SDK (`sdk/node`) with native Fetch API, TypeScript definitions (`index.d.ts`), and unit test suite.
  - [x] Pre-built Discord phishing bot (`sdk/webhooks/discord_phish_guard.py`) and Slack link auditor (`sdk/webhooks/slack_link_auditor.py`).
- [x] **4.3 Interactive Customer Dashboard**
  - [x] Modernized web dashboard (`templates/index.html`, `static/css/style.css`, `static/js/app.js`) with responsive navigation tabs.
  - [x] Developer API Keys management portal with live cryptographic key generator (`pg_live_...`), prefix masking, and key revocation.
  - [x] Interactive copy-paste SDK code generators for Python, Node.js, and cURL.
  - [x] Real-time quota and monthly scan consumption progress meter.
  - [x] 110 tests passing across all test suites (0 failures, 0 errors).

---

## Phase 5: Monetization, Security & Launch (P0 — Critical) [COMPLETED]
*Goal: Turn technical capabilities into paying recurring revenue.*

- [x] **5.1 Razorpay Payment Gateway & Subscription Integration (Code Ready — Toggled OFF in UI)**
  - [x] Implemented `src/saas/billing.py` (`BillingManager` & `RazorpayClient`) supporting native Razorpay orders and Standard Checkout.
  - [x] Supports UPI (Google Pay, PhonePe, Paytm), Netbanking, Credit/Debit cards, and recurring subscriptions.
  - [x] Implemented cryptographic HMAC-SHA256 signature verification for payment completion and webhook lifecycle events (`payment.captured`, `order.paid`, `subscription.cancelled`).
  - [x] *Status:* Payment gates and checkout popups are toggled OFF in the UI per user request; all platform features, detection tiers, and API keys are completely unlocked for unrestricted access. Can be re-enabled instantly on demand.
  - [x] Full unit test coverage in `tests/test_billing.py` (all 6 tests passing).
- [x] **5.2 API Documentation & Developer Portal**
  - [x] Complete OpenAPI 3.0 specification in `static/swagger.json` and endpoint `/api/v1/openapi.json`.
  - [x] Interactive Swagger UI explorer mounted at `/docs` (`templates/swagger.html`).
- [x] **5.3 Legal, Compliance & Cybersecurity Disclaimers**
  - [x] Drafted Terms of Service (`templates/terms.html`, endpoint `/terms`) with limitation of liability and Acceptable Use Policy.
  - [x] Drafted Privacy Policy (`templates/privacy.html`, endpoint `/privacy`) detailing URL privacy scrubbing and GDPR/CCPA disclosures.
- [x] **5.4 Production Deployment & Infrastructure**
  - [x] Automated preflight audit script `scripts/preflight_check.py` validating runtime, model, DBs, and dependencies.
  - [x] Comprehensive cloud deployment manual `DEPLOYMENT.md` covering Render, AWS ECS, DigitalOcean, and Docker Compose.
  - [x] Production environment template `.env.production.example`.
  - [x] Full test suite (116 tests passing cleanly across all modules).

