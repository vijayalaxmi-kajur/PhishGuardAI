# @phishguard/sdk

Official Node.js & TypeScript client for the **PhishGuardAI Threat Intelligence & Phishing Detection API**.

Protect your Node.js backends, chat platforms, webhooks, and SaaS applications against zero-day phishing, typosquatting, and credential harvesting in real-time.

## Features
- **Zero Dependencies**: Built on native Fetch API (Node 18+).
- **TypeScript Support**: Full typing declarations out-of-the-box (`index.d.ts`).
- **High-Throughput Batch Scanning**: Built-in concurrency control.
- **Enterprise Ready**: Full support for API keys, rate limits, and multi-tenant telemetry.

## Installation

```bash
npm install @phishguard/sdk
```

## Quickstart

```javascript
const { PhishGuardClient } = require("@phishguard/sdk");

const client = new PhishGuardClient({
  apiKey: "pg_live_xxxxxxxxxxxxxxxx",
  baseUrl: "http://127.0.0.1:5000" // or your deployed cloud endpoint
});

async function main() {
  // 1. Quick boolean safety check
  const isThreat = await client.isPhishing("http://paypal-security-verification.xyz");
  if (isThreat) {
    console.warn("🚨 Dangerous link blocked!");
  }

  // 2. Comprehensive deep scan
  const result = await client.scan("https://google.com");
  console.log("Verdict:", result.verdict);
  console.log("Risk Score:", result.phishing_probability);
  console.log("Domain Age:", result.structural_indicators?.domain_age_days);

  // 3. Batch scan with concurrency
  const links = [
    "https://github.com",
    "http://update-chase-banking-security.tk",
    "https://stripe.com"
  ];
  const results = await client.batchScan(links, { concurrency: 3 });
  results.forEach(r => console.log(r.url, "->", r.verdict));
}

main();
```

## Error Handling

```javascript
const { PhishGuardClient, AuthenticationError, RateLimitError } = require("@phishguard/sdk");

const client = new PhishGuardClient({ apiKey: "bad_key" });

try {
  await client.scan("https://example.com");
} catch (err) {
  if (err instanceof AuthenticationError) {
    console.error("Invalid API Key.");
  } else if (err instanceof RateLimitError) {
    console.error("Rate limit exceeded.");
  } else {
    console.error("API error:", err.message);
  }
}
```

## License
MIT

