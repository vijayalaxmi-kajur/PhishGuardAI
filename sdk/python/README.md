# PhishGuardAI Official Python SDK

The official Python client for the **PhishGuardAI Threat Intelligence & Phishing Detection API**.

Protect web applications, chat systems, email pipelines, and enterprise workflows against zero-day phishing, typosquatting, and credential harvesting in real-time.

## Features
- **Zero Runtime Dependencies**: Works out-of-the-box using standard Python `urllib` and `json`.
- **Fast Local & Cloud Scanning**: Sub-millisecond cached URL reputation lookups.
- **Concurrent Batch Processing**: Inspect thousands of URLs simultaneously with built-in thread pooling.
- **Detailed Threat Telemetry**: Access WHOIS domain age, SSL certificate analysis, DOM inspection signals, and confidence metrics.

## Installation

```bash
pip install phishguard
```

Or for local development:
```bash
pip install -e sdk/python
```

## Quickstart

```python
from phishguard import PhishGuardClient

# Initialize with your API key
client = PhishGuardClient(
    api_key="pg_live_xxxxxxxxxxxxxxxx",
    base_url="http://127.0.0.1:5000"  # or your production endpoint
)

# 1. Quick boolean risk check
if client.is_phishing("http://paypal-verification-account.xyz"):
    print("🚨 Threat Detected! Phishing link blocked.")
else:
    print("✅ Domain safe.")

# 2. Detailed URL deep scan
result = client.scan("https://google.com")
print(f"Verdict: {result['verdict']}")
print(f"Risk Score: {result['phishing_probability']}")
print(f"Confidence: {result['confidence_percent']}%")
print(f"Explanation: {result['explanation']}")

# 3. High-throughput batch scan
urls = [
    "https://github.com",
    "http://update-chase-banking-security.tk",
    "https://microsoft.com"
]

results = client.batch_scan(urls, max_workers=5)
for r in results:
    print(r["url"], "->", r.get("verdict"))
```

## Error Handling

```python
from phishguard import PhishGuardClient
from phishguard.exceptions import AuthenticationError, RateLimitError, PhishGuardError

client = PhishGuardClient(api_key="invalid_key")

try:
    client.scan("https://example.com")
except AuthenticationError:
    print("Please check your API key.")
except RateLimitError:
    print("Monthly quota or RPM limit exceeded.")
except PhishGuardError as e:
    print(f"API Error: {e}")
```

## License
MIT License.

