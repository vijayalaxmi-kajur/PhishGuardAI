# PhishGuardAI Browser Security Extension (Manifest V3)

Real-time zero-day phishing protection for Chromium browsers (Google Chrome, Microsoft Edge, Brave, Opera, Arc).

## Features
- **Real-Time Pre-Navigation Interception**: Inspects outgoing navigations (`webNavigation.onBeforeNavigate`) and blocks confirmed phishing links before network assets load.
- **Red Interstitial Warning Screen**: Displays high-risk detection signals and domain telemetry, warning the user away from credential theft or combosquatting sites.
- **Dynamic Risk Badge**: Color-coded toolbar badge (Green `OK`, Yellow `?`, Red `!`) indicating active tab safety.
- **In-Memory & Storage Cache**: Sub-millisecond lookups for frequently visited URLs to minimize latency.
- **Configurable API Endpoint**: Seamlessly connects to your self-hosted PhishGuardAI instance or cloud enterprise SaaS backend with custom API keys.

## Installation Instructions (Developer Mode)

1. Open your Chromium browser and navigate to:
   - **Chrome**: `chrome://extensions`
   - **Edge**: `edge://extensions`
   - **Brave**: `brave://extensions`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **Load unpacked**.
4. Select the `extension/` folder inside this repository:
   ```
   c:\Users\yalla\OneDrive\Desktop\PhishGuardAI\extension
   ```
5. Pin the PhishGuardAI shield icon to your toolbar.
6. Click the extension icon to view the active tab's security score or configure your PhishGuard API key.

