/**
 * PhishGuardAI - Manifest V3 Background Service Worker
 * Intercepts real-time navigations, queries PhishGuardAI Threat API, and blocks malicious sites.
 */

const DEFAULT_API_URL = "http://127.0.0.1:5000/api/v1/scan";
const CACHE_TTL_MS = 3600 * 1000; // 1 hour

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.sync.get(["apiUrl", "apiKey", "enabled"]);
  if (!current.apiUrl) {
    await chrome.storage.sync.set({
      apiUrl: DEFAULT_API_URL,
      apiKey: "", // Optional default; falls back to free local scanning
      enabled: true,
      blockHighRisk: true,
    });
  }
});

/**
 * Intercept outgoing web navigation before the page loads.
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level navigation frames
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    return;
  }

  // Check if protection is enabled
  const settings = await chrome.storage.sync.get(["enabled", "apiUrl", "apiKey", "blockHighRisk"]);
  if (settings.enabled === false) return;

  // Check local cache
  const cacheKey = `cache_${url}`;
  const cachedData = await chrome.storage.local.get(cacheKey);
  const now = Date.now();

  let scanResult = null;
  if (cachedData[cacheKey] && (now - cachedData[cacheKey].timestamp < CACHE_TTL_MS)) {
    scanResult = cachedData[cacheKey].data;
  } else {
    // Perform live scan
    try {
      scanResult = await queryPhishGuardAPI(url, settings.apiUrl || DEFAULT_API_URL, settings.apiKey);
      // Cache the result
      if (scanResult && scanResult.success) {
        await chrome.storage.local.set({
          [cacheKey]: { data: scanResult, timestamp: now }
        });
      }
    } catch (err) {
      console.warn("[PhishGuardAI] Scan query error:", err);
      return;
    }
  }

  if (!scanResult || !scanResult.success) return;

  const verdict = (scanResult.verdict || "").toLowerCase();
  const risk = (scanResult.risk_level || "").toLowerCase();
  const isBlocked = (
    verdict === "phishing" ||
    verdict === "confirmed_malicious" ||
    risk === "critical" ||
    (settings.blockHighRisk && risk === "high")
  );

  if (isBlocked) {
    // Update extension badge
    chrome.action.setBadgeText({ tabId: details.tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#ef4444" });

    // Redirect to PhishGuardAI blocked interstitial warning page
    const reason = (scanResult.explanation && scanResult.explanation[0]) ? scanResult.explanation[0] : "Verified phishing or credential harvesting attempt.";
    const blockPageUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(url)}&verdict=${encodeURIComponent(scanResult.standardized_verdict || "HIGH RISK")}&risk=${encodeURIComponent(risk)}&reason=${encodeURIComponent(reason)}`
    );

    await chrome.tabs.update(details.tabId, { url: blockPageUrl });
  } else if (verdict === "legitimate" || verdict === "no_known_threat_detected") {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#10b981" });
  } else {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#f59e0b" });
  }
});

/**
 * Query PhishGuardAI API.
 */
async function queryPhishGuardAPI(targetUrl, apiUrl, apiKey) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  const response = await fetch(apiUrl, {
    method: "POST",
    headers: headers,
    body: JSON.stringify({ url: targetUrl, check_presence: false }),
  });

  if (!response.ok) {
    // If v1 returns 401 (API key required), fallback to standard /api/scan endpoint
    if (response.status === 401 && apiUrl.includes("/api/v1/scan")) {
      const fallbackUrl = apiUrl.replace("/api/v1/scan", "/api/scan");
      const fallbackResp = await fetch(fallbackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl, check_presence: false }),
      });
      return await fallbackResp.json();
    }
    throw new Error(`API returned HTTP ${response.status}`);
  }

  return await response.json();
}

/**
 * Handle manual scan message from popup.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scan_active_tab") {
    (async () => {
      const settings = await chrome.storage.sync.get(["apiUrl", "apiKey"]);
      try {
        const result = await queryPhishGuardAPI(message.url, settings.apiUrl || DEFAULT_API_URL, settings.apiKey);
        sendResponse({ success: true, result: result });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true; // Keep message channel open for async response
  }
});

