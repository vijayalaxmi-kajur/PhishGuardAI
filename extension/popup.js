/**
 * PhishGuardAI - Extension Popup Controller
 */

document.addEventListener("DOMContentLoaded", async () => {
  const tabDomain = document.getElementById("tabDomain");
  const valRisk = document.getElementById("valRisk");
  const valAge = document.getElementById("valAge");
  const valSSL = document.getElementById("valSSL");
  const valVerdict = document.getElementById("valVerdict");
  const badgeStatus = document.getElementById("badgeStatus");
  const btnScanNow = document.getElementById("btnScanNow");
  const toggleSettings = document.getElementById("toggleSettings");
  const settingsPanel = document.getElementById("settingsPanel");
  const inputApiKey = document.getElementById("inputApiKey");
  const inputApiUrl = document.getElementById("inputApiUrl");
  const btnSaveSettings = document.getElementById("btnSaveSettings");

  let activeUrl = "";

  // 1. Load saved settings
  if (chrome.storage && chrome.storage.sync) {
    const settings = await chrome.storage.sync.get(["apiUrl", "apiKey"]);
    if (settings.apiUrl) inputApiUrl.value = settings.apiUrl;
    if (settings.apiKey) inputApiKey.value = settings.apiKey;
  }

  // 2. Query active tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0 && tabs[0].url) {
      activeUrl = tabs[0].url;
      try {
        const parsed = new URL(activeUrl);
        tabDomain.textContent = parsed.hostname || activeUrl;
      } catch (_) {
        tabDomain.textContent = activeUrl;
      }

      // Check if this is an internal chrome/extension URL
      if (activeUrl.startsWith("chrome://") || activeUrl.startsWith("chrome-extension://") || activeUrl.startsWith("about:")) {
        tabDomain.textContent = "Browser System Page";
        valVerdict.textContent = "SYSTEM";
        valRisk.textContent = "0.00 (Safe)";
        valAge.textContent = "Internal";
        valSSL.textContent = "N/A";
        badgeStatus.className = "status-badge status-safe";
        badgeStatus.textContent = "SECURE";
        btnScanNow.disabled = true;
        return;
      }

      // Trigger automatic scan on popup open
      performScan(activeUrl);
    } else {
      tabDomain.textContent = "No active web page detected";
      btnScanNow.disabled = true;
    }
  } catch (err) {
    console.error("Tab query error:", err);
    tabDomain.textContent = "Tab access unavailable";
  }

  // 3. Scan Button Click
  btnScanNow.addEventListener("click", () => {
    if (activeUrl) {
      performScan(activeUrl);
    }
  });

  // 4. Toggle Settings Panel
  toggleSettings.addEventListener("click", () => {
    const isVisible = settingsPanel.style.display === "block";
    settingsPanel.style.display = isVisible ? "none" : "block";
  });

  // 5. Save Settings
  btnSaveSettings.addEventListener("click", async () => {
    const newApiUrl = inputApiUrl.value.trim() || "http://127.0.0.1:5000/api/v1/scan";
    const newApiKey = inputApiKey.value.trim();

    await chrome.storage.sync.set({
      apiUrl: newApiUrl,
      apiKey: newApiKey,
    });

    btnSaveSettings.textContent = "Saved ✓";
    setTimeout(() => {
      btnSaveSettings.textContent = "Save Configuration";
      settingsPanel.style.display = "none";
    }, 1200);
  });

  /**
   * Send scan request to background service worker and update UI
   */
  function performScan(url) {
    btnScanNow.disabled = true;
    btnScanNow.textContent = "Scanning Threat Intelligence...";
    badgeStatus.className = "status-badge";
    badgeStatus.textContent = "CHECKING";

    chrome.runtime.sendMessage({ action: "scan_active_tab", url: url }, (response) => {
      btnScanNow.disabled = false;
      btnScanNow.textContent = "Scan Active Page Now";

      if (chrome.runtime.lastError || !response || !response.success) {
        valVerdict.textContent = "Scan Error";
        badgeStatus.className = "status-badge status-warn";
        badgeStatus.textContent = "OFFLINE";
        return;
      }

      const res = response.result;
      updateUIWithResult(res);
    });
  }

  /**
   * Render result metrics in the popup DOM
   */
  function updateUIWithResult(res) {
    const verdict = (res.verdict || res.standardized_verdict || "UNKNOWN").toUpperCase();
    const riskScore = typeof res.risk_score === "number" ? res.risk_score.toFixed(2) : "—";
    const riskLevel = (res.risk_level || "UNKNOWN").toUpperCase();

    valVerdict.textContent = verdict;
    valRisk.textContent = `${riskScore} (${riskLevel})`;

    // Domain age
    if (res.features && res.features.domain_age_days !== undefined) {
      valAge.textContent = `${res.features.domain_age_days} days`;
    } else if (res.domain_age_days !== undefined) {
      valAge.textContent = `${res.domain_age_days} days`;
    } else {
      valAge.textContent = "Verified";
    }

    // SSL status
    if (res.presence && res.presence.ssl_certificate) {
      valSSL.textContent = res.presence.ssl_certificate.status || "Valid";
    } else {
      valSSL.textContent = "Encrypted (HTTPS)";
    }

    // Set badge style
    badgeStatus.className = "status-badge";
    if (verdict.includes("PHISHING") || verdict.includes("MALICIOUS") || riskLevel === "CRITICAL" || riskLevel === "HIGH") {
      badgeStatus.classList.add("status-danger");
      badgeStatus.textContent = "DANGER";
    } else if (verdict.includes("LEGITIMATE") || verdict.includes("NO_KNOWN_THREAT") || riskLevel === "LOW") {
      badgeStatus.classList.add("status-safe");
      badgeStatus.textContent = "SAFE";
    } else {
      badgeStatus.classList.add("status-warn");
      badgeStatus.textContent = "CAUTION";
    }
  }
});

