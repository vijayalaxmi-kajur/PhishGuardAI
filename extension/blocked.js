// Parse query parameters
const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url") || "Unknown Destination";
const verdict = params.get("verdict") || "HIGH RISK";
const risk = params.get("risk") || "high";
const reason = params.get("reason") || "Suspicious or malicious activity detected.";

document.getElementById("targetUrl").textContent = targetUrl;
document.getElementById("riskBadge").textContent = `${verdict.toUpperCase()} (${risk.toUpperCase()})`;
document.getElementById("reasonText").textContent = reason;

// Back to Safety button
document.getElementById("btnBack").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "about:blank";
  }
});

// Bypass button
document.getElementById("btnBypass").addEventListener("click", () => {
  if (confirm("WARNING: Entering passwords, personal details, or credit cards on this site can result in identity theft. Proceed?")) {
    window.location.href = targetUrl;
  }
});

