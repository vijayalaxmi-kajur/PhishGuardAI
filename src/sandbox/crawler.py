"""PhishGuardAI - Tier 3 Deep Sandbox & DOM Crawler Orchestrator

Coordinates headless crawling, DOM syntax parsing, credential form inspection,
and visual perceptual matching for suspicious or ambiguous URLs.
"""

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import requests

from src.sandbox.dom_analyzer import DOMAnalyzer, DOMAnalysisResult
from src.sandbox.visual_analyzer import VisualBrandAnalyzer, VisualAnalysisResult


@dataclass
class SandboxReport:
    """Consolidated assessment report from Tier 3 deep sandboxing."""
    url: str
    registered_domain: str
    execution_mode: str
    dom_result: DOMAnalysisResult
    visual_result: Optional[VisualAnalysisResult] = None
    is_phishing_confirmed: bool = False
    is_suspicious: bool = False
    escalated_risk_level: Optional[str] = None
    explanations: List[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "registered_domain": self.registered_domain,
            "execution_mode": self.execution_mode,
            "dom_analysis": self.dom_result.to_dict(),
            "visual_analysis": self.visual_result.to_dict() if self.visual_result else None,
            "is_phishing_confirmed": self.is_phishing_confirmed,
            "is_suspicious": self.is_suspicious,
            "escalated_risk_level": self.escalated_risk_level,
            "explanations": self.explanations,
            "latency_ms": self.latency_ms,
        }


class DeepSandboxCrawler:
    """Orchestrates deep inspection of HTML DOM and visual elements."""

    DEFAULT_TIMEOUT_SEC: float = 3.5
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 PhishGuardAI/2.0"

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SEC,
        session: Optional[requests.Session] = None,
        mock_driver: Optional[Any] = None,
    ) -> None:
        """Initialize crawler.
        
        Args:
            timeout: Maximum network request timeout in seconds.
            session: Optional custom requests.Session.
            mock_driver: Optional callable(url) -> Tuple[html_str, Optional[bytes_screenshot]] for testing.
        """
        self._timeout = timeout
        self._session = session or requests.Session()
        self._mock_driver = mock_driver
        self.dom_analyzer = DOMAnalyzer()
        self.visual_analyzer = VisualBrandAnalyzer()

    def inspect_url(
        self,
        url: str,
        direct_html: Optional[str] = None,
        screenshot_bytes: Optional[bytes] = None,
    ) -> SandboxReport:
        """Execute deep sandbox inspection on target URL.
        
        Args:
            url: Target URL string.
            direct_html: Optional direct HTML string to bypass network fetching.
            screenshot_bytes: Optional raw screenshot bytes for visual hash matching.
            
        Returns:
            SandboxReport with synthesized findings.
        """
        start_time = time.time()
        reg_domain = self.dom_analyzer.extract_registered_domain(url)
        html_content = direct_html or ""
        exec_mode = "direct_input" if direct_html else "network_probe"

        # 1. Acquire HTML & Screenshot
        if not html_content:
            if self._mock_driver is not None:
                html_content, screenshot_bytes = self._mock_driver(url)
                exec_mode = "mock_driver"
            else:
                try:
                    headers = {"User-Agent": self.USER_AGENT}
                    resp = self._session.get(url, headers=headers, timeout=self._timeout, verify=False)
                    html_content = resp.text
                    exec_mode = "http_stream"
                except Exception as e:
                    # Graceful degradation if page is unreachable
                    latency = round((time.time() - start_time) * 1000.0, 2)
                    return SandboxReport(
                        url=url,
                        registered_domain=reg_domain,
                        execution_mode="network_error",
                        dom_result=DOMAnalysisResult(),
                        explanations=[f"Sandbox network probe could not reach host: {str(e)[:80]}"],
                        latency_ms=latency,
                    )

        # 2. Run DOM Analysis
        dom_res = self.dom_analyzer.analyze_html(html_content, current_url=url)

        # 3. Run Visual Analysis if screenshot is provided
        visual_res: Optional[VisualAnalysisResult] = None
        if screenshot_bytes is not None:
            visual_res = self.visual_analyzer.analyze_screenshot(screenshot_bytes, registered_domain=reg_domain)

        # 4. Synthesize Evidence and Escalations
        explanations: List[str] = list(dom_res.detected_threats)
        is_confirmed = False
        is_suspicious = False
        escalated_risk = None

        # Critical Escalation 1: Brand Impersonation Mismatch
        if dom_res.has_brand_mismatch:
            is_confirmed = True
            escalated_risk = "CRITICAL"
            explanations.append(
                f"Tier 3 Sandbox: High-confidence brand impersonation confirmed. "
                f"Page claims to be '{dom_res.impersonated_brand}' but is served from '{reg_domain}'."
            )

        # Critical Escalation 2: Password Exfiltration Mismatch or Webhook
        if dom_res.has_webhook_exfiltration:
            is_confirmed = True
            escalated_risk = "CRITICAL"
            explanations.append("Tier 3 Sandbox: Form credentials post directly to external exfiltration channels.")

        if dom_res.has_password_input and dom_res.has_external_form_action:
            is_confirmed = True
            escalated_risk = "CRITICAL"
            explanations.append("Tier 3 Sandbox: Password input field submits credentials to an untrusted external domain.")

        # Visual Impersonation Escalation
        if visual_res and visual_res.has_visual_impersonation:
            is_confirmed = True
            escalated_risk = "CRITICAL"
            explanations.append(
                f"Tier 3 Visual Sandbox: Page layout visual perceptual hash matches '{visual_res.impersonated_brand}' "
                f"portal on an unauthorized domain."
            )

        # Moderate Escalations (Hidden iframes, obfuscated code, or sensitive inputs on unbranded pages)
        if not is_confirmed:
            if dom_res.has_hidden_iframe or dom_res.has_obfuscated_scripts or dom_res.has_sensitive_input:
                is_suspicious = True
                escalated_risk = "HIGH"
                explanations.append("Tier 3 Sandbox: Suspicious DOM cloaking, obfuscated scripts, or sensitive inputs detected.")

        latency = round((time.time() - start_time) * 1000.0, 2)

        return SandboxReport(
            url=url,
            registered_domain=reg_domain,
            execution_mode=exec_mode,
            dom_result=dom_res,
            visual_result=visual_res,
            is_phishing_confirmed=is_confirmed,
            is_suspicious=is_suspicious,
            escalated_risk_level=escalated_risk,
            explanations=explanations,
            latency_ms=latency,
        )

