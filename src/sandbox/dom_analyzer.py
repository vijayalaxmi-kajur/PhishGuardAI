"""PhishGuardAI - DOM & Credential Harvesting Analyzer

Performs deep syntactic and semantic inspection of HTML document trees:
1. Credential harvesting inputs (password fields, CVV, credit card numbers, SSN, 2FA tokens).
2. Form action destination mismatch (exfiltration to third-party domains, raw IPs, or webhooks).
3. Hidden or cloaked iframe redirections (zero width/height, hidden styles).
4. Obfuscated script signatures (eval, atob decoding, unescape, excessive hex encoding).
5. Brand identity mismatch (login page claims to be Microsoft/PayPal/Google on an unrelated domain).
"""

import re
import html
import urllib.parse
from html.parser import HTMLParser
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
import tldextract

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


@dataclass
class DOMAnalysisResult:
    """Detailed structural findings from DOM and credential harvesting inspection."""
    has_password_input: bool = False
    has_sensitive_input: bool = False
    sensitive_field_names: List[str] = field(default_factory=list)
    has_external_form_action: bool = False
    external_form_actions: List[str] = field(default_factory=list)
    has_webhook_exfiltration: bool = False
    has_hidden_iframe: bool = False
    hidden_iframe_sources: List[str] = field(default_factory=list)
    has_obfuscated_scripts: bool = False
    obfuscation_indicators: List[str] = field(default_factory=list)
    has_brand_mismatch: bool = False
    impersonated_brand: Optional[str] = None
    page_title: Optional[str] = None
    total_forms: int = 0
    total_inputs: int = 0
    total_scripts: int = 0
    risk_score: float = 0.0
    detected_threats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dictionary."""
        return {
            "has_password_input": self.has_password_input,
            "has_sensitive_input": self.has_sensitive_input,
            "sensitive_field_names": self.sensitive_field_names,
            "has_external_form_action": self.has_external_form_action,
            "external_form_actions": self.external_form_actions,
            "has_webhook_exfiltration": self.has_webhook_exfiltration,
            "has_hidden_iframe": self.has_hidden_iframe,
            "hidden_iframe_sources": self.hidden_iframe_sources,
            "has_obfuscated_scripts": self.has_obfuscated_scripts,
            "obfuscation_indicators": self.obfuscation_indicators,
            "has_brand_mismatch": self.has_brand_mismatch,
            "impersonated_brand": self.impersonated_brand,
            "page_title": self.page_title,
            "total_forms": self.total_forms,
            "total_inputs": self.total_inputs,
            "total_scripts": self.total_scripts,
            "risk_score": round(self.risk_score, 4),
            "detected_threats": self.detected_threats,
        }


class _HTMLDOMParser(HTMLParser):
    """Event-driven streaming HTML parser extracting inputs, forms, and scripts."""

    def __init__(self, page_domain: str) -> None:
        super().__init__()
        self.page_domain = page_domain.lower()
        self.in_title = False
        self.in_script = False
        self.title_parts: List[str] = []
        self.script_bodies: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.current_form: Optional[Dict[str, Any]] = None
        self.inputs: List[Dict[str, str]] = []
        self.iframes: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower == "title":
            self.in_title = True
        elif tag_lower == "script":
            self.in_script = True
        elif tag_lower == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self.current_form)
        elif tag_lower == "input":
            input_info = {
                "type": attr_dict.get("type", "text").lower(),
                "name": attr_dict.get("name", "").lower(),
                "id": attr_dict.get("id", "").lower(),
                "placeholder": attr_dict.get("placeholder", "").lower(),
            }
            self.inputs.append(input_info)
            if self.current_form is not None:
                self.current_form["inputs"].append(input_info)
        elif tag_lower == "iframe":
            self.iframes.append({
                "src": attr_dict.get("src", ""),
                "style": attr_dict.get("style", "").lower(),
                "width": attr_dict.get("width", ""),
                "height": attr_dict.get("height", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self.in_title = False
        elif tag_lower == "script":
            self.in_script = False
        elif tag_lower == "form":
            self.current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        elif self.in_script:
            self.script_bodies.append(data)


class DOMAnalyzer:
    """Analyzes HTML body content for phishing signatures, credentials, and evasion tactics."""

    # High-value brands commonly targeted in credential harvesting
    PROTECTED_BRANDS: Dict[str, List[str]] = {
        "microsoft": ["microsoft", "office365", "outlook", "live.com", "onedrive", "sharepoint", "azure"],
        "google": ["google", "gmail", "google drive", "google docs", "youtube"],
        "apple": ["apple", "icloud", "apple id", "itunes"],
        "paypal": ["paypal"],
        "amazon": ["amazon", "prime video", "aws"],
        "chase": ["chase", "jpmorgan"],
        "bank of america": ["bank of america", "bofa"],
        "wells fargo": ["wells fargo"],
        "netflix": ["netflix"],
        "facebook": ["facebook", "meta"],
        "instagram": ["instagram"],
        "metamask": ["metamask", "crypto wallet"],
        "steam": ["steam", "valve"],
        "dropbox": ["dropbox"],
        "adobe": ["adobe", "creative cloud"],
    }

    # Legitimate root domains owned and operated by protected brands
    LEGITIMATE_BRAND_DOMAINS: Dict[str, Set[str]] = {
        "microsoft": {"microsoft.com", "office.com", "live.com", "azure.com", "msn.com", "windows.net", "sharepoint.com", "office365.com", "microsoftonline.com"},
        "google": {"google.com", "youtube.com", "gmail.com", "google.co.uk", "google.co.in", "google.ca", "google.de", "google.fr", "google.com.br", "withgoogle.com", "1e100.net"},
        "apple": {"apple.com", "icloud.com"},
        "paypal": {"paypal.com", "paypal.me"},
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.jp", "aws.amazon.com", "media-amazon.com"},
        "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
        "bank of america": {"bankofamerica.com", "bofa.com"},
        "wells fargo": {"wellsfargo.com"},
        "netflix": {"netflix.com"},
        "facebook": {"facebook.com", "fb.com", "meta.com"},
        "instagram": {"instagram.com"},
        "metamask": {"metamask.io"},
        "steam": {"steampowered.com", "steamcommunity.com"},
        "dropbox": {"dropbox.com"},
        "adobe": {"adobe.com"},
    }

    # Sensitive input keywords
    SENSITIVE_INPUT_KEYWORDS: Set[str] = {
        "card_number", "cardnumber", "cc_num", "creditcard", "cvv", "cvc", "security_code",
        "ssn", "social_security", "pin", "otp", "2fa", "two_factor", "token", "passcode",
        "secret", "private_key", "seed_phrase", "recovery_phrase",
    }

    # Known data-exfiltration webhooks
    EXFILTRATION_PATTERNS = [
        re.compile(r"api\.telegram\.org/bot", re.IGNORECASE),
        re.compile(r"discord\.com/api/webhooks", re.IGNORECASE),
        re.compile(r"^mailto:", re.IGNORECASE),
    ]

    def extract_registered_domain(self, url_or_host: str) -> str:
        """Extract root registered domain (e.g. 'paypal.com')."""
        target = str(url_or_host or "").strip()
        if not target:
            return ""
        if "://" in target or target.startswith("//"):
            try:
                parsed = urllib.parse.urlsplit(target)
                target = parsed.netloc.split(":")[0]
            except Exception:
                pass
        else:
            target = target.split("/")[0].split(":")[0]

        ext = _TLD_EXTRACTOR(target)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return target.lower()

    def analyze_html(self, html_content: str, current_url: str) -> DOMAnalysisResult:
        """Execute full DOM inspection on the provided HTML source.
        
        Args:
            html_content: Raw HTML text of the page.
            current_url: The URL hosting this HTML.
            
        Returns:
            DOMAnalysisResult with structured findings and risk scoring.
        """
        page_domain = self.extract_registered_domain(current_url)
        parser = _HTMLDOMParser(page_domain=page_domain)

        try:
            parser.feed(html_content or "")
        except Exception:
            pass

        page_title = " ".join(parser.title_parts).strip()
        page_title = html.unescape(page_title) if page_title else None

        result = DOMAnalysisResult(
            page_title=page_title,
            total_forms=len(parser.forms),
            total_inputs=len(parser.inputs),
            total_scripts=len(parser.script_bodies),
        )

        threats: List[str] = []
        score: float = 0.0

        # 1. Password & Sensitive Input Detection
        for inp in parser.inputs:
            itype = inp.get("type", "")
            iname = inp.get("name", "")
            iid = inp.get("id", "")
            iplace = inp.get("placeholder", "")

            if itype == "password":
                result.has_password_input = True
                score += 0.25

            field_identifiers = f"{iname} {iid} {iplace}"
            for kw in self.SENSITIVE_INPUT_KEYWORDS:
                if kw in field_identifiers:
                    result.has_sensitive_input = True
                    result.sensitive_field_names.append(kw)
                    score += 0.35
                    break

        if result.has_password_input:
            threats.append("Live password input field detected in DOM.")
        if result.has_sensitive_input:
            threats.append(f"Sensitive financial/MFA inputs detected: {', '.join(set(result.sensitive_field_names))}.")

        # 2. Form Action Destination Audit
        for form in parser.forms:
            action = form.get("action", "").strip()
            if not action or action.startswith("#") or action.startswith("javascript:"):
                continue

            # Check webhook / mailto exfiltration
            if any(pattern.search(action) for pattern in self.EXFILTRATION_PATTERNS):
                result.has_webhook_exfiltration = True
                threats.append(f"Form exfiltration webhook/mailto detected: {action[:60]}")
                score += 0.60

            # Check external domain / IP destination
            if "://" in action or action.startswith("//"):
                action_domain = self.extract_registered_domain(action)
                if action_domain and action_domain != page_domain:
                    result.has_external_form_action = True
                    result.external_form_actions.append(action)
                    # If form contains a password and submits off-domain, that is a severe threat!
                    form_has_pw = any(i.get("type") == "password" for i in form.get("inputs", []))
                    if form_has_pw:
                        threats.append(f"CRITICAL: Form with password input posts credentials to external domain '{action_domain}'.")
                        score += 0.70
                    else:
                        threats.append(f"Form action posts data to external domain '{action_domain}'.")
                        score += 0.20

        # 3. Hidden / Cloaked Iframes
        for ifr in parser.iframes:
            style = ifr.get("style", "")
            w = ifr.get("width", "")
            h = ifr.get("height", "")
            is_zero_size = (w in {"0", "0px", "0%", "1", "1px"} or h in {"0", "0px", "0%", "1", "1px"})
            is_hidden_style = any(h in style for h in ["display:none", "display: none", "visibility:hidden", "visibility: hidden", "opacity:0", "opacity: 0"])

            if is_zero_size or is_hidden_style:
                result.has_hidden_iframe = True
                src = ifr.get("src", "unspecified")
                result.hidden_iframe_sources.append(src)
                threats.append(f"Hidden or zero-pixel iframe detected (src: '{src[:60]}').")
                score += 0.40

        # 4. Obfuscated Script Analysis
        full_script_text = " ".join(parser.script_bodies)
        obfuscation_patterns = [
            (r"\beval\s*\(", "eval() dynamic execution"),
            (r"\batob\s*\(", "atob() base64 decoder"),
            (r"\bunescape\s*\(", "unescape() decoder"),
            (r"String\.fromCharCode\(", "String.fromCharCode() concatenation"),
            (r"(?:\\x[0-9a-fA-F]{2}){4,}", "Heavy hex-escaped bytecode string"),
        ]
        for pattern_str, label in obfuscation_patterns:
            if re.search(pattern_str, full_script_text):
                result.has_obfuscated_scripts = True
                result.obfuscation_indicators.append(label)
                score += 0.25

        if result.has_obfuscated_scripts:
            threats.append(f"Obfuscated client-side JavaScript signatures: {', '.join(result.obfuscation_indicators)}.")

        # 5. Brand Identity Mismatch Detection
        title_text = (page_title or "").lower()
        combined_text = f"{title_text} {html_content[:4096].lower()}"

        for brand, identifiers in self.PROTECTED_BRANDS.items():
            # Check if page prominently claims to be a brand
            brand_in_title = any(ident in title_text for ident in identifiers)
            
            # Check against authorized brand domains
            legit_domains = self.LEGITIMATE_BRAND_DOMAINS.get(brand, set())
            is_legitimate_owner = (page_domain in legit_domains) or any(page_domain.endswith(f".{d}") for d in legit_domains)

            if brand_in_title and not is_legitimate_owner:
                # Brand mismatch! The page claims to be Microsoft/PayPal/Google, but domain is not an authorized domain!
                result.has_brand_mismatch = True
                result.impersonated_brand = brand.capitalize()
                threats.append(
                    f"CRITICAL: Brand Impersonation Mismatch. Page title/header claims to be '{brand.capitalize()}', "
                    f"but registered domain is '{page_domain}'."
                )
                score += 0.75
                break

        result.risk_score = min(1.0, score)
        result.detected_threats = threats
        return result
