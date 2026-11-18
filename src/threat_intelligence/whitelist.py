"""PhishGuardAI - Verified Domain Whitelist & Multi-Tenant Registry

Provides high-confidence whitelisting for verified enterprise, cloud, and media domains
to eliminate false positives on high-entropy URLs (e.g. YouTube playlist URLs, AWS presigned links).
Carefully partitions direct trusted domains from open multi-tenant hosting providers
(where arbitrary user-generated content or phishing may reside).
"""

import urllib.parse
from dataclasses import dataclass
from typing import Set, Dict, Optional, Tuple, Any
import tldextract

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


@dataclass
class WhitelistResult:
    """Evaluation result from the verified domain whitelist registry."""
    target: str
    registered_domain: str
    is_whitelisted: bool
    is_multi_tenant: bool = False
    category: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "registered_domain": self.registered_domain,
            "is_whitelisted": self.is_whitelisted,
            "is_multi_tenant": self.is_multi_tenant,
            "category": self.category,
            "reason": self.reason,
        }


class VerifiedDomainWhitelist:
    """Manages high-reputation domain registries and multi-tenant hosting awareness."""

    # Top-tier high-reputation commercial and enterprise platforms (Zero false positive targets)
    CORE_TRUSTED_DOMAINS: Dict[str, str] = {
        # Search & Global Portals
        "google.com": "Search & Cloud Platform",
        "youtube.com": "Streaming Media",
        "microsoft.com": "Enterprise Software & Cloud",
        "apple.com": "Technology & Services",
        "amazon.com": "E-Commerce & Cloud",
        "yahoo.com": "Portal & Media",
        "baidu.com": "Search & Services",
        "yandex.ru": "Search & Services",
        "wikipedia.org": "Reference & Encyclopedia",
        "wikimedia.org": "Reference & Media Repository",
        
        # Developer & Technical
        "github.com": "Developer Platform",
        "gitlab.com": "Developer Platform",
        "bitbucket.org": "Developer Platform",
        "stackoverflow.com": "Developer Q&A",
        "stackexchange.com": "Technical Q&A",
        "docker.com": "Developer Platform",
        "npmjs.com": "Software Registry",
        "pypi.org": "Software Registry",
        "python.org": "Technical Documentation",
        "mozilla.org": "Open Source & Documentation",
        "kernel.org": "Open Source Infrastructure",
        "apache.org": "Open Source Foundation",
        "cloudflare.com": "CDN & Internet Security",
        "fastly.com": "Content Delivery Network",
        "akamai.com": "Content Delivery Network",

        # Business, Social & Collaboration
        "linkedin.com": "Professional Network",
        "twitter.com": "Social Network",
        "x.com": "Social Network",
        "facebook.com": "Social Network",
        "instagram.com": "Social Media",
        "reddit.com": "Discussion Platform",
        "slack.com": "Enterprise Messaging",
        "zoom.us": "Video Conferencing",
        "salesforce.com": "Enterprise CRM",
        "atlassian.net": "Productivity & Issue Tracking",
        "stripe.com": "Payment Infrastructure",
        "paypal.com": "Financial Services",
        "netflix.com": "Entertainment Streaming",
        "spotify.com": "Music Streaming",
        "nytimes.com": "News & Journalism",
        "bbc.com": "News & Broadcasting",
        "cnn.com": "News & Journalism",
        "reuters.com": "News & Financial Telemetry",
        "bloomberg.com": "Financial Telemetry",
    }

    # Public Multi-tenant User Content Hosting (Phishing may be uploaded under user accounts)
    # These domains are recognized as legitimate infrastructure, but MUST NOT be unconditionally cleared!
    MULTI_TENANT_USER_HOSTS: Set[str] = {
        "forms.gle",
        "docs.google.com",
        "drive.google.com",
        "sites.google.com",
        "firebaseapp.com",
        "web.app",
        "workers.dev",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "github.io",
        "gitlab.io",
        "notion.site",
        "azurewebsites.net",
        "amazonaws.com",
        "s3.amazonaws.com",
        "blob.core.windows.net",
        "sharepoint.com",
        "weebly.com",
        "wixsite.com",
        "blogspot.com",
        "wordpress.com",
        "appspot.com",
        "glitch.me",
        "ngrok.io",
        "ngrok-free.app",
    }

    def __init__(self, custom_trusted: Optional[Dict[str, str]] = None) -> None:
        """Initialize whitelist manager.
        
        Args:
            custom_trusted: Optional supplementary dictionary of {domain: category}.
        """
        self._trusted = dict(self.CORE_TRUSTED_DOMAINS)
        if custom_trusted:
            self._trusted.update(custom_trusted)

    def extract_registered_domain(self, target: str) -> Tuple[str, str]:
        """Extract both full host and root registered domain."""
        target_str = str(target or "").strip()
        if not target_str:
            return "", ""

        if "://" not in target_str and not target_str.startswith("//"):
            target_str = f"http://{target_str}"

        try:
            parsed = urllib.parse.urlsplit(target_str)
            host = parsed.netloc.split(":")[0].strip().lower()
        except Exception:
            host = target_str.split("/")[0].split(":")[0].strip().lower()

        ext = _TLD_EXTRACTOR(host)
        if ext.domain and ext.suffix:
            reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        else:
            reg_domain = host

        return host, reg_domain

    def is_multi_tenant(self, host: str, reg_domain: str) -> bool:
        """Check if hostname or domain belongs to an open user-content hosting platform."""
        host_lower = host.lower()
        reg_lower = reg_domain.lower()

        if host_lower in self.MULTI_TENANT_USER_HOSTS or reg_lower in self.MULTI_TENANT_USER_HOSTS:
            return True

        for mth in self.MULTI_TENANT_USER_HOSTS:
            if host_lower.endswith(f".{mth}"):
                return True

        return False

    def check_whitelist(self, target: str) -> WhitelistResult:
        """Evaluate if target URL or domain is an established verified platform.
        
        Args:
            target: Full URL or domain name.
            
        Returns:
            WhitelistResult with classification details.
        """
        host, reg_domain = self.extract_registered_domain(target)

        if not host and not reg_domain:
            return WhitelistResult(
                target=str(target),
                registered_domain="",
                is_whitelisted=False,
                reason="Invalid domain or hostname",
            )

        # Check multi-tenant condition
        if self.is_multi_tenant(host, reg_domain):
            return WhitelistResult(
                target=str(target),
                registered_domain=reg_domain,
                is_whitelisted=False,
                is_multi_tenant=True,
                category="Multi-Tenant User Content Provider",
                reason=(
                    f"Domain '{host}' belongs to an open multi-tenant user content platform. "
                    f"Must be evaluated through deep content analysis; cannot be blanket whitelisted."
                ),
            )

        # Check core trusted registry
        if reg_domain in self._trusted:
            category = self._trusted[reg_domain]
            return WhitelistResult(
                target=str(target),
                registered_domain=reg_domain,
                is_whitelisted=True,
                is_multi_tenant=False,
                category=category,
                reason=f"Verified high-reputation domain registered to {category}.",
            )

        return WhitelistResult(
            target=str(target),
            registered_domain=reg_domain,
            is_whitelisted=False,
            is_multi_tenant=False,
            reason="Domain is not present in verified top-tier registry.",
        )
