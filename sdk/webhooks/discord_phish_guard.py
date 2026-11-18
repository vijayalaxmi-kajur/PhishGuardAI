"""
PhishGuardAI Discord Bot Link Auditor
Automatically scans incoming Discord messages for phishing links and credential harvesters.
"""

import os
import re
import sys
import argparse
from typing import List, Dict, Any

from pathlib import Path
SDK_DIR = Path(__file__).resolve().parent.parent / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from phishguard import PhishGuardClient

URL_REGEX = re.compile(
    r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\'"]*)?',
    re.IGNORECASE
)


class DiscordPhishGuardAuditor:
    """Audits Discord messages for malicious phishing links using PhishGuardAI."""

    def __init__(self, api_key: str = None, base_url: str = "http://127.0.0.1:5000"):
        self.client = PhishGuardClient(api_key=api_key, base_url=base_url)

    def extract_urls(self, text: str) -> List[str]:
        """Extract all HTTP/HTTPS links from raw message content."""
        if not text:
            return []
        return URL_REGEX.findall(text)

    def audit_message(self, content: str, author_name: str = "User") -> Dict[str, Any]:
        """
        Audit a single message: extract URLs and scan each with PhishGuardAI.
        Returns a moderation verdict.
        """
        urls = self.extract_urls(content)
        if not urls:
            return {"action": "ALLOW", "threats_found": 0, "details": []}

        threats = []
        for url in urls:
            try:
                res = self.client.scan(url, check_presence=False)
                verdict = (res.get("verdict") or res.get("standardized_verdict") or "").lower()
                risk = (res.get("risk_level") or "").lower()

                is_malicious = (
                    verdict in ("phishing", "confirmed_malicious") or
                    risk in ("high", "critical")
                )

                if is_malicious:
                    threats.append({
                        "url": url,
                        "verdict": verdict,
                        "risk_level": risk,
                        "score": res.get("phishing_probability", 0.0),
                        "reasons": res.get("explanation", [])
                    })
            except Exception as e:
                # Log error without failing moderation
                pass

        if threats:
            return {
                "action": "DELETE_AND_WARN",
                "author": author_name,
                "threats_found": len(threats),
                "threats": threats,
                "moderation_alert": self._format_discord_alert(author_name, threats)
            }

        return {"action": "ALLOW", "threats_found": 0, "details": []}

    def _format_discord_alert(self, author: str, threats: List[Dict[str, Any]]) -> str:
        """Format an embed text string suitable for Discord moderation channel."""
        lines = [
            f"🚨 **PHISHGUARD SECURITY ALERT** 🚨",
            f"**User:** `{author}` posted one or more verified malicious phishing links.",
            f"**Action Taken:** Message flagged for immediate removal.",
            "**Threat Details:**"
        ]
        for t in threats:
            lines.append(f"• **URL:** `{t['url']}` (Risk: **{t['risk_level'].upper()}**, Score: `{t['score']:.2f}`)")
            if t["reasons"]:
                lines.append(f"  *Reason:* {t['reasons'][0]}")
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="PhishGuardAI Discord Link Auditor")
    parser.add_argument("--test", type=str, help="Simulate moderation on test message string")
    parser.add_argument("--api-key", type=str, default=os.getenv("PHISHGUARD_API_KEY", ""))
    parser.add_argument("--url", type=str, default=os.getenv("PHISHGUARD_URL", "http://127.0.0.1:5000"))
    args = parser.parse_args()

    auditor = DiscordPhishGuardAuditor(api_key=args.api_key, base_url=args.url)

    if args.test:
        print(f"Auditing test message: '{args.test}'")
        result = auditor.audit_message(args.test, author_name="SuspiciousUser#1337")
        print("\nModeration Result:")
        print(f"Action: {result['action']}")
        print(f"Threats Detected: {result['threats_found']}")
        if result['threats_found'] > 0:
            print("\nDiscord Alert Preview:\n" + result['moderation_alert'])
    else:
        print("PhishGuardAI Discord Auditor initialized.")
        print("To test: python discord_phish_guard.py --test 'Check this gift: http://discord-free-nitro.xyz'")


if __name__ == "__main__":
    main()

