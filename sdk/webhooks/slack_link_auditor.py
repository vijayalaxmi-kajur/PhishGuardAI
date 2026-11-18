"""
PhishGuardAI Slack Link Auditor Bot
Inspects incoming Slack message events and flags malicious phishing URLs.
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

# Slack formats links as <https://example.com|optional text> or bare URLs
SLACK_LINK_REGEX = re.compile(
    r'<((?:https?://[^\s>|]+))(?:\|[^>]+)?>|(https?://[^\s<>]+)',
    re.IGNORECASE
)


class SlackLinkAuditor:
    """Audits Slack messages for phishing and credential harvesting attacks."""

    def __init__(self, api_key: str = None, base_url: str = "http://127.0.0.1:5000"):
        self.client = PhishGuardClient(api_key=api_key, base_url=base_url)

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs accounting for Slack markdown formatting."""
        if not text:
            return []
        matches = SLACK_LINK_REGEX.findall(text)
        urls = []
        for match in matches:
            url = match[0] or match[1]
            if url:
                urls.append(url.strip())
        return urls

    def audit_message(self, text: str, user_id: str = "U123456") -> Dict[str, Any]:
        """
        Audit message content from Slack event.
        Returns Slack blocks payload for threat alerts.
        """
        urls = self.extract_urls(text)
        if not urls:
            return {"action": "ALLOW", "threats_found": 0}

        threats = []
        for url in urls:
            try:
                res = self.client.scan(url, check_presence=False)
                verdict = (res.get("verdict") or res.get("standardized_verdict") or "").lower()
                risk = (res.get("risk_level") or "").lower()

                if verdict in ("phishing", "confirmed_malicious") or risk in ("high", "critical"):
                    threats.append({
                        "url": url,
                        "verdict": verdict,
                        "risk_level": risk,
                        "score": res.get("phishing_probability", 0.0),
                        "reasons": res.get("explanation", [])
                    })
            except Exception:
                pass

        if threats:
            return {
                "action": "FLAG_AND_REPLY",
                "user_id": user_id,
                "threats_found": len(threats),
                "threats": threats,
                "slack_blocks": self._build_slack_blocks(user_id, threats)
            }

        return {"action": "ALLOW", "threats_found": 0}

    def _build_slack_blocks(self, user_id: str, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Construct Slack Block Kit UI components."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ PhishGuardAI: Security Threat Detected",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Warning: <@{user_id}> shared a link flagged as **Phishing / Malicious**."
                }
            },
            {"type": "divider"}
        ]

        for t in threats:
            reason = t["reasons"][0] if t["reasons"] else "Identified as credential theft or phishing."
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*URL:*\n`{t['url']}`"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n*{t['risk_level'].upper()}* ({t['score']:.2f})"}
                ]
            })
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"⚠️ *Reason:* {reason}"}
                ]
            })

        return blocks


def main():
    parser = argparse.ArgumentParser(description="PhishGuardAI Slack Link Auditor")
    parser.add_argument("--test", type=str, help="Simulate audit on Slack message text")
    parser.add_argument("--api-key", type=str, default=os.getenv("PHISHGUARD_API_KEY", ""))
    parser.add_argument("--url", type=str, default=os.getenv("PHISHGUARD_URL", "http://127.0.0.1:5000"))
    args = parser.parse_args()

    auditor = SlackLinkAuditor(api_key=args.api_key, base_url=args.url)

    if args.test:
        print(f"Auditing Slack test message: '{args.test}'")
        res = auditor.audit_message(args.test, user_id="U98765432")
        print(f"Action: {res['action']}")
        print(f"Threats: {res['threats_found']}")
        if res['threats_found'] > 0:
            import json
            print("Slack Blocks Payload Preview:")
            print(json.dumps(res['slack_blocks'], indent=2))
    else:
        print("PhishGuardAI Slack Auditor initialized.")
        print("To test: python slack_link_auditor.py --test 'See doc: <http://google-docs-verify.com|Click Here>'")


if __name__ == "__main__":
    main()

