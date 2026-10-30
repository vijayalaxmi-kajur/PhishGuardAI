import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json
from app import create_app

def main():
    print("=" * 70)
    print("PHISHGUARDAI: LIVE WEBSITE PRESENCE E2E VERIFICATION TEST")
    print("=" * 70)

    # Initialize app with real presence checking enabled
    app = create_app({"CHECK_WEBSITE_PRESENCE": True})
    client = app.test_client()

    test_urls = [
        # Real websites
        "https://www.google.com",
        "https://chatledge.vercel.app/",
        "https://ishacotton.sanchikahub.in/",
        # Non-existent websites on wildcard hosts (Netlify 404 Site not found)
        "https://mayur189122221.netlify.app",
        # Non-existent websites (NXDOMAIN)
        "https://thisdomaindoesnotexistanywhereinthisuniverse9982347.com/login",
        "https://fake-phishing-bank-portal-never-registered-992384.xyz/auth",
    ]

    for url in test_urls:
        print(f"\nScanning: {url}")
        resp = client.post("/api/scan", json={"url": url})
        data = resp.get_json()

        print(f"Status Code           : {resp.status_code}")
        print(f"Website Present       : {data.get('website_present')}")
        print(f"Presence Message      : {data.get('presence_message')}")
        print(f"Verdict               : {data.get('verdict')}")
        print(f"Standardized Verdict  : {data.get('standardized_verdict')}")
        print(f"Risk Level            : {data.get('risk_level')}")
        print(f"Phishing Probability  : {data.get('phishing_probability')}")
        print(f"Confidence Percent    : {data.get('confidence_percent')}%")
        print(f"Live Telemetry        : {json.dumps(data.get('live_telemetry', {}), indent=2)}")
        print(f"Explanation Sample    : {data.get('explanation', [''])[0]}")

    print("\n" + "=" * 70)
    print("ALL E2E PRESENCE TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    main()
