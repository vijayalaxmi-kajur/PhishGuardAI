"""PhishGuardAI - End-to-End Prediction Verification
Tests the retrained production model and decision engine via Flask app /api/scan endpoint.
Verifies real-world legitimate and phishing URLs.
"""

import os
import sys
import json

PROJECT_ROOT = os.path.abspath(".")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app

app = create_app()
client = app.test_client()

test_cases = [
    # Legitimate popular web services & complex dynamic paths
    ("https://www.youtube.com/playlist?list=PLrAXtmErZgOdP_8GzKt234q632L_q5P-v", "Legitimate (YouTube Playlist)"),
    ("https://www.youtube.com/watch?v=913IBjqJdFI", "Legitimate (YouTube Video)"),
    ("https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array", "Legitimate (StackOverflow Q&A)"),
    ("https://store.steampowered.com/app/1091500/Cyberpunk_2077/", "Legitimate (Steam Game Store)"),
    ("https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT", "Legitimate (Spotify Base62 Track ID)"),
    ("https://www.google.com/search?q=machine+learning+tutorial", "Legitimate (Google Search Query)"),
    ("https://en.wikipedia.org/wiki/Phishing", "Legitimate (Wikipedia Article)"),
    ("https://en.wikipedia.org/w/index.php?title=Phishing&action=history", "Legitimate (Wikipedia History with Query)"),
    ("https://github.com/torvalds/linux/blob/master/README.md", "Legitimate (GitHub Repository File)"),
    ("https://github.com/scikit-learn/scikit-learn/issues/12345", "Legitimate (GitHub Issue Number)"),
    ("https://springeveningpl.com/about-us", "Legitimate (Company Apex Domain About Us)"),
    ("https://www.springeveningpl.com/about-us", "Legitimate (Company Subdomain About Us)"),
    ("https://unstop.com/blog/differences-between-product-based-and-service-based-companies", "Legitimate (Unstop Long Blog Slug)"),
    ("https://www.skills.google/course_templates/702", "Legitimate (Google Skills Portal with ID)"),
    ("https://docs.python.org/3/library/urllib.parse.html", "Legitimate (Python Official Documentation)"),
    ("https://datatracker.ietf.org/doc/html/rfc7230", "Legitimate (IETF Standards RFC 7230)"),
    ("https://arxiv.org/abs/2301.00001", "Legitimate (arXiv Research Paper)"),
    ("https://www.amazon.com/dp/B08N5WRWNW", "Legitimate (Amazon ASIN Product URL)"),

    # Phishing / Deceptive attacks
    ("http://paypal-security-update-account-verification.com/login.php", "Phishing (Deceptive PayPal Domain with Login)"),
    ("http://192.168.1.100/secure-banking/login", "Phishing (Direct IP Hostname with Banking Auth Path)"),
    ("https://appleid-apple.com.manage-login-auth.xyz/verify", "Phishing (Brand Subdomain Spoof on Disposable .xyz TLD)"),
    ("http://metamask-sync-wallet-keys.cfd/index.html", "Phishing (Crypto Wallet Credential Theft on .cfd TLD)"),
    ("http://secure-login-chase-update.top/auth", "Phishing (Chase Banking Credential Harvesting on .top TLD)"),
    ("http://login-microsoft-online.live/webscr/login.php", "Phishing (Microsoft Credential Harvesting on .live TLD)"),
    ("https://netflix-billing-update-account.site/portal/auth.php", "Phishing (Netflix Subscription Phishing on .site TLD)"),
    ("http://dhl-express-package-tracking-notice.xyz/track?id=9876", "Phishing (Courier Impersonation on .xyz TLD)")
]

print("=" * 115)
print(f"{'URL':<65} | {'Category':<22} | {'Prob':<6} | {'Verdict':<12}")
print("=" * 115)

correct_count = 0
for url, category in test_cases:
    res = client.post("/api/scan", json={"url": url})
    data = res.get_json()
    prob = data.get("phishing_probability", 0.0)
    verdict = data.get("verdict", "unknown")
    is_phish_case = "Phishing" in category
    expected_verdict = "phishing" if is_phish_case else "legitimate"
    is_correct = (verdict == expected_verdict)
    if is_correct:
        correct_count += 1
    flag = "OK" if is_correct else "MISMATCH"
    print(f"{url[:65]:<65} | {category[:22]:<22} | {prob:.2%} | {verdict:<12} [{flag}]")

print("=" * 115)
print(f"Total Benchmark Accuracy: {correct_count}/{len(test_cases)} ({correct_count/len(test_cases):.2%})")
