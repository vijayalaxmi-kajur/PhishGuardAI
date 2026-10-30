import sys
import os
sys.path.insert(0, ".")
from app import create_app

app = create_app()
client = app.test_client()

real_urls = [
    "https://www.google.com/search?q=machine+learning",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4",
    "https://www.amazon.in/dp/B08N5WRWNW?ref=nb_sb_ss",
    "https://github.com/search?q=repo%3Ascikit-learn",
    "https://stackoverflow.com/questions/12345/how-to-fix-bug?rq=1",
    "https://twitter.com/search?q=ai&f=live",
    "https://www.flipkart.com/search?q=laptops&otracker=search",
    "https://en.wikipedia.org/w/index.php?title=Phishing&action=history",
    "https://www.nytimes.com/section/technology?action=click&pgtype=Homepage",
    "https://www.reddit.com/r/Python/comments/xyz123/my_new_project/",
    "https://edition.cnn.com/world",
    "https://store.steampowered.com/app/1091500/Cyberpunk_2077/",
    "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT"
]

print("=" * 110)
for u in real_urls:
    res = client.post("/api/scan", json={"url": u}).get_json()
    verdict = res.get("verdict")
    std_verdict = res.get("standardized_verdict")
    risk = res.get("risk_level")
    prob = res.get("phishing_probability")
    conf = res.get("confidence_percent")
    print(f"{u[:60]:<60} => Verdict: {verdict} ({std_verdict}, {risk}) | Prob: {prob:.4f} | Conf: {conf}%")
print("=" * 110)
