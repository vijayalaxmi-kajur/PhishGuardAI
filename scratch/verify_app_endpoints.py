import os
import sys
import json

sys.path.insert(0, os.path.abspath('.'))
from app import create_app

app = create_app()
client = app.test_client()

urls = [
    ("YouTube playlist", "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4"),
    ("Google Skills", "https://www.skills.google/course_templates/702"),
    ("Unstop blog", "https://unstop.com/blog/infosys-aptitude-questions"),
    ("Spring Evening PL", "https://springeveningpl.com/"),
    ("Edutainer internship", "http://www.internship.edutainer.in/student/student-dashboard"),
]

print("=== APP INFERENCE VERIFICATION ===")
for name, u in urls:
    resp = client.post('/api/scan', json={'url': u})
    data = resp.get_json()
    print(f"Target: {name}")
    print(f"  URL: {u}")
    print(f"  HTTP Status: {resp.status_code}")
    print(f"  Verdict: {data.get('verdict')} | Standardized: {data.get('standardized_verdict')}")
    print(f"  Risk Level: {data.get('risk_level')} | Model Probability: {data.get('phishing_probability')} | Confidence: {data.get('confidence_percent')}%")
    print(f"  Features Count: {len(data.get('feature_breakdown', {}))}")
    print(f"  Explanation: {data.get('explanation')}")
    print(f"  Warnings: {data.get('warnings')}")
    print("-" * 70)
