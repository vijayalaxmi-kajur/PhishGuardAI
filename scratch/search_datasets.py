import os
import sys
sys.path.insert(0, os.path.abspath("."))
import pandas as pd
import tldextract

domains_to_check = [
    "youtube.com",
    "skills.google",
    "unstop.com",
    "springeveningpl.com",
    "edutainer.in"
]

urls_to_check = [
    "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4",
    "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4",
    "https://www.skills.google/course_templates/702",
    "https://unstop.com/blog/infosys-aptitude-questions",
    "https://springeveningpl.com/",
    "http://www.internship.edutainer.in/student/student-dashboard",
]

datasets = {
    "Baseline Dataset.csv": "dataset/Dataset.csv",
    "Phase 14A Verified Eval Set": "data/phase14a/phase14a_verified_evaluation_set.csv",
}

if os.path.exists("data/phase13c1/phase13c1_dataset.csv"):
    datasets["Phase 13C1 Dataset"] = "data/phase13c1/phase13c1_dataset.csv"
elif os.path.exists("data/phase13c1/train.csv"):
    datasets["Phase 13C1 Train"] = "data/phase13c1/train.csv"

def extract_reg_domain(url):
    ext = tldextract.extract(str(url))
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}".lower()
    return (ext.domain or "").lower()

for d_name, d_path in datasets.items():
    if not os.path.exists(d_path):
        continue
    df = pd.read_csv(d_path)
    url_col = "url" if "url" in df.columns else ("URL" if "URL" in df.columns else df.columns[0])
    label_col = "label" if "label" in df.columns else ("target" if "target" in df.columns else None)
    
    print(f"\n==========================================")
    print(f"SEARCHING IN: {d_name} ({len(df)} rows)")
    
    # Exact URL match
    for u in urls_to_check:
        matches = df[df[url_col].str.lower() == u.lower()]
        if len(matches) > 0:
            labels = matches[label_col].tolist() if label_col else "N/A"
            print(f"  [EXACT URL MATCH] '{u}' -> {len(matches)} rows, labels: {labels}")
            
    # Domain search
    df["reg_domain"] = df[url_col].apply(extract_reg_domain)
    for dom in domains_to_check:
        dom_matches = df[df["reg_domain"] == dom]
        if len(dom_matches) > 0:
            label_counts = dom_matches[label_col].value_counts().to_dict() if label_col else len(dom_matches)
            print(f"  [DOMAIN MATCH] '{dom}' -> {len(dom_matches)} rows, labels: {label_counts}")
        else:
            print(f"  [DOMAIN NOT FOUND] '{dom}' (0 matches)")
