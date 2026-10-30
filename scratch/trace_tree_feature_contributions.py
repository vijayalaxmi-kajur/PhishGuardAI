import os
import sys
sys.path.insert(0, os.path.abspath("."))
import joblib
import pandas as pd
import numpy as np
from src.feature_extraction import URLFeatureExtractor

prod_artifact = joblib.load("models/phishing_model.joblib")
rf = prod_artifact["model"]
feature_names = prod_artifact["feature_names"]
extractor = URLFeatureExtractor()

target_urls = [
    ("YouTube", "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"),
    ("Skills Google", "https://www.skills.google/course_templates/702"),
    ("Unstop", "https://unstop.com/blog/infosys-aptitude-questions"),
    ("Spring Evening PL", "https://springeveningpl.com/"),
    ("Edutainer", "http://www.internship.edutainer.in/student/student-dashboard"),
]

# Compute tree feature importances
importances = pd.Series(rf.feature_importances_, index=feature_names).sort_values(ascending=False)
print("=== Global Feature Importances (Production Random Forest) ===")
print(importances)

# Now compute tree path feature contributions (MDI / treeinterpreter style)
# We can evaluate how each feature shifts the probability from base rate across all trees
base_prob = np.mean([tree.tree_.value[0][0][1] / np.sum(tree.tree_.value[0][0]) for tree in rf.estimators_])
print(f"\nModel Base Phishing Probability (Prior): {base_prob:.4f}")

for label, url in target_urls:
    feat_dict = extractor.extract_features(url)
    x = pd.DataFrame([[feat_dict[c] for c in feature_names]], columns=feature_names)
    pred_prob = rf.predict_proba(x)[0][1]
    
    # Feature contributions across all trees
    contributions = {f: 0.0 for f in feature_names}
    
    for tree in rf.estimators_:
        t = tree.tree_
        node = 0
        path_nodes = [0]
        while t.children_left[node] != t.children_right[node]:
            feature = t.feature[node]
            threshold = t.threshold[node]
            val = x.iloc[0, feature]
            if val <= threshold:
                next_node = t.children_left[node]
            else:
                next_node = t.children_right[node]
            
            p_parent = t.value[node][0][1] / np.sum(t.value[node][0])
            p_child = t.value[next_node][0][1] / np.sum(t.value[next_node][0])
            delta = p_child - p_parent
            contributions[feature_names[feature]] += delta / len(rf.estimators_)
            node = next_node
            
    sorted_contrib = sorted(contributions.items(), key=lambda item: abs(item[1]), reverse=True)
    print(f"\n==========================================")
    print(f"URL: {label} -> P(phishing) = {pred_prob:.2%}")
    print(f"Top 5 Positive (Phishing-pushing) Feature Contributions:")
    pos = [c for c in sorted_contrib if c[1] > 0][:5]
    for k, v in pos:
        print(f"  + {k:15s}: +{v:+.4f} (value={feat_dict[k]})")
    print(f"Top 5 Negative (Legit-pushing) Feature Contributions:")
    neg = [c for c in sorted_contrib if c[1] < 0][:5]
    for k, v in neg:
        print(f"  - {k:15s}: {v:+.4f} (value={feat_dict[k]})")
