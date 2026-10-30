import os
import sys
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath("."))
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

ext = ExperimentalURLFeatureExtractor()
target_url = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"

v22 = np.array([ext.extract_vector(target_url, "baseline")], dtype=np.float32)
v30 = np.array([ext.extract_vector(target_url, "experimental")], dtype=np.float32)

prod_m = joblib.load("models/phishing_model.joblib")["model"]
c1_m = joblib.load("models/experiments/stage1/rf_baseline_22f.joblib")["model"]
c2_m = joblib.load("models/experiments/stage1/rf_regularized_22f.joblib")["model"]
c3_m = joblib.load("models/experiments/stage1/rf_experimental_30f.joblib")["model"]

models = [
    ("Production RF", prod_m, v22, ext.BASELINE_FEATURE_NAMES),
    ("Candidate 1 (RF Base)", c1_m, v22, ext.BASELINE_FEATURE_NAMES),
    ("Candidate 2 (RF Reg)", c2_m, v22, ext.BASELINE_FEATURE_NAMES),
    ("Candidate 3 (RF Exp 30f)", c3_m, v30, ext.EXPERIMENTAL_FEATURE_NAMES),
]

for name, m, vec, feat_names in models:
    proba = m.predict_proba(vec)[0]
    print(f"\n=======================================================")
    print(f"Model: {name} | Phishing Prob: {proba[1]:.4f}")
    print(f"=======================================================")
    
    # Feature importances
    importances = m.feature_importances_
    top_indices = np.argsort(importances)[::-1][:7]
    print("Top 7 Global Feature Importances:")
    for idx in top_indices:
        print(f"  {feat_names[idx]:<20}: {importances[idx]:.4f} (value={vec[0][idx]})")
    
    # Analyze leaf predictions across all trees in forest
    tree_votes = []
    split_features_used = {}
    for tree in m.estimators_:
        leaf_id = tree.apply(vec)[0]
        # tree.tree_.value shape: (n_nodes, 1, n_classes)
        val = tree.tree_.value[leaf_id][0]
        # vote probability for class 1
        p1 = val[1] / np.sum(val) if np.sum(val) > 0 else 0.0
        tree_votes.append(p1)
        
        # Trace path to leaf
        node_id = 0
        while node_id != leaf_id:
            feat_idx = tree.tree_.feature[node_id]
            threshold = tree.tree_.threshold[node_id]
            feat_name = feat_names[feat_idx]
            split_features_used[feat_name] = split_features_used.get(feat_name, 0) + 1
            if vec[0][feat_idx] <= threshold:
                node_id = tree.tree_.children_left[node_id]
            else:
                node_id = tree.tree_.children_right[node_id]
                
    print(f"Tree Vote Distribution: mean={np.mean(tree_votes):.4f}, median={np.median(tree_votes):.4f}")
    print(f"Trees voting >= 0.5: {sum(v >= 0.5 for v in tree_votes)} / {len(tree_votes)} ({sum(v >= 0.5 for v in tree_votes)/len(tree_votes):.1%})")
    
    sorted_splits = sorted(split_features_used.items(), key=lambda x: x[1], reverse=True)[:8]
    print("Most Frequently Traversed Decision Splits:")
    for fn, cnt in sorted_splits:
        print(f"  {fn:<20}: used in {cnt} decision nodes")
