import os
import sys
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.feature_extraction import URLFeatureExtractor
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor

fe22 = URLFeatureExtractor()
ext30 = ExperimentalURLFeatureExtractor()

df_train = pd.read_csv("data/experiments/stage1_training.csv")
yt_train = df_train[df_train["url"].str.contains("youtube.com", case=False, na=False)]

target_url = "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"
target_feat = fe22.extract_features(target_url)

print("=== TARGET URL FEATURES ===")
for k, v in target_feat.items():
    print(f"  {k:<15}: {v}")

print(f"\n=== YOUTUBE TRAINING URLS IN STAGE 1 (N={len(yt_train)}) ===")
df_yt_feats = pd.DataFrame([fe22.extract_features(u) for u in yt_train["url"]])
print(df_yt_feats[["url_len", "path_len", "query_len", "entropy", "dash_cnt", "under_cnt", "digit_cnt", "special_cnt"]].describe())

# Check how many phishing URLs in training set have similar length & entropy
phish_train = df_train[df_train["label"] == 1]
df_phish_feats = pd.DataFrame([fe22.extract_features(u) for u in phish_train["url"].sample(1000, random_state=42)])

print("\n=== SAMPLE PHISHING TRAINING SET DISTRIBUTION (N=1000) ===")
print(df_phish_feats[["url_len", "path_len", "query_len", "entropy", "dash_cnt", "under_cnt", "digit_cnt", "special_cnt"]].describe())

# Check entire training set class balance at target URL range:
# url_len between 80 and 100, entropy between 5.0 and 5.8
print("\n=== TRAINING CORPUS DENSITY IN TARGET REGION (len 80-100, entropy > 5.0) ===")
# Let's sample or check
