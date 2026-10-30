import os
import sys
import pandas as pd
import tldextract

real_df = pd.read_csv("data/realistic_evaluation_set.csv")
print(f"Realistic Eval Set Shape: {real_df.shape}")
print(f"Columns: {list(real_df.columns)}")
print("Label counts:")
print(real_df["label"].value_counts())

if "source" in real_df.columns:
    print("\nSources:")
    print(real_df["source"].value_counts())

train_c = pd.read_csv("data/experiments/phase_c_training.csv")
orig_dataset = pd.read_csv("dataset/Dataset.csv")

real_urls = set(real_df["url"])
train_c_urls = set(train_c["url"])
orig_urls = set(orig_dataset["url"])

print(f"\nURL Overlap with Phase C Train: {len(real_urls & train_c_urls)}")
print(f"URL Overlap with Original Dataset.csv: {len(real_urls & orig_urls)}")

ext = tldextract.TLDExtract(suffix_list_urls=None)
real_doms = {ext(u).registered_domain for u in real_urls if ext(u).registered_domain}
train_c_doms = {ext(u).registered_domain for u in train_c_urls if ext(u).registered_domain}
orig_doms = {ext(u).registered_domain for u in orig_urls if ext(u).registered_domain}

print(f"\nUnique domains in Realistic Eval: {len(real_doms)}")
shared_c = real_doms & train_c_doms
shared_orig = real_doms & orig_doms
print(f"Domain Overlap with Phase C Train: {len(shared_c)} -> {sorted(list(shared_c))}")
print(f"Domain Overlap with Original Dataset.csv: {len(shared_orig)} -> {sorted(list(shared_orig))}")
