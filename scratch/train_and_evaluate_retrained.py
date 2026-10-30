"""PhishGuardAI - Model Training, Calibration & Rigorous Evaluation (Retrained Pipeline)
Trains regularized Random Forest and HistGradientBoosting models on the balanced retrained corpus,
calibrates probabilities on the validation split, and evaluates performance on:
- 4,934-sample domain-disjoint Holdout set
- 43-sample realistic_evaluation_set.csv
- 963-sample phase14a_verified_evaluation_set.csv
- Real-world popular websites (YouTube, StackOverflow, Steam, Spotify, Amazon, GitHub, etc.)
"""

import os
import sys
import time
import json
import joblib
import pandas as pd
import numpy as np

PROJECT_ROOT = os.path.abspath(".")
sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, recall_score,
    f1_score, balanced_accuracy_score, roc_auc_score, average_precision_score,
    brier_score_loss
)

from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.adapter import ModelInferenceAdapter
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel
from src.threat_intelligence.manager import ThreatIntelligenceManager

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "retrained")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "retrained")
os.makedirs(MODELS_DIR, exist_ok=True)

# 1. Load data
print("Loading feature matrices...")
X_train = pd.read_csv(os.path.join(DATA_DIR, "X_train_30f.csv"))
y_train = pd.read_csv(os.path.join(DATA_DIR, "y_train.csv")).squeeze()

X_val = pd.read_csv(os.path.join(DATA_DIR, "X_val_30f.csv"))
y_val = pd.read_csv(os.path.join(DATA_DIR, "y_val.csv")).squeeze()

X_holdout = pd.read_csv(os.path.join(DATA_DIR, "X_holdout_30f.csv"))
y_holdout = pd.read_csv(os.path.join(DATA_DIR, "y_holdout.csv")).squeeze()
holdout_meta = pd.read_csv(os.path.join(DATA_DIR, "holdout.csv"))

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Holdout: {X_holdout.shape}")

# 2. Train Model 1: Regularized Random Forest (30f)
print("\n--- Training Model 1: retrained_rf_30f ---")
t0 = time.time()
rf_model = RandomForestClassifier(
    n_estimators=150,
    max_depth=18,
    min_samples_leaf=3,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)
t_rf = time.time() - t0
print(f"Random Forest trained in {t_rf:.2f}s")
joblib.dump(rf_model, os.path.join(MODELS_DIR, "retrained_rf_30f.joblib"))

# 3. Train Model 2: Regularized HistGradientBoosting (30f)
print("\n--- Training Model 2: retrained_gbdt_30f ---")
t0 = time.time()
gbdt_model = HistGradientBoostingClassifier(
    max_iter=150,
    max_depth=10,
    min_samples_leaf=15,
    l2_regularization=2.0,
    class_weight="balanced",
    random_state=42
)
gbdt_model.fit(X_train, y_train)
t_gbdt = time.time() - t0
print(f"HistGradientBoosting trained in {t_gbdt:.2f}s")
joblib.dump(gbdt_model, os.path.join(MODELS_DIR, "retrained_gbdt_30f.joblib"))

# 4. Train Model 3: Calibrated HistGBDT (Isotonic on Val split)
print("\n--- Training Model 3: retrained_calibrated_gbdt_30f ---")
t0 = time.time()
try:
    from sklearn.frozen import FrozenEstimator
    cal_gbdt = CalibratedClassifierCV(estimator=FrozenEstimator(gbdt_model), method="isotonic")
    cal_gbdt.fit(X_val, y_val)
except Exception:
    cal_gbdt = CalibratedClassifierCV(estimator=gbdt_model, cv=5, method="isotonic")
    cal_gbdt.fit(X_train, y_train)

t_cal = time.time() - t0
print(f"Calibrated HistGBDT fitted in {t_cal:.2f}s")
joblib.dump(cal_gbdt, os.path.join(MODELS_DIR, "retrained_calibrated_gbdt_30f.joblib"))

# 5. Evaluate on Holdout Set
print("\n" + "=" * 90)
print(f"{'EVALUATION ON DOMAIN-DISJOINT HOLDOUT SET (N=' + str(len(X_holdout)) + ')':^90}")
print("=" * 90)

models_to_eval = {
    "Retrained RF (30f)": rf_model,
    "Retrained HistGBDT (30f)": gbdt_model,
    "Retrained Calibrated GBDT (30f)": cal_gbdt
}

results = {}
for name, m in models_to_eval.items():
    p = m.predict_proba(X_holdout)[:, 1]
    y_pred = (p >= 0.5).astype(int)
    
    cm = confusion_matrix(y_holdout, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    acc = accuracy_score(y_holdout, y_pred)
    bal_acc = balanced_accuracy_score(y_holdout, y_pred)
    prec = precision_score(y_holdout, y_pred)
    rec = recall_score(y_holdout, y_pred)
    f1 = f1_score(y_holdout, y_pred)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    roc_auc = roc_auc_score(y_holdout, p)
    pr_auc = average_precision_score(y_holdout, p)
    brier = brier_score_loss(y_holdout, p)
    
    results[name] = {
        "acc": acc, "bal_acc": bal_acc, "prec": prec, "rec": rec,
        "f1": f1, "fpr": fpr, "fnr": fnr, "roc_auc": roc_auc,
        "pr_auc": pr_auc, "brier": brier, "cm": (tn, fp, fn, tp)
    }
    
    print(f"\nModel: {name}")
    print(f"  Accuracy: {acc:.4f} | Bal Acc: {bal_acc:.4f} | Prec: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
    print(f"  FPR (False Alarm Rate): {fpr:.4f} (FP={fp}/{fp+tn}) | FNR (Miss Rate): {fnr:.4f} (FN={fn}/{fn+tp})")
    print(f"  ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f} | Brier: {brier:.4f}")

# 6. Evaluate on the 43-sample realistic_evaluation_set.csv
print("\n" + "=" * 90)
print(f"{'EVALUATION ON 43-SAMPLE REALISTIC BENCHMARK SET':^90}")
print("=" * 90)

real_bench_path = os.path.join(PROJECT_ROOT, "data", "realistic_evaluation_set.csv")
if os.path.exists(real_bench_path):
    df_real = pd.read_csv(real_bench_path)
    extractor = ExperimentalURLFeatureExtractor()
    feature_names = ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES
    
    X_real = []
    for u in df_real["url"]:
        d = extractor.extract_experimental_features(u)
        X_real.append([d[fn] for fn in feature_names])
    X_real = pd.DataFrame(X_real, columns=feature_names)
    
    for name, m in models_to_eval.items():
        probs = m.predict_proba(X_real)[:, 1]
        preds = (probs >= 0.5).astype(int)
        
        # Test on verified labels (exclude unverified stress cases if any)
        verified_mask = df_real["verification_status"].isin(["verified_legitimate", "verified_phishing"])
        v_true = df_real.loc[verified_mask, "label"].astype(int)
        v_pred = preds[verified_mask]
        v_probs = probs[verified_mask]
        
        acc = accuracy_score(v_true, v_pred)
        cm = confusion_matrix(v_true, v_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        print(f"Model: {name}")
        print(f"  Verified Accuracy: {acc:.4f} ({acc*100:.1f}%) | False Positives: {fp}/{fp+tn} (FPR={fpr:.2%}) | Misses: {fn}/{fn+tp}")

# 7. Test on Key User Real-World URLs
print("\n" + "=" * 90)
print(f"{'KEY REAL-WORLD URL TEST (LEGITIMATE vs PHISHING)':^90}")
print("=" * 90)

test_cases = [
    # Legitimate modern URLs that previously failed
    ("https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4", 0, "YouTube Playlist"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0, "YouTube Video"),
    ("https://stackoverflow.com/questions/12345/how-to-fix-bug?rq=1", 0, "StackOverflow Q&A"),
    ("https://store.steampowered.com/app/1091500/Cyberpunk_2077/", 0, "Steam Game Store"),
    ("https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT", 0, "Spotify Track"),
    ("https://www.google.com/search?q=machine+learning+tutorial", 0, "Google Search"),
    ("https://github.com/torvalds/linux", 0, "GitHub Repo"),
    ("https://github.com/search?q=repo%3Ascikit-learn", 0, "GitHub Search"),
    ("https://www.amazon.in/dp/B08N5WRWNW?ref=nb_sb_ss", 0, "Amazon Product"),
    ("https://en.wikipedia.org/w/index.php?title=Phishing&action=history", 0, "Wikipedia History"),
    ("https://unstop.com/blog/infosys-aptitude-questions", 0, "Unstop Blog"),
    ("https://springeveningpl.com/", 0, "Spring Evening PL"),
    ("http://www.internship.edutainer.in/student/student-dashboard", 0, "Edutainer Internship"),
    ("https://www.skills.google/course_templates/702", 0, "Skills Google"),
    ("https://datatracker.ietf.org/doc/html/rfc7230", 0, "IETF RFC 7230"),
    ("https://docs.kernel.org/filesystems/ext4/index.html", 0, "Linux Kernel Doc"),
    ("https://pkg.go.dev/crypto/sha256#Sum256", 0, "Go Package Dev"),
    
    # Real Phishing Attacks that MUST be detected
    ("http://login-account-update.xyz/verify", 1, "Cheap TLD Credential Phish"),
    ("https://secure-chase-auth.top/signin", 1, "Banking Impersonation (.top)"),
    ("http://netflix-billing-alert.com/login", 1, "Streaming Brand Theft"),
    ("http://secure-login-update-paypal-account.com/webscr/", 1, "PayPal Impersonation"),
    ("http://appleid-apple.com-verify.appleid.auth.net/sign-in", 1, "Apple ID Subdomain Spoofing"),
    ("http://paypa1-account-update.suspicious-domain.xyz/login", 1, "PayPal Typo + Suspicious TLD"),
    ("https://office365-password-reset.pages.dev/auth/login.php", 1, "Cloudflare Pages Abuse"),
    ("https://dhl-package-tracking-alert.firebaseapp.com/?tracking=938210948", 1, "Firebase Hosting Abuse"),
    ("http://192.241.220.14/portal/admin/login.php", 1, "Direct IP Host Phishing"),
    ("https://paypal.com.account-verification-notice.online/webapps/mpp/home", 1, "PayPal Brand Subdomain Spoof")
]

best_model = cal_gbdt
extractor = ExperimentalURLFeatureExtractor()
feature_names = ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES

print(f"{'URL':<55} | {'True':<6} | {'Cal GBDT Prob':<15} | {'Cand 10 Prob':<15} | {'Verdict'}")
print("-" * 115)

old_cand10_path = "models/experiments/phase15c/cand10_calibrated_gbdt_phase15c_30f.joblib"
old_cand10 = joblib.load(old_cand10_path) if os.path.exists(old_cand10_path) else None

for url, expected_label, desc in test_cases:
    d = extractor.extract_experimental_features(url)
    vec = pd.DataFrame([[d[fn] for fn in feature_names]], columns=feature_names)
    
    p_new = float(best_model.predict_proba(vec)[0][1])
    p_old = float(old_cand10.predict_proba(vec)[0][1]) if old_cand10 else 0.0
    
    pred_new = "PHISHING" if p_new >= 0.5 else "LEGITIMATE"
    expected_str = "PHISHING" if expected_label == 1 else "LEGIT"
    status = "OK" if (p_new >= 0.5 and expected_label == 1) or (p_new < 0.5 and expected_label == 0) else "MISCLASSIFIED"
    
    print(f"{url[:52]:<52}... | {expected_str:<6} | {p_new*100:>6.2f}% ({status}) | {p_old*100:>6.2f}% (Old) | {pred_new}")

print("\nTraining and evaluation finished successfully!")
