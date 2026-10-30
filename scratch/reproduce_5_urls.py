import os
import sys
sys.path.insert(0, os.path.abspath("."))
import json
import joblib
import pandas as pd
import numpy as np

from src.feature_extraction import URLFeatureExtractor
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor
from src.decision_engine.url_validation import validate_url
from src.decision_engine.adapter import ModelInferenceAdapter
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel
from src.threat_intelligence.manager import ThreatIntelligenceManager

urls = [
    # 1. YouTube playlist URL (both exact prompt string and DB string)
    ("YouTube (Prompt)", "https://www.youtube.com/watch?v=913IBjqJdFI&list=PL0oogDtEDyvvqaKSM-ZkwAqUjyvR402HH&index=4"),
    ("YouTube (DB Row 8)", "https://www.youtube.com/watch?v=9l3IBjqJdFI&list=PLOoogDtEDyvvqaKSM-ZkwAqUyjyR402HH&index=4"),
    # 2. Skills Google
    ("Skills Google", "https://www.skills.google/course_templates/702"),
    # 3. Unstop Blog
    ("Unstop Blog", "https://unstop.com/blog/infosys-aptitude-questions"),
    # 4. Spring Evening PL
    ("Spring Evening PL", "https://springeveningpl.com/"),
    # 5. Edutainer Internship
    ("Edutainer Internship", "http://www.internship.edutainer.in/student/student-dashboard"),
]

# Load models
prod_artifact = joblib.load("models/phishing_model.joblib")
prod_model = prod_artifact["model"]
prod_features = prod_artifact["feature_names"]

cand04_model = joblib.load("models/experiments/phase13c2/cand04_rf_regularized_30f.joblib")
cand06_model = joblib.load("models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib")

extractor_22 = URLFeatureExtractor()
extractor_30 = ExperimentalURLFeatureExtractor()

# Offline Threat Intelligence Manager
intel_mgr = ThreatIntelligenceManager()

# Layered Decision Engines
engine_prod = LayeredDecisionEngine(ml_model=prod_model, feature_schema="baseline", threat_intel_manager=intel_mgr, model_name="Production RF (22f)")
engine_cand04 = LayeredDecisionEngine(ml_model=cand04_model, feature_schema="experimental", threat_intel_manager=intel_mgr, model_name="Cand04 RF (30f)")
engine_cand06 = LayeredDecisionEngine(ml_model=cand06_model, feature_schema="experimental", threat_intel_manager=intel_mgr, model_name="Cand06 HistGBDT (30f)")

results = []

for label, url in urls:
    val = validate_url(url)
    
    # 1. Production Model (22 features - app.py pipeline)
    f22_dict = extractor_22.extract_features(url)
    f22_vec = [f22_dict[col] for col in prod_features]
    df_22 = pd.DataFrame([f22_vec], columns=prod_features)
    prod_prob = float(prod_model.predict_proba(df_22)[0][1])
    prod_verdict = "phishing" if prod_prob >= 0.5 else "legitimate"
    prod_conf = round(prod_prob * 100.0, 2) if prod_verdict == "phishing" else round((1.0 - prod_prob) * 100.0, 2)
    
    # 2. Candidate 4 (30 features)
    f30_dict = extractor_30.extract_experimental_features(url)
    f30_vec = [f30_dict[col] for col in cand04_model.feature_names_in_]
    df_30 = pd.DataFrame([f30_vec], columns=cand04_model.feature_names_in_)
    c4_prob = float(cand04_model.predict_proba(df_30)[0][1])
    c4_verdict = "phishing" if c4_prob >= 0.5 else "legitimate"
    
    # 3. Candidate 6 (30 features)
    c6_prob = float(cand06_model.predict_proba(df_30)[0][1])
    c6_verdict = "phishing" if c6_prob >= 0.5 else "legitimate"
    
    # 4. Layered Decision Engine results
    de_prod = engine_prod.evaluate_url(url)
    de_c4 = engine_cand04.evaluate_url(url)
    de_c6 = engine_cand06.evaluate_url(url)
    
    res = {
        "label": label,
        "url": url,
        "validation_valid": val.is_valid,
        "validation_error": val.error_message,
        "app_py_prod": {
            "phishing_prob": round(prod_prob, 5),
            "verdict": prod_verdict,
            "confidence_pct": prod_conf,
        },
        "candidate_4": {
            "phishing_prob": round(c4_prob, 5),
            "verdict": c4_verdict,
        },
        "candidate_6": {
            "phishing_prob": round(c6_prob, 5),
            "verdict": c6_verdict,
        },
        "decision_engine_prod": {
            "verdict": de_prod.verdict.value,
            "risk_level": de_prod.risk_level.value,
            "score": round(de_prod.model_score, 5) if de_prod.model_score is not None else None,
            "structural_indicators": de_prod.structural_indicators,
        },
        "decision_engine_c4": {
            "verdict": de_c4.verdict.value,
            "risk_level": de_c4.risk_level.value,
            "score": round(de_c4.model_score, 5) if de_c4.model_score is not None else None,
            "structural_indicators": de_c4.structural_indicators,
        },
        "decision_engine_c6": {
            "verdict": de_c6.verdict.value,
            "risk_level": de_c6.risk_level.value,
            "score": round(de_c6.model_score, 5) if de_c6.model_score is not None else None,
            "structural_indicators": de_c6.structural_indicators,
        },
        "f22": f22_dict,
        "f30": f30_dict
    }
    results.append(res)

with open("scratch/reproduction_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Reproduction complete. Summary:")
for r in results:
    print(f"\n--- {r['label']} ---")
    print(f"URL: {r['url']}")
    print(f"app.py Prod Model: Verdict={r['app_py_prod']['verdict'].upper()}, Prob={r['app_py_prod']['phishing_prob']:.2%}, Conf={r['app_py_prod']['confidence_pct']}%")
    print(f"Candidate 4 Model: Verdict={r['candidate_4']['verdict'].upper()}, Prob={r['candidate_4']['phishing_prob']:.2%}")
    print(f"Candidate 6 Model: Verdict={r['candidate_6']['verdict'].upper()}, Prob={r['candidate_6']['phishing_prob']:.2%}")
    print(f"DE + Cand 6: Verdict={r['decision_engine_c6']['verdict']}, Risk={r['decision_engine_c6']['risk_level']}")
