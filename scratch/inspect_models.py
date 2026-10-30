import joblib

def inspect_model(path, name):
    art = joblib.load(path)
    print(f"=== {name} ({path}) ===")
    if isinstance(art, dict):
        print("Type: dict wrapper")
        print("Keys:", list(art.keys()))
        model = art["model"]
        fn = art.get("feature_names")
        print(f"Model class: {type(model)}")
        print(f"Classes: {getattr(model, 'classes_', None)}")
        print(f"Feature names count: {len(fn) if fn else None}")
        if fn:
            print("Feature names (first 5, last 5):", fn[:5], "...", fn[-5:])
        meta = {k: v for k, v in art.items() if k != "model"}
        print("Metadata:", meta)
    else:
        print(f"Type: direct estimator ({type(art)})")
        print(f"Classes: {getattr(art, 'classes_', None)}")
        print(f"n_features_in_: {getattr(art, 'n_features_in_', None)}")
        if hasattr(art, "feature_names_in_"):
            print("feature_names_in_:", art.feature_names_in_)

inspect_model("models/phishing_model.joblib", "Production Model")
print()
inspect_model("models/experiments/phase13c2/cand04_rf_regularized_30f.joblib", "Candidate 4")
print()
inspect_model("models/experiments/phase13c2/cand06_hist_gbdt_30f.joblib", "Candidate 6")
