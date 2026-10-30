# Models Directory

This directory stores trained machine learning model artifacts, encoders, and evaluation metadata.

### Anticipated Artifacts:
- `phishing_model.joblib`: Serialized Scikit-learn estimator (e.g., Random Forest Classifier, Logistic Regression, or XGBoost).
- `feature_names.json`: Ordered list of extracted features expected by the trained model pipeline.
- `model_metrics.json`: Training and test performance figures (Accuracy, Precision, Recall, F1-Score, ROC-AUC) computed strictly on validation splits.
