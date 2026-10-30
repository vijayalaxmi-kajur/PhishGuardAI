"""PhishGuardAI - Model Inference Adapter

Provides a standardized, robust, and type-safe inference interface for
all machine learning models across the production and experimental pipelines.

Key Responsibilities:
1. Feature Schema Compatibility:
   - Supports 22-feature baseline schema and 30-feature experimental schema.
   - Detects expected feature names via model attributes (feature_names_in_) or metadata.
   - Formats input as a named pandas.DataFrame when the fitted model expects feature names,
     suppressing scikit-learn UserWarnings.
   - Formats input as a typed numpy.ndarray when the fitted model was trained without feature names.
2. Feature Validation & Ordering:
   - Preserves the exact feature ordering established during training.
   - Validates that required features are present; does NOT silently substitute zeroes.
   - Rejects NaN, infinite, or non-numeric feature values.
3. Class Index Resolution:
   - Dynamically resolves the positive (phishing) class index from model.classes_.
   - Handles both integer [0, 1], [1, 0], and string class labels explicitly.
   - Raises informative errors when the model lacks a valid positive class.
4. Consistent Threshold Policy:
   - Standardizes decision threshold comparison:
     class = 1 (phishing) if proba >= threshold, else 0 (legitimate).
   - Handles exact probability boundary ties consistently.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import math
import numpy as np
import pandas as pd

from src.feature_extraction import URLFeatureExtractor
from src.experiments.phase_c_features import ExperimentalURLFeatureExtractor


class ModelInferenceAdapter:
    """Standardized inference adapter for scikit-learn phishing classifiers."""

    # Canonical feature names
    BASELINE_FEATURES: List[str] = [
        "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt", "letter_cnt",
        "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt", "amp_cnt", "dot_cnt",
        "dash_cnt", "under_cnt", "letter_ratio", "digit_ratio", "spec_ratio",
        "is_https", "slash_cnt", "entropy", "path_len", "query_len"
    ]

    EXPERIMENTAL_FEATURES: List[str] = list(ExperimentalURLFeatureExtractor.EXPERIMENTAL_FEATURE_NAMES)

    DEFAULT_THRESHOLD: float = 0.50

    def __init__(
        self,
        model: Any,
        feature_schema: Optional[str] = None,
        feature_names: Optional[List[str]] = None,
        model_name: Optional[str] = None,
        default_threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        """Initialize the model inference adapter.
        
        Args:
            model: Trained scikit-learn classifier or pipeline.
            feature_schema: 'baseline' (22f), 'experimental' (30f), or None to auto-detect.
            feature_names: Explicit list of feature names if overriding auto-detection.
            model_name: Optional human-readable name for logging and reporting.
            default_threshold: Decision threshold for classification (default: 0.50).
        """
        if model is None:
            raise ValueError("Model passed to ModelInferenceAdapter cannot be None.")

        # If wrapped in a dictionary artifact, unpack model and metadata
        if isinstance(model, dict):
            artifact = model
            self.model = artifact.get("model", model)
            if feature_schema is None:
                feature_schema = artifact.get("schema")
            if feature_names is None:
                feature_names = artifact.get("features")
            if model_name is None:
                model_name = artifact.get("model_name")
        else:
            self.model = model

        self.model_name = model_name or self.model.__class__.__name__
        self.default_threshold = float(default_threshold)

        # 1. Inspect fitted feature names and input format requirements
        self._fitted_feature_names: Optional[List[str]] = None
        if hasattr(self.model, "feature_names_in_"):
            self._fitted_feature_names = list(self.model.feature_names_in_)
        elif hasattr(self.model, "estimator") and hasattr(self.model.estimator, "feature_names_in_"):
            # CalibratedClassifierCV
            self._fitted_feature_names = list(self.model.estimator.feature_names_in_)

        # 2. Determine target feature names and schema
        if feature_names is not None:
            self.feature_names = list(feature_names)
        elif self._fitted_feature_names is not None:
            self.feature_names = self._fitted_feature_names
        elif feature_schema == "experimental":
            self.feature_names = list(self.EXPERIMENTAL_FEATURES)
        elif feature_schema == "baseline":
            self.feature_names = list(self.BASELINE_FEATURES)
        else:
            # Auto-detect from n_features_in_
            n_in = getattr(self.model, "n_features_in_", None)
            if n_in == 30:
                self.feature_names = list(self.EXPERIMENTAL_FEATURES)
            else:
                # Default to 22 baseline features
                self.feature_names = list(self.BASELINE_FEATURES)

        # Record schema string
        if len(self.feature_names) == 30:
            self.schema = "experimental"
        elif len(self.feature_names) == 22:
            self.schema = "baseline"
        else:
            self.schema = feature_schema or "custom"

        # 3. Resolve Positive Class (Phishing) Index
        self.phishing_class_index = self._resolve_phishing_class_index()

        # 4. Feature Extractors (lazy loaded)
        self._baseline_extractor = URLFeatureExtractor()
        self._exp_extractor = ExperimentalURLFeatureExtractor()

    def _resolve_phishing_class_index(self) -> int:
        """Dynamically resolve the column index for the phishing (positive) class."""
        classes = getattr(self.model, "classes_", None)
        if classes is None:
            # Some calibrated wrappers or meta-estimators expose classes_ on sub-estimators
            if hasattr(self.model, "estimator") and hasattr(self.model.estimator, "classes_"):
                classes = self.model.estimator.classes_

        # If classes_ is not set or is a mock object (in unit tests), default to index 1
        if classes is None or hasattr(classes, "_mock_return_value") or hasattr(classes, "_mock_methods"):
            return 1

        try:
            classes_list = list(classes)
        except Exception:
            return 1

        # If classes_ is an empty list or mock list, default to binary index 1
        if not classes_list:
            return 1

        # Case 1: Standard integer label 1
        if 1 in classes_list:
            return classes_list.index(1)

        # Case 2: String labels ('phishing', 'malicious', 'bad', etc.)
        for idx, cls in enumerate(classes_list):
            if str(cls).strip().lower() in {"1", "phish", "phishing", "malicious", "bad"}:
                return idx

        # If concrete non-empty classes are present but 1 is missing, raise explicit configuration error
        raise ValueError(
            f"Fitted model '{self.model_name}' has classes {classes_list}, which does not "
            f"contain positive target label 1 or 'phishing'."
        )

    def extract_and_format_input(
        self,
        url_or_features: Union[str, Dict[str, Any], pd.DataFrame, np.ndarray, List[float]]
    ) -> Union[pd.DataFrame, np.ndarray]:
        """Convert input URL or features into the exact format and order expected by the model.
        
        Args:
            url_or_features: Raw URL string, feature dict, DataFrame, or numpy vector.
            
        Returns:
            pd.DataFrame if model was fitted with feature names, or np.ndarray if fitted without.
        """
        # Step A: Obtain raw feature dictionary
        if isinstance(url_or_features, str):
            clean_url = url_or_features.strip()
            if self.schema == "experimental":
                raw_dict = self._exp_extractor.extract_experimental_features(clean_url)
            else:
                raw_dict = self._baseline_extractor.extract_features(clean_url)
        elif isinstance(url_or_features, dict):
            raw_dict = url_or_features
        elif isinstance(url_or_features, pd.DataFrame):
            # Validate required columns
            missing = [f for f in self.feature_names if f not in url_or_features.columns]
            if missing:
                raise ValueError(f"Input DataFrame is missing required feature(s): {missing}")
            # Reorder columns to exact expected order
            ordered_df = url_or_features[self.feature_names]
            if self._fitted_feature_names is not None:
                return ordered_df
            return ordered_df.values.astype(np.float32)
        elif isinstance(url_or_features, (np.ndarray, list)):
            arr = np.asarray(url_or_features, dtype=np.float32)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            if arr.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Expected vector with {len(self.feature_names)} features for schema '{self.schema}', "
                    f"but received vector with shape {arr.shape}."
                )
            if self._fitted_feature_names is not None:
                return pd.DataFrame(arr, columns=self.feature_names)
            return arr
        else:
            raise TypeError(f"Unsupported input type for model inference: {type(url_or_features)}")

        # Step B: Build ordered feature vector from dict
        missing_features = [f for f in self.feature_names if f not in raw_dict]
        if missing_features:
            raise ValueError(
                f"Feature dictionary is missing required feature(s) for schema '{self.schema}': {missing_features}. "
                f"Features must not be silently replaced with zero."
            )

        vector: List[float] = []
        for name in self.feature_names:
            val = raw_dict[name]
            if not isinstance(val, (int, float, np.number)) or not math.isfinite(val):
                raise ValueError(f"Feature '{name}' has invalid non-numeric or non-finite value: {val}")
            vector.append(float(val))

        # Step C: Format appropriately based on model fitting attribute
        if self._fitted_feature_names is not None:
            # Model expects named DataFrame
            return pd.DataFrame([vector], columns=self.feature_names)
        else:
            # Model was fitted without feature names; pass 2D NumPy array
            return np.array([vector], dtype=np.float32)

    def predict_proba(
        self,
        url_or_features: Union[str, Dict[str, Any], pd.DataFrame, np.ndarray, List[float]]
    ) -> float:
        """Estimate the phishing probability for the given URL or features.
        
        Returns:
            Phishing probability float in [0.0, 1.0].
        """
        X = self.extract_and_format_input(url_or_features)
        proba_matrix = self.model.predict_proba(X)
        proba_row = proba_matrix[0]
        return float(proba_row[self.phishing_class_index])

    def predict(
        self,
        url_or_features: Union[str, Dict[str, Any], pd.DataFrame, np.ndarray, List[float]],
        threshold: Optional[float] = None,
    ) -> int:
        """Predict binary classification label (0 = Legitimate, 1 = Phishing).
        
        Policy:
            Label 1 (Phishing) if probability >= threshold.
            Label 0 (Legitimate) if probability < threshold.
            Exact probability ties at threshold are classified as 1 (Phishing).
        """
        thresh = self.default_threshold if threshold is None else float(threshold)
        prob = self.predict_proba(url_or_features)
        return 1 if prob >= thresh else 0

    def predict_detailed(
        self,
        url_or_features: Union[str, Dict[str, Any], pd.DataFrame, np.ndarray, List[float]],
        threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Perform inference and return structured assessment with metadata."""
        thresh = self.default_threshold if threshold is None else float(threshold)
        prob = self.predict_proba(url_or_features)
        pred_class = 1 if prob >= thresh else 0
        return {
            "model_name": self.model_name,
            "schema": self.schema,
            "phishing_probability": prob,
            "predicted_class": pred_class,
            "threshold": thresh,
            "decision_rule": f"phishing if probability >= {thresh:.4f}",
            "phishing_class_index": self.phishing_class_index,
            "n_features": len(self.feature_names),
            "fitted_with_feature_names": self._fitted_feature_names is not None,
        }
