"""Loads the trained classifier (training it on first use if no model file exists)."""
import json
import warnings

import joblib
import numpy as np

from app.config import ML_METRICS_PATH, ML_MODEL_PATH


class RiskClassifier:
    def __init__(self) -> None:
        if not ML_MODEL_PATH.exists() or not ML_METRICS_PATH.exists():
            from app.ml.train import train_and_save
            train_and_save()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._pipeline = joblib.load(ML_MODEL_PATH)
        self.metrics = json.loads(ML_METRICS_PATH.read_text(encoding="utf-8"))

    def predict_score(self, feature_vector: list[float]) -> float:
        """Probability of the 'malicious' class scaled to 0-100."""
        probability = self._pipeline.predict_proba(np.array([feature_vector]))[0, 1]
        return float(probability) * 100.0


_classifier: RiskClassifier | None = None


def get_classifier() -> RiskClassifier:
    global _classifier
    if _classifier is None:
        _classifier = RiskClassifier()
    return _classifier
