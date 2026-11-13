"""Train the ML risk classifier on a SYNTHETIC, reproducible dataset.

Honesty note: no public labelled dataset of MCP tool-call attacks was available, so the dataset is
generated from documented assumptions about how benign and malicious requests differ. Labels are
noisy on purpose (5% flipped) and the class distributions overlap, so the model must learn a
probabilistic boundary instead of a simple rule. Reported metrics describe performance on held-out
synthetic data only - they are NOT evidence of real-world detection accuracy.

Run:  python -m app.ml.train
"""
import json
import random
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.config import ML_METRICS_PATH, ML_MODEL_PATH
from app.security.risk_engine import FEATURE_NAMES

TRAINING_SEED = 42
DATASET_SIZE = 4000
LABEL_NOISE = 0.05


def _sample(rng: random.Random, malicious: bool) -> list[float]:
    """One synthetic feature vector (same order as RiskFeatures.vector())."""
    if malicious:
        sensitivity = rng.choices([0, 1, 2], weights=[0.2, 0.35, 0.45])[0]
        critical = rng.choices([0, 1, 2], weights=[0.55, 0.35, 0.10])[0]
        high = rng.choices([0, 1, 2], weights=[0.5, 0.35, 0.15])[0]
        medium = rng.choices([0, 1, 2], weights=[0.45, 0.35, 0.20])[0]
        payload_ratio = min(2.0, rng.betavariate(2, 4) * 1.4)
        bulk = int(rng.random() < 0.35)
        block_ratio = rng.betavariate(2, 3)
        rate = min(1.0, rng.expovariate(1 / 0.35))
        distrust = rng.choices([0, 1, 2], weights=[0.2, 0.35, 0.45])[0]
        anomalies = rng.choices([0, 1, 2, 3], weights=[0.45, 0.3, 0.15, 0.10])[0]
    else:
        sensitivity = rng.choices([0, 1, 2], weights=[0.5, 0.35, 0.15])[0]
        critical = rng.choices([0, 1], weights=[0.98, 0.02])[0]
        high = rng.choices([0, 1], weights=[0.93, 0.07])[0]
        medium = rng.choices([0, 1, 2], weights=[0.8, 0.17, 0.03])[0]
        payload_ratio = rng.betavariate(1.2, 12)
        bulk = int(rng.random() < 0.06)
        block_ratio = rng.betavariate(1, 12)
        rate = min(1.0, rng.expovariate(1 / 0.12))
        distrust = rng.choices([0, 1, 2], weights=[0.5, 0.35, 0.15])[0]
        anomalies = rng.choices([0, 1], weights=[0.9, 0.1])[0]
    return [sensitivity, critical, high, medium, payload_ratio, bulk, block_ratio, rate, distrust, anomalies]


def generate_dataset(seed: int = TRAINING_SEED, size: int = DATASET_SIZE):
    rng = random.Random(seed)
    features, labels = [], []
    for _ in range(size):
        malicious = rng.random() < 0.35
        features.append(_sample(rng, malicious))
        label = int(malicious)
        if rng.random() < LABEL_NOISE:
            label = 1 - label
        labels.append(label)
    return np.array(features), np.array(labels)


def train_and_save() -> dict:
    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=TRAINING_SEED, stratify=y)
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]
    coefficients = model.named_steps["logisticregression"].coef_[0]
    metrics = {
        "model": "LogisticRegression (StandardScaler pipeline)",
        "dataset": f"synthetic, {DATASET_SIZE} samples, seed {TRAINING_SEED}, {int(LABEL_NOISE * 100)}% label noise",
        "warning": "Metrics are measured on held-out SYNTHETIC data, not real attack traffic.",
        "test_samples": int(len(y_test)),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions)), 4),
        "recall": round(float(recall_score(y_test, predictions)), 4),
        "f1": round(float(f1_score(y_test, predictions)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
        "standardised_coefficients": {name: round(float(c), 3) for name, c in zip(FEATURE_NAMES, coefficients)},
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(model, ML_MODEL_PATH)
    ML_METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    print(json.dumps(train_and_save(), indent=2))
