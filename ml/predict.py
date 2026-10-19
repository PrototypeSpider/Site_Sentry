"""Run optional advisory ML separately from deterministic findings."""

import joblib
import numpy as np
from .deployment import verify_bundle

from .features import FEATURE_COLUMNS, FEATURE_VERSION, extract_features


def assess(record: dict, model_path: str) -> dict:
    try:
        verify_bundle(model_path)
        bundle = joblib.load(model_path)
    except FileNotFoundError:
        return {"status": "not_configured", "model": None, "prediction": None, "confidence": None}
    except (ValueError, OSError):
        return {"status": "incompatible_model", "model": None, "prediction": None, "confidence": None}
    if bundle.get("metadata", {}).get("feature_version") != FEATURE_VERSION or tuple(bundle.get("feature_columns", ())) != FEATURE_COLUMNS:
        return {"status": "incompatible_model", "model": bundle.get("metadata", {}).get("model_version"), "prediction": None, "confidence": None}
    vector = np.asarray([[extract_features(record)[name] for name in FEATURE_COLUMNS]], dtype=float)
    model = bundle["model"]
    probabilities = model.predict_proba(vector)[0]
    index = int(np.argmax(probabilities))
    return {"status": "advisory", "model": bundle["metadata"]["model_version"], "feature_version": FEATURE_VERSION,
            "prediction": str(model.classes_[index]), "confidence": float(probabilities[index]),
            "warning": "Advisory classification only; not verified vulnerability evidence."}
