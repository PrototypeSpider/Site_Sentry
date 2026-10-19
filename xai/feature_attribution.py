"""SHAP explanations for SiteSentry's packaged tabular model artifacts."""

from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
import shap

from ml.features import FEATURE_COLUMNS, extract_features

_EXPLANATION = (
    "SHAP values describe how input features move this model's probability relative to its "
    "training reference rows. They are advisory, not causal and not verified security evidence."
)


def _mswd_frame(bundle: dict, features: dict) -> pd.DataFrame:
    columns = bundle["feature_columns"]
    row = {column: features.get(column) for column in columns}
    for column in bundle.get("numeric_columns", []):
        try:
            value = float(row[column]) if row[column] not in (None, "") else np.nan
        except (TypeError, ValueError):
            value = np.nan
        row[column] = np.nan if value == -1 else value
    for column in bundle.get("categorical_columns", []):
        value = row[column]
        row[column] = None if value is None or str(value).strip().lower() in {"", "nan", "none", "null"} else str(value)
    return pd.DataFrame([row], columns=columns)


def _configuration_frame(bundle: dict, record: dict) -> pd.DataFrame:
    features = extract_features(record)
    columns = bundle.get("feature_columns", FEATURE_COLUMNS)
    return pd.DataFrame([[features[name] for name in columns]], columns=columns, dtype=float)


def explain_bundle(bundle: dict, features: dict, *, max_background: int = 20) -> dict:
    """Explain the positive-class probability for either supported task bundle."""
    try:
        task = bundle.get("task")
        if task == "mswd_malicious_site":
            row = _mswd_frame(bundle, features)
            label = "malicious"
            class_value = 1
            model_name = bundle.get("model_version")
        elif task == "configuration_review":
            row = _configuration_frame(bundle, features)
            label = "review"
            class_value = "review"
            model_name = bundle.get("metadata", {}).get("model_version")
        else:
            # Backward compatibility for earlier config model artifacts.
            row = _configuration_frame(bundle, features)
            label = "review"
            class_value = "review"
            model_name = bundle.get("metadata", {}).get("model_version")

        model = bundle["model"]
        classes = list(model.classes_)
        if class_value not in classes:
            return {"method": "shap_permutation", "status": "unsupported_model", "model": model_name, "feature_contributions": []}
        class_index = classes.index(class_value)
        columns = list(row.columns)
        background_rows = bundle.get("shap_background")
        if background_rows:
            raw_background = pd.DataFrame(background_rows, columns=columns)
        else:
            raw_background = row.copy()

        categorical = set(bundle.get("categorical_columns", [])) if task == "mswd_malicious_site" else set()
        category_maps = {}
        for column in categorical:
            values = sorted({str(value) for value in raw_background[column] if not pd.isna(value)})
            category_maps[column] = {value: index for index, value in enumerate(values)}
        def encode(frame):
            result = frame.copy()
            for column in columns:
                if column in categorical:
                    mapping = category_maps[column]
                    result[column] = result[column].map(lambda value: np.nan if pd.isna(value) else mapping.get(str(value), len(mapping))).astype(float)
                else:
                    result[column] = pd.to_numeric(result[column], errors="coerce")
            return result.to_numpy(dtype=float)

        def decode(masked):
            frame = pd.DataFrame(np.asarray(masked, dtype=float), columns=columns)
            for column in columns:
                if column in categorical:
                    reverse = {index: value for value, index in category_maps[column].items()}
                    frame[column] = frame[column].map(lambda value: reverse.get(int(value), None) if not pd.isna(value) else None)
                else:
                    frame[column] = pd.to_numeric(frame[column], errors="coerce")
                    frame.loc[frame[column] == -1, column] = np.nan
            return frame

        def positive_probability(masked):
            frame = decode(masked)
            return model.predict_proba(frame)[:, class_index]

        explainer = shap.Explainer(
            positive_probability,
            shap.maskers.Independent(encode(raw_background), max_samples=max_background),
            algorithm="permutation",
        )
        # Permutation SHAP needs 2 * feature_count + 1 evaluations for one cycle.
        values = explainer(encode(row), max_evals=max(2 * len(columns) + 1, 100), silent=True)
        contributions = [
            {"feature": name, "value": _json_value(row.iloc[0][name]), "contribution": float(values.values[0][index])}
            for index, name in enumerate(columns)
        ]
        contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
        return {
            "method": "shap_permutation", "status": "available", "model": model_name,
            "explained_output": f"{label}_probability",
            "base_value": float(np.asarray(values.base_values).reshape(-1)[0]),
            "feature_contributions": contributions,
            "interpretation": _EXPLANATION,
        }
    except Exception as exc:
        return {"method": "shap_permutation", "status": "unavailable", "reason": type(exc).__name__,
                "model": bundle.get("model_version") or bundle.get("metadata", {}).get("model_version"),
                "feature_contributions": [], "interpretation": _EXPLANATION}


def _json_value(value):
    if pd.isna(value):
        return None
    if isinstance(value, np.generic):
        return value.item()
    return value


def explain_linear(record: dict, model_path: str) -> dict:
    """Compatibility wrapper for the live configuration-review assessment."""
    try:
        bundle = joblib.load(model_path)
    except FileNotFoundError:
        return {"method": "shap_permutation", "status": "not_available", "feature_contributions": []}
    return explain_bundle(bundle, record)
