"""Advisory inference for the separately trained MSWD website classifier."""

from __future__ import annotations

from pathlib import Path

import joblib
import math
import pandas as pd
from xai.feature_attribution import explain_bundle
from .deployment import verify_bundle


def predict_mswd_features(features: dict, model_path: str | Path = "models/mswd-final/logistic_regression_calibrated.joblib") -> dict:
    """Predict the MSWD dataset label from a matching feature record.

    This classifier is not called by the SiteSentry rule scanner. Its output is
    an advisory malicious-site probability and cannot establish exploitability.
    """
    verify_bundle(model_path)
    bundle=joblib.load(model_path)
    columns=bundle["feature_columns"]
    row={column:features.get(column) for column in columns}
    for column in bundle.get("numeric_columns", []):
        value=row[column]
        try:
            number=float(value) if value is not None and value != "" else math.nan
        except (TypeError, ValueError):
            number=math.nan
        row[column]=math.nan if number == -1 else number
    for column in bundle.get("categorical_columns", []):
        value=row[column]
        row[column]=None if value is None or str(value).strip().lower() in {"", "nan", "none", "null"} else str(value)
    frame=pd.DataFrame([row],columns=columns)
    model=bundle["model"]
    probabilities=model.predict_proba(frame)[0]
    class_index=list(model.classes_).index(1)
    return {"status":"advisory","model":bundle["model_version"],"prediction":int(model.predict(frame)[0]),
            "label_mapping_assumption":"0=benign, 1=malicious; confirm with dataset authors",
            "malicious_probability":float(probabilities[class_index]),
            "xai": explain_bundle(bundle, features),
            "warning":"Dataset classification only; not a verified vulnerability finding or proof of exploitability."}
