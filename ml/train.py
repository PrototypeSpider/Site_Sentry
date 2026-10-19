"""Train an advisory configuration-review classifier on labeled CSV data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from .deployment import save_bundle

from .features import FEATURE_COLUMNS, FEATURE_VERSION, extract_features
from scanner.checks import evaluate_observation
from scanner.transport import HttpObservation

MODEL_VERSION = "logistic-config-review-1.0"


def _load_features(dataset: Path):
    raw = dataset.read_bytes()
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
    required = {"target_group", "label", "https", "tls_verified", "headers_json"}
    if len(rows) < 20 or not rows or not required.issubset(rows[0]):
        raise ValueError("Need at least 20 labeled rows with target_group, label, https, tls_verified and headers_json columns.")
    y = np.asarray([row["label"].strip() for row in rows])
    groups = np.asarray([row["target_group"].strip() for row in rows])
    if any(not label for label in y) or any(not group for group in groups):
        raise ValueError("Labels and target_group values must be non-empty.")
    if set(y) != {"compliant", "review"}:
        raise ValueError("Configuration-review labels must be exactly 'compliant' and 'review'.")
    provenance_path=dataset.with_suffix(".provenance.json")
    if not provenance_path.is_file():
        raise ValueError("A companion .provenance.json file is required before training.")
    provenance=json.loads(provenance_path.read_text(encoding="utf-8"))
    required_provenance={"schema_version","target_definition","labeling_policy","source","collected_at","reviewer","records_sha256"}
    if not required_provenance.issubset(provenance):
        raise ValueError("Dataset provenance is missing required fields.")
    if provenance["target_definition"] != "advisory configuration-review label; not vulnerability exploitability":
        raise ValueError("Dataset target must be advisory configuration review, not exploitability.")
    if provenance["records_sha256"] != hashlib.sha256(raw).hexdigest():
        raise ValueError("Dataset checksum does not match provenance metadata.")
    records = []
    for row in rows:
        headers = json.loads(row["headers_json"] or "{}")
        if not isinstance(headers, dict):
            raise ValueError("headers_json must contain a JSON object.")
        records.append({"https": row["https"].lower() in {"1", "true", "yes"}, "tls_verified": row["tls_verified"].lower() in {"1", "true", "yes"},
                        "tls_days_remaining": float(row.get("tls_days_remaining") or 0), "headers": headers})
    x = np.asarray([[extract_features(record)[name] for name in FEATURE_COLUMNS] for record in records], dtype=float)
    return x, y, groups, raw, rows


def _rule_baseline_label(row: dict[str, str]) -> str:
    """Translate the deterministic scanner's current rules into a binary review label."""
    headers = json.loads(row["headers_json"] or "{}")
    if not isinstance(headers, dict):
        raise ValueError("headers_json must contain a JSON object.")
    https = row["https"].strip().lower() in {"1", "true", "yes"}
    verified = row["tls_verified"].strip().lower() in {"1", "true", "yes"}
    try:
        days = float(row.get("tls_days_remaining") or 0)
    except ValueError as exc:
        raise ValueError("tls_days_remaining must be numeric when provided.") from exc
    not_after = format_datetime(datetime.now(timezone.utc) + timedelta(days=days)) if https else None
    observation = HttpObservation(
        requested_url="https://dataset.invalid" if https else "http://dataset.invalid",
        final_url="https://dataset.invalid" if https else "http://dataset.invalid",
        status_code=200, headers={str(k).lower(): str(v) for k, v in headers.items()},
        tls={"verified": verified, "not_after": not_after} if https else None,
        redirect_chain=[], body_bytes_read=0,
    )
    findings = evaluate_observation(observation)
    return "review" if any(item.status in {"finding", "warning", "fail", "error"} for item in findings) else "compliant"


def _metrics(y_true, y_pred) -> dict:
    labels = ["compliant", "review"]
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    tn, fp, fn, tp = matrix.ravel()
    return {"per_class": {label: {"precision": float(precision[i]), "recall": float(recall[i]),
            "f1": float(f1[i]), "support": int(support[i])} for i, label in enumerate(labels)},
        "macro_f1": float(np.mean(f1)), "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "confusion_matrix_labels_compliant_review": matrix.tolist()}


def train(dataset: Path, output: Path) -> dict:
    x, y, groups, raw, rows = _load_features(dataset)
    if len(set(y)) < 2 or len(set(groups)) < 4:
        raise ValueError("Need at least two labels and four target groups for held-out evaluation.")
    train_idx = test_idx = None
    splitter = GroupShuffleSplit(n_splits=50, test_size=0.25, random_state=42)
    for candidate_train, candidate_test in splitter.split(x, y, groups):
        if set(y[candidate_train]) == set(y) and set(y[candidate_test]) == set(y):
            train_idx, test_idx = candidate_train, candidate_test
            break
    if train_idx is None:
        raise ValueError("Could not find a domain-grouped holdout with both labels in train and test.")
    if set(groups[train_idx]) & set(groups[test_idx]):
        raise AssertionError("Target-group leakage across train/test split.")
    train_class_counts = {label: int(sum(y[train_idx] == label)) for label in set(y)}
    if min(train_class_counts.values()) < 3:
        raise ValueError("Sigmoid calibration requires at least three training rows per class; add labeled target groups.")
    base = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scale", StandardScaler()),
                     ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42))])
    base.fit(x[train_idx], y[train_idx])
    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(x[train_idx], y[train_idx])
    predictions = model.predict(x[test_idx])
    classes = model.classes_
    model_metrics = _metrics(y[test_idx], predictions)
    rule_predictions = np.asarray([_rule_baseline_label(rows[index]) for index in test_idx])
    rule_metrics = _metrics(y[test_idx], rule_predictions)
    metadata = {"model_version": MODEL_VERSION, "feature_version": FEATURE_VERSION, "target": "advisory configuration-review label",
        "trained_at": datetime.now(timezone.utc).isoformat(), "dataset_sha256": hashlib.sha256(raw).hexdigest(), "row_count": len(y),
        "train_rows": len(train_idx), "test_rows": len(test_idx), "train_groups": sorted(set(groups[train_idx])), "test_groups": sorted(set(groups[test_idx])),
        "classes": classes.tolist(), "probability_calibration": "sigmoid calibration fitted on training split using 3-fold CV", "metrics": model_metrics,
        "deterministic_rule_baseline": {"name": "SiteSentry scanner checks", "rule_version": "1.0",
            "mapping": "review if any deterministic finding, warning, fail or error exists; otherwise compliant",
            "metrics": rule_metrics},
        "limitations": ["Advisory ranking only; never evidence that a vulnerability exists.", "Evaluation applies only to supplied labels and held-out target groups.", "For unseen-domain acceptance, do not rely on the random group split alone; reserve and report a separately locked domain holdout."],
        "baseline": {"name":"deterministic_site_rules","available":True,
            "comparison_note":"Predictions are compared to the held-out human labels; deterministic findings remain authoritative."}}
    output.parent.mkdir(parents=True, exist_ok=True)
    background = x[train_idx][np.linspace(0, len(train_idx) - 1, min(20, len(train_idx)), dtype=int)].tolist()
    bundle = {"task": "configuration_review", "model": model, "metadata": metadata,
              "feature_columns": FEATURE_COLUMNS, "shap_background": background}
    save_bundle(bundle, output)
    output.with_suffix(".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models/config_review.joblib"))
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.output), indent=2))


if __name__ == "__main__":
    main()
