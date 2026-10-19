"""Train and compare MSWD malicious-website classifiers on domain-held-out data.

This task is malicious-site classification, distinct from SiteSentry's deterministic
configuration findings. The dataset's numeric label mapping is inferred from strong
agreement with its VirusTotal features and is recorded as an assumption in metadata.
Threat-intelligence fields are excluded from predictors to reduce target leakage.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_recall_fscore_support,
                             roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from .deployment import save_bundle

SOURCE_URL = "https://data.mendeley.com/datasets/n8hkzbzhb4/1"
SOURCE_LICENSE = "CC BY 4.0"
VERSION = "mswd-malicious-site-1.0"
EXCLUDED_COLUMNS = {
    "Domain", "SHA256", "IP", "class", "vt_blacklisted", "vt_malicious_engines",
    "vt_reputation_score", "google_safe_browsing_report", "google_safebrowsing_report", "vt_malicious",
    "vt_suspicious", "vt_harmless", "vt_undetected",
}


def _domain_group(value: str) -> str:
    parsed = urlsplit(value if "://" in value else "https://" + value)
    host = (parsed.hostname or "").lower().rstrip(".")
    return host.removeprefix("www.")


def _read_dataset(path: Path) -> tuple[list[dict[str, str]], bytes, dict]:
    raw = path.read_bytes()
    zip_path = path.parent / "MSWD Multi-Source Website Detection Dataset.zip"
    zip_metadata = {"zip_checked": zip_path.exists(), "zip_matches_csv": None}
    if zip_path.exists():
        with zipfile.ZipFile(zip_path) as archive:
            csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if len(csv_names) != 1:
                raise ValueError("Expected one CSV file inside the supplied dataset ZIP.")
            zip_metadata["zip_matches_csv"] = archive.read(csv_names[0]) == raw
            if not zip_metadata["zip_matches_csv"]:
                raise ValueError("The ZIP and standalone CSV differ; choose one authoritative dataset version.")
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines(), delimiter=";"))
    if not rows or "class" not in rows[0] or "Domain" not in rows[0]:
        raise ValueError("Expected the MSWD semicolon-delimited CSV schema.")
    return rows, raw, zip_metadata


def _feature_data(rows: list[dict[str, str]]):
    labeled = [row for row in rows if row.get("class", "").strip() in {"0", "1"}]
    if not labeled:
        raise ValueError("Dataset has no labeled class 0/1 records.")
    y = np.asarray([int(row["class"].strip()) for row in labeled], dtype=int)
    groups = np.asarray([_domain_group(row["Domain"]) for row in labeled])
    if any(not group for group in groups):
        raise ValueError("A labeled record has no parseable domain for grouped splitting.")
    columns = [name for name in labeled[0] if name not in EXCLUDED_COLUMNS]
    frame = []
    for row in labeled:
        record = {}
        for name in columns:
            value = (row.get(name) or "").strip()
            if value == "" or value.lower() in {"nan", "none", "null"}:
                record[name] = np.nan
            elif re.fullmatch(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?", value):
                number = float(value)
                # The dataset uses -1 as unknown/unavailable for several numeric fields.
                record[name] = np.nan if number == -1 else number
            else:
                record[name] = value
        frame.append(record)
    numeric = [col for col in columns if all(isinstance(row[col], (float, np.floating, int, np.integer)) for row in frame)]
    categorical = [col for col in columns if col not in numeric]
    for row in frame:
        for col in categorical:
            if not pd.isna(row[col]):
                row[col]=str(row[col])
    X = pd.DataFrame(frame, columns=columns)
    return X, y, groups, columns, numeric, categorical, len(rows) - len(labeled)


def _pipeline(columns, numeric, categorical, classifier, *, scale_numeric: bool):
    numeric_steps = [("imputer", SimpleImputer(strategy="median", add_indicator=True))]
    if scale_numeric:
        numeric_steps.append(("scale", StandardScaler()))
    transformers = []
    if numeric:
        transformers.append(("num", Pipeline(numeric_steps), numeric))
    if categorical:
        transformers.append(("cat", Pipeline([("imputer", SimpleImputer(strategy="most_frequent")),
                                               ("encode", OneHotEncoder(handle_unknown="ignore", min_frequency=2))]), categorical))
    return Pipeline([("features", ColumnTransformer(transformers, remainder="drop")), ("model", classifier)])


def _metrics(model, X_test, y_test):
    pred = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    precision, recall, f1, support = precision_recall_fscore_support(y_test, pred, labels=[0, 1], zero_division=0)
    matrix = confusion_matrix(y_test, pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "accuracy": float(accuracy_score(y_test, pred)), "macro_f1": float(f1_score(y_test, pred, average="macro")),
        "roc_auc": float(roc_auc_score(y_test, probs)), "brier_score": float(brier_score_loss(y_test, probs)),
        "per_class": {str(label): {"precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]), "support": int(support[i])} for i, label in enumerate([0, 1])},
        "confusion_matrix_labels_0_1": matrix.tolist(), "malicious_false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "malicious_false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
    }


def train(dataset: Path, output_dir: Path, *, test_size: float = 0.25, random_state: int = 42) -> dict:
    rows, raw, zip_metadata = _read_dataset(dataset)
    X, y, groups, columns, numeric, categorical, unlabeled_count = _feature_data(rows)
    if len(set(groups)) < 4 or set(y) != {0, 1}:
        raise ValueError("Need at least four domain groups and both binary labels.")
    split = GroupShuffleSplit(n_splits=50, test_size=test_size, random_state=random_state)
    train_idx = test_idx = None
    for candidate_train, candidate_test in split.split(np.zeros(len(y)), y, groups):
        if set(y[candidate_train]) == {0, 1} and set(y[candidate_test]) == {0, 1}:
            train_idx, test_idx = candidate_train, candidate_test
            break
    if train_idx is None:
        raise ValueError("Could not make a domain-group split containing both labels; inspect group/label coverage.")
    if set(groups[train_idx]) & set(groups[test_idx]):
        raise AssertionError("Domain leakage across train/test split.")
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    if min(np.bincount(y_train)) < 3:
        raise ValueError("Training split has too few examples per class for calibration.")

    logistic_base = _pipeline(columns, numeric, categorical,
        LogisticRegression(max_iter=3000, class_weight="balanced", random_state=random_state), scale_numeric=True)
    logistic = CalibratedClassifierCV(logistic_base, method="sigmoid", cv=3)
    logistic.fit(X_train, y_train)
    models = {"logistic_regression_calibrated": logistic}

    random_forest = _pipeline(columns, numeric, categorical,
        RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=random_state), scale_numeric=False)
    random_forest.fit(X_train, y_train)
    models["random_forest"] = random_forest

    mlp = _pipeline(columns, numeric, categorical,
        MLPClassifier(hidden_layer_sizes=(64, 32), alpha=0.01, early_stopping=True, max_iter=500, random_state=random_state), scale_numeric=True)
    mlp.fit(X_train, y_train)
    models["mlp_deep_learning"] = mlp

    metrics = {name: _metrics(model, X_test, y_test) for name, model in models.items()}
    majority = int(np.bincount(y_train).argmax())
    majority_pred = np.full(len(y_test), majority)
    baseline_metrics = {"majority_class": majority, "accuracy": float(accuracy_score(y_test, majority_pred)),
        "macro_f1": float(f1_score(y_test, majority_pred, average="macro")),
        "confusion_matrix_labels_0_1": confusion_matrix(y_test, majority_pred, labels=[0, 1]).tolist()}

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_paths = {}
    background_frame = X_train.iloc[np.linspace(0, len(X_train) - 1, min(20, len(X_train)), dtype=int)]
    shap_background = background_frame.where(pd.notna(background_frame), None).to_dict(orient="records")
    for name, model in models.items():
        path = output_dir / f"{name}.joblib"
        bundle = {"task": "mswd_malicious_site", "model": model, "model_version": VERSION + ":" + name, "target": "MSWD malicious website label",
                     "label_mapping": {"0": "benign (inferred)", "1": "malicious (inferred)"},
                     "feature_columns": columns, "numeric_columns": numeric,
                     "categorical_columns": categorical,
                     "shap_background": shap_background,
                     "metrics": _metrics(model, X_test, y_test),
                     "excluded_columns": sorted(EXCLUDED_COLUMNS)}
        save_bundle(bundle, path)
        artifact_paths[name] = str(path)

    metadata = {
        "model_version": VERSION, "task": "malicious website classification; advisory only; not a SiteSentry vulnerability finding",
        "source": SOURCE_URL, "source_license": SOURCE_LICENSE,
        "dataset_sha256": hashlib.sha256(raw).hexdigest(), "dataset_rows": len(rows), "labeled_rows": len(y),
        "unlabeled_rows_excluded": unlabeled_count, "label_counts": {str(label): int(np.sum(y == label)) for label in [0, 1]},
        "label_mapping": {"0": "benign", "1": "malicious"},
        "label_mapping_status": "inferred, not explicitly documented in supplied CSV/ZIP; inferred from source description and strong alignment of class 1 with threat-intelligence indicators",
        "zip_validation": zip_metadata,
        "feature_columns": columns, "excluded_columns": sorted(EXCLUDED_COLUMNS), "numeric_columns": numeric, "categorical_columns": categorical,
        "split": {"method": "GroupShuffleSplit by normalized URL hostname", "random_state": random_state,
                  "test_fraction_requested": test_size, "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
                  "train_domains": int(len(set(groups[train_idx]))), "test_domains": int(len(set(groups[test_idx]))),
                  "group_overlap": sorted(set(groups[train_idx]) & set(groups[test_idx])),
                  "train_label_counts": {str(label): int(np.sum(y_train == label)) for label in [0, 1]},
                  "test_label_counts": {str(label): int(np.sum(y_test == label)) for label in [0, 1]}},
        "baseline": baseline_metrics, "metrics": metrics, "artifacts": artifact_paths,
        "limitations": ["The 1,013 unlabeled rows were excluded.", "Label 0/1 semantic mapping is inferred and needs confirmation from dataset authors.",
            "The held-out set is hostname-grouped but not a separately locked external-domain benchmark.",
            "Dataset signals were collected at an unknown or fixed time and may be stale.",
            "VirusTotal/Safe Browsing features were excluded; performance may still reflect collection-source and dataset biases.",
            "Predictions do not verify exploitability and do not override SiteSentry rule findings."],
    }
    report = output_dir / "mswd_training_report.json"
    report.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Train SiteSentry advisory classifiers on supplied MSWD data.")
    parser.add_argument("dataset", type=Path, nargs="?", default=Path("ml/dataset_final.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/mswd-final"))
    parser.add_argument("--test-size", type=float, default=0.25)
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.output_dir, test_size=args.test_size), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
