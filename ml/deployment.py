"""Write integrity-checked, versioned bundles for local/API deployment."""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy
import pandas
import sklearn
import shap


def save_bundle(bundle: dict, path: str | Path) -> dict:
    """Serialize a complete inference bundle and a checksum-verified sidecar."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "artifact": path.name,
        "sha256": digest,
        "model_version": bundle.get("model_version") or bundle.get("metadata", {}).get("model_version"),
        "task": bundle.get("task") or bundle.get("target"),
        "feature_columns": bundle.get("feature_columns", []),
        "metrics": bundle.get("metrics") or bundle.get("metadata", {}).get("metrics"),
        "limitations": bundle.get("metadata", {}).get("limitations", []),
        "label_mapping": bundle.get("label_mapping"),
        "label_mapping_status": bundle.get("metadata", {}).get("label_mapping_status"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runtime": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                    "numpy": numpy.__version__, "pandas": pandas.__version__, "shap": shap.__version__,
                    "joblib": joblib.__version__},
        "load_instruction": "Load with joblib in an isolated, trusted Python environment using the recorded compatible dependencies.",
        "trusted_pickle_warning": "Only load this artifact from a trusted source; joblib uses Python pickle serialization.",
    }
    path.with_suffix(path.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    lockfile = path.parent / "requirements-deploy.txt"
    lockfile.write_text("\n".join([
        f"joblib=={joblib.__version__}", f"numpy=={numpy.__version__}",
        f"pandas=={pandas.__version__}", f"scikit-learn=={sklearn.__version__}",
        f"shap=={shap.__version__}", "",
    ]), encoding="utf-8")
    return manifest


def verify_bundle(path: str | Path) -> dict:
    """Reject an artifact whose bytes differ from its deployment manifest."""
    path = Path(path)
    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, manifest.get("sha256", "")):
        raise ValueError(f"Model artifact checksum verification failed: {path.name}")
    return manifest
