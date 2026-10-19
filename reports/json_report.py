"""Canonical JSON report serialization and safe filesystem export."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path

from scanner.models import ScanResult


def serialize_report(result: ScanResult) -> str:
    payload = result.to_dict()
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["integrity"] = {"algorithm": "sha256", "digest": hashlib.sha256(canonical).hexdigest()}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def write_report(result: ScanResult, output_dir: str | Path = "reports/out") -> Path:
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    scan_id = re.sub(r"[^a-zA-Z0-9_-]", "", result.scan_id)
    if not scan_id:
        raise ValueError("Scan result has an invalid scan ID.")
    destination = (directory / f"{scan_id}.json").resolve()
    if destination.parent != directory:
        raise ValueError("Report path escaped the configured output directory.")
    destination.write_text(serialize_report(result) + "\n", encoding="utf-8")
    return destination
