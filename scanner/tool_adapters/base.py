"""Fixed executable adapters: no shell, caller-controlled paths, or flags."""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..url_validation import TargetValidationError, ValidatedTarget, validate_target

MAX_OUTPUT_BYTES = 64_000


class AdapterError(RuntimeError):
    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class AdapterResult:
    tool: str
    version: str
    status: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    error_code: str | None = None
    duration_ms: int = 0
    evidence: str = ""

    def normalized_observations(self) -> list[dict[str, Any]]:
        return [{"observation_id": _observation_id(self.tool, row), "source": self.tool, "tool_version": self.version,
                 "status": row.get("status", "inconclusive"), "evidence": row.get("evidence", ""),
                 "check_id": row.get("check_id"), "observed_at": row.get("observed_at"),
                 "limitation": row.get("limitation")} for row in self.observations]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolAdapter:
    name = "abstract"
    executable_names: tuple[str, ...] = ()
    timeout_seconds = 30
    authorization_required = True
    network_module = "web"

    def __init__(self, *, allowed_domains: set[str], executable_dir: str | None = None):
        if not allowed_domains:
            raise ValueError("Tool adapters require an explicit authorized-domain allowlist.")
        self.allowed_domains = {item.lower().rstrip(".") for item in allowed_domains}
        self.executable_dir = Path(executable_dir).resolve() if executable_dir else None
        if self.executable_dir is None:
            raise ValueError("External tools require an explicit executable directory; PATH lookup is disabled.")
        if self.executable_dir is not None and not self.executable_dir.is_dir():
            raise ValueError("Configured executable directory must exist.")

    def available(self) -> bool:
        return self._resolve_executable() is not None

    def run(self, target: ValidatedTarget, *, authorization_ref: str | None = None) -> AdapterResult:
        if self.authorization_required and not authorization_ref:
            raise AdapterError("An authorization reference is required for external tools.", code="authorization_required")
        try:
            checked = validate_target(target.url, allowed_domains=self.allowed_domains)
        except TargetValidationError as exc:
            raise AdapterError("Target is outside authorized scope.", code="scope_rejected") from exc
        executable = self._resolve_executable()
        if executable is None:
            return AdapterResult(self.name, "unavailable", "not_available", error_code="tool_not_installed")
        argv = self.build_argv(executable, checked)
        start = time.monotonic()
        try:
            proc = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.timeout_seconds, check=False, env={"PATH": os.path.dirname(executable), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                cwd=os.path.dirname(executable), close_fds=True)
        except subprocess.TimeoutExpired as exc:
            raw = (exc.stdout or b"")[:MAX_OUTPUT_BYTES]
            if isinstance(raw, str): raw=raw.encode("utf-8",errors="replace")
            return AdapterResult(self.name, "unknown", "error", error_code="tool_timeout",
                duration_ms=int((time.monotonic()-start)*1000), evidence=_decode(raw))
        except OSError:
            return AdapterResult(self.name, "unknown", "error", error_code="tool_execution_failed",
                duration_ms=int((time.monotonic()-start)*1000))
        elapsed = int((time.monotonic()-start)*1000)
        stdout = proc.stdout[:MAX_OUTPUT_BYTES]
        stderr = proc.stderr[:MAX_OUTPUT_BYTES]
        combined = _decode(stdout)
        if len(proc.stdout) > MAX_OUTPUT_BYTES or len(proc.stderr) > MAX_OUTPUT_BYTES:
            return AdapterResult(self.name,self.version(executable),"error",error_code="output_limit_exceeded",duration_ms=elapsed,evidence=combined)
        if proc.returncode != 0:
            return AdapterResult(self.name, self.version(executable), "error", error_code="tool_nonzero_exit",
                duration_ms=elapsed, evidence=combined or _decode(stderr))
        try:
            observations = self.parse_output(combined)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return AdapterResult(self.name, self.version(executable), "error", error_code="parser_failed",
                duration_ms=elapsed, evidence=combined[:2000])
        return AdapterResult(self.name, self.version(executable), "completed", observations=deduplicate(observations),
            duration_ms=elapsed, evidence=combined)

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        raise NotImplementedError

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def _resolve_executable(self) -> str | None:
        for name in self.executable_names:
            candidate = self.executable_dir / name
            if not str(candidate) or not candidate.is_absolute() or not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if self.executable_dir and self.executable_dir not in resolved.parents:
                continue
            return str(resolved)
        return None

    def version(self, executable: str) -> str:
        return Path(executable).name


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]


def deduplicate(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    result = []
    for observation in observations:
        key = (str(observation.get("check_id", "")), str(observation.get("status", "")), json.dumps(observation.get("evidence", ""), sort_keys=True))
        if key not in seen:
            seen.add(key)
            result.append(observation)
    return result


def _observation_id(source: str, row: dict[str, Any]) -> str:
    import hashlib
    payload = json.dumps([source, row.get("check_id"), row.get("status"), row.get("evidence")], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def reconcile_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group same-check results while preserving disagreement as inconclusive."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in observations:
        grouped.setdefault(str(row.get("check_id", "unknown")), []).append(row)
    output=[]
    for check_id, rows in grouped.items():
        statuses={row.get("status") for row in rows}
        output.append({"check_id":check_id,"status":next(iter(statuses)) if len(statuses)==1 else "inconclusive",
                       "conflict":len(statuses)>1,"sources":rows,"evidence":"Conflicting observations preserved." if len(statuses)>1 else rows[0].get("evidence","")})
    return output
