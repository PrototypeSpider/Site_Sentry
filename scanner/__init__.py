"""SiteSentry passive assessment engine with lazy scanner imports."""

from .models import Finding, ScanResult

__all__ = ["Finding", "ScanResult", "Scanner", "scan_url"]


def __getattr__(name: str):
    # Keep lightweight URL-policy utilities and CLI diagnostics importable even
    # before optional ML/XAI runtime dependencies are available.
    if name in {"Scanner", "scan_url"}:
        from .engine import Scanner, scan_url
        return Scanner if name == "Scanner" else scan_url
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
