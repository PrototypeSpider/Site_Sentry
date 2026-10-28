"""Terminal-native SiteSentry CLI; Advanced is the single scan profile."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# The repository has existing top-level packages (including the generic name
# `ml`). Put this installation's package root first so editable CLI installs do
# not accidentally resolve a similarly named namespace from another project.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(Path.cwd() / ".env", override=False)
load_dotenv(PROJECT_ROOT / ".env", override=False)

from config import _parse_domains
from scanner.url_validation import TargetValidationError, report_safe_url, validate_target
from sitesentry import __version__
from storage import ScanStore

app = typer.Typer(
    name="sitesentry",
    help="Passive website security assessment from the terminal. Advanced checks are the default and only scan profile.",
    no_args_is_help=False,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
config_app = typer.Typer(help="Inspect SiteSentry CLI configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")

console = Console()
CLI_OWNER = "local-cli"
SUPPORTED_FORMATS = ("text", "json")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def _settings() -> tuple[tuple[float, float], set[str] | None, str, str]:
    try:
        connect_timeout = float(os.getenv("SITESENTRY_CONNECT_TIMEOUT", "3.05"))
        read_timeout = float(os.getenv("SITESENTRY_READ_TIMEOUT", "7"))
    except ValueError as exc:
        raise ValueError("SITESENTRY_CONNECT_TIMEOUT and SITESENTRY_READ_TIMEOUT must be numbers.") from exc
    if min(connect_timeout, read_timeout) <= 0:
        raise ValueError("Connect and read timeouts must be positive.")
    domains = _parse_domains(os.getenv("SITESENTRY_ALLOWED_DOMAINS", ""))
    database = os.getenv("SITESENTRY_DATABASE", "data/sitesentry.sqlite3")
    report_dir = os.getenv("SITESENTRY_REPORT_DIR", "reports/out")
    return (connect_timeout, read_timeout), set(domains) or None, database, report_dir


def _store() -> ScanStore:
    _, _, database, _ = _settings()
    return ScanStore(database)


def _write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _exit_error(message: str, code: int) -> None:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


def _status_style(status: str) -> str:
    return {
        "pass": "green",
        "finding": "yellow",
        "warning": "yellow",
        "fail": "bold red",
        "error": "bold red",
        "inconclusive": "cyan",
        "not_assessed": "dim",
    }.get(status, "white")


def _severity_style(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "informational": "dim",
    }.get(severity.lower(), "white")


def _render_report(report: dict[str, Any], *, output: Console = console) -> None:
    result_state = str(report.get("scan_status", report.get("status", "unknown"))).upper()
    profile = (report.get("metadata") or {}).get("scan_profile", report.get("profile", "advanced"))
    target = report.get("target", "unknown target")
    scan_id = report.get("scan_id", "unknown")
    header = Text()
    header.append("Target   ", style="bold")
    header.append(str(target) + "\n")
    header.append("Profile  ", style="bold")
    header.append(str(profile).upper() + " · passive checks\n")
    header.append("State    ", style="bold")
    header.append(result_state + "\n")
    header.append("Scan ID  ", style="bold")
    header.append(str(scan_id))
    output.print(Panel(header, title=f"SiteSentry {__version__}", border_style="blue", expand=False))

    findings = report.get("findings") or []
    table = Table(title="Security findings", show_lines=True, expand=True)
    table.add_column("Status", width=14)
    table.add_column("Severity", width=14)
    table.add_column("Check", min_width=24)
    table.add_column("Evidence", ratio=3, overflow="fold")
    table.add_column("Recommended fix", ratio=3, overflow="fold")
    for item in findings:
        status = str(item.get("status", "unknown"))
        severity = str(item.get("severity", "informational"))
        table.add_row(
            Text(status.upper(), style=_status_style(status)),
            Text(severity.upper(), style=_severity_style(severity)),
            Text(str(item.get("check", item.get("check_id", "Check")))),
            Text(str(item.get("evidence", "—"))),
            Text(str(item.get("recommendation", "—"))),
        )
    output.print(table)

    summary = report.get("summary") or {}
    metrics = report.get("metrics") or {}
    count_rows = [
        ("Checks", len(findings)),
        ("Passed", metrics.get("checks_passed", summary.get("pass", 0))),
        ("To review", metrics.get("findings_to_review", 0)),
        ("High / critical", metrics.get("high_critical_findings", 0)),
    ]
    counts = Table(title="Scan summary", show_header=False, box=None, padding=(0, 2))
    for label, value in count_rows:
        counts.add_row(label, str(value))
    duration = metrics.get("scan_duration_seconds")
    counts.add_row("Duration", f"{duration:.2f}s" if isinstance(duration, (float, int)) else "not available")
    tls = metrics.get("tls_verified")
    counts.add_row("TLS verified", "yes" if tls is True else "no" if tls is False else "not assessed")
    output.print(counts)

    limitations = report.get("limitations") or []
    if limitations:
        output.print("[dim]Limitations:[/dim]")
        for limitation in limitations:
            output.print(Text(f"  • {limitation}", style="dim"))
    errors = report.get("errors") or []
    for error in errors:
        message = Text("Scan error: ", style="bold red")
        message.append(str(error))
        output.print(message)


def _completed_below_threshold(report: dict, fail_on: str) -> bool:
    if fail_on == "none":
        return True
    threshold = SEVERITY_ORDER.index(fail_on)
    for item in report.get("findings", []):
        if item.get("status") not in {"finding", "warning", "fail", "error", "inconclusive"}:
            continue
        severity = str(item.get("severity", "informational")).lower()
        if severity in SEVERITY_ORDER and SEVERITY_ORDER.index(severity) <= threshold:
            return False
    return True


def _load_report(source: str) -> dict[str, Any]:
    path = Path(source).expanduser()
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Could not read a valid SiteSentry JSON report from that path.") from exc
    else:
        stored = _store().get_scan(source, CLI_OWNER)
        if not stored or not isinstance(stored.get("result"), dict):
            raise ValueError("No local CLI scan with that ID or JSON report file was found.")
        payload = stored["result"]
    if not isinstance(payload, dict) or not isinstance(payload.get("findings", []), list):
        raise ValueError("The JSON file does not have the expected SiteSentry report structure.")
    return payload


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        typer.echo(f"SiteSentry {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def scan(
    url: str = typer.Argument(..., help="HTTP(S) target URL on a standard port."),
    authorized: bool = typer.Option(False, "--authorized", help="Confirm you are authorized to assess this target."),
    output_format: str = typer.Option("text", "--format", help="Terminal output: text or json."),
    output_path: Path | None = typer.Option(None, "--output", help="Optional path for the canonical JSON scan report."),
    fail_on: str = typer.Option("none", "--fail-on", help="Return exit code 1 for unresolved findings at this severity or higher; default none."),
) -> None:
    """Run the single Advanced passive assessment profile."""
    if not authorized:
        _exit_error("pass --authorized to confirm permission to assess this target.", 3)
    if output_format not in SUPPORTED_FORMATS:
        _exit_error("--format must be text or json.", 3)
    if fail_on not in {"none", "critical", "high", "medium", "low"}:
        _exit_error("--fail-on must be none, critical, high, medium, or low.", 3)
    try:
        timeout, domains, _, report_dir = _settings()
        target = validate_target(url, allowed_domains=domains)
    except (ValueError, TargetValidationError) as exc:
        _exit_error(str(exc), 3)

    if output_format == "text":
        console.print(Text(f"SiteSentry {__version__} · starting ADVANCED passive scan", style="bold blue"))
        target_line = Text("Target: ")
        target_line.append(report_safe_url(target.url))
        console.print(target_line)
    try:
        from scanner.engine import Scanner
        progress_console = Console(stderr=True)
        with progress_console.status("Collecting DNS, HTTP, and TLS evidence; applying Advanced rules…", spinner="dots"):
            result = Scanner(timeout=timeout, allowed_domains=domains).scan(target.url, profile="advanced").to_dict()
            # Persist every accepted local CLI scan in the same versioned SQLite store.
            store = _store()
            created_at = result.get("started_at") or datetime.now(timezone.utc).isoformat()
            store.create_scan(result["scan_id"], report_safe_url(target.url), created_at, "advanced", CLI_OWNER)
            store.update_status(
                result["scan_id"], result.get("scan_status", "error"), result=result,
                error="; ".join(result.get("errors", [])) or None,
                finished_at=result.get("completed_at") or datetime.now(timezone.utc).isoformat(),
            )
        default_report = Path(report_dir).expanduser() / f"{result['scan_id']}.json"
        report_destination = output_path.expanduser() if output_path else default_report
        _write_json(report_destination, result)
    except Exception as exc:
        # Avoid leaking request internals or environment values from unexpected exceptions.
        _exit_error(f"scan could not be saved or completed ({type(exc).__name__}).", 2)

    if output_format == "json":
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _render_report(result)
        console.print(f"[green]JSON report saved:[/green] {report_destination.resolve()}")

    if result.get("scan_status") != "completed":
        raise typer.Exit(code=2)
    if not _completed_below_threshold(result, fail_on):
        raise typer.Exit(code=1)


@app.command()
def report(
    source: str = typer.Argument(..., help="A local CLI scan ID or a SiteSentry JSON report path."),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
    output_path: Path | None = typer.Option(None, "--output", help="Optional destination file."),
) -> None:
    """Display or export a saved scan report."""
    if output_format not in SUPPORTED_FORMATS:
        _exit_error("--format must be text or json.", 3)
    try:
        payload = _load_report(source)
    except ValueError as exc:
        _exit_error(str(exc), 3)
    if output_format == "json":
        rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        if output_path:
            output_path.expanduser().parent.mkdir(parents=True, exist_ok=True)
            output_path.expanduser().write_text(rendered, encoding="utf-8")
        typer.echo(rendered, nl=False)
    else:
        _render_report(payload)
        if output_path:
            _write_json(output_path.expanduser(), payload)
            console.print(f"[green]JSON report saved:[/green] {output_path.expanduser().resolve()}")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", min=1, max=100, help="Number of recent local CLI scans to show."),
) -> None:
    """List recent scans submitted through this local CLI."""
    try:
        scans = _store().list_scans(limit, CLI_OWNER)
    except Exception as exc:
        _exit_error(f"could not open local scan history ({type(exc).__name__}).", 2)
    if not scans:
        console.print("No CLI scans are saved yet. Run [bold]sitesentry scan URL --authorized[/bold].")
        return
    table = Table(title="Recent SiteSentry scans", show_lines=False)
    table.add_column("Created", style="dim")
    table.add_column("State")
    table.add_column("Profile")
    table.add_column("Target")
    table.add_column("Scan ID", overflow="fold")
    for item in scans:
        table.add_row(str(item.get("created_at", ""))[:19].replace("T", " "), str(item.get("status", "unknown")).upper(),
                      str(item.get("profile", "advanced")).upper(), str(item.get("target", "")), str(item.get("scan_id", "")))
    console.print(table)


@config_app.command("show")
def config_show() -> None:
    """Show effective non-secret CLI settings."""
    try:
        timeout, domains, database, report_dir = _settings()
    except ValueError as exc:
        _exit_error(str(exc), 3)
    table = Table(title="SiteSentry CLI configuration", show_header=True)
    table.add_column("Setting")
    table.add_column("Value")
    values = {
        "scan_profile": "advanced (only CLI profile)",
        "allowed_domains": ", ".join(sorted(domains)) if domains else "any valid public hostname",
        "connect_timeout_seconds": timeout[0],
        "read_timeout_seconds": timeout[1],
        "database_path": str(Path(database).expanduser()),
        "report_directory": str(Path(report_dir).expanduser()),
        "API token": "configured" if os.getenv("SITESENTRY_API_TOKEN") else "not required for standalone CLI",
        "Redis": "configured" if os.getenv("SITESENTRY_REDIS_URL") else "not configured (not needed for one local CLI process)",
        "AI provider": os.getenv("AI_PROVIDER") or "disabled",
        "Gemini credential": "configured" if os.getenv("GEMINI_API_KEY") else "not configured",
        "Grok credential": "configured" if os.getenv("XAI_API_KEY") else "not configured",
    }
    for key, value in values.items():
        table.add_row(key, str(value))
    console.print(table)


@app.command()
def doctor() -> None:
    """Check local CLI dependencies and configuration without scanning a target."""
    _doctor_impl()


def _doctor_impl() -> None:
    checks = [
        ("Typer CLI", "typer"), ("Rich terminal output", "rich"),
        ("Flask/backend models", "flask"), ("DNS resolver", "dns.resolver"),
        ("scikit-learn", "sklearn"), ("SHAP explanations", "shap"),
    ]
    table = Table(title="SiteSentry doctor")
    table.add_column("Component")
    table.add_column("Status")
    missing = []
    for label, module in checks:
        try:
            import_module(module)
            table.add_row(label, "[green]available[/green]")
        except ImportError:
            missing.append(module.split(".")[0])
            table.add_row(label, "[red]missing[/red]")
    try:
        timeout, domains, database, report_dir = _settings()
        Path(database).expanduser().parent.mkdir(parents=True, exist_ok=True)
        Path(report_dir).expanduser().mkdir(parents=True, exist_ok=True)
        table.add_row("CLI configuration", "[green]valid[/green]")
        table.add_row("Domain scope", "[green]allowlist configured[/green]" if domains else "[yellow]all public hostnames allowed[/yellow]")
        table.add_row("Network timeouts", f"{timeout[0]}s connect / {timeout[1]}s read")
        config_error = None
    except (OSError, ValueError) as exc:
        table.add_row("CLI configuration", "[red]invalid[/red]")
        config_error = str(exc)
    console.print(table)
    if missing:
        error_console.print("Install project dependencies with: python -m pip install -e .")
        raise typer.Exit(code=2)
    if config_error:
        _exit_error(config_error, 3)
    console.print("[green]Ready.[/green] No target was contacted by this diagnostic.")


@app.command("check-config")
def check_config() -> None:
    """Alias for doctor: validate local CLI dependencies and settings."""
    _doctor_impl()


@app.command()
def version() -> None:
    """Display the installed SiteSentry CLI version."""
    typer.echo(f"SiteSentry {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
