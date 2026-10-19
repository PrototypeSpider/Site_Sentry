"""Streamlit dashboard for authenticated, profile-based SiteSentry scans."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanner import (BackendError, api_token, cancel_scan, create_scan,
                     get_pdf_report, get_report, get_scan, get_xai_report, health, list_scans, normalize_url)

st.set_page_config(page_title="SiteSentry", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
[data-testid="stMainBlockContainer"] { max-width: 1480px; padding-top: 1.1rem; }
[data-testid="stMetric"] { background: #142030; padding: 14px; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SiteSentry")
st.caption("Authorized passive website security checks · deterministic findings from the SiteSentry backend")

if not api_token():
    st.error("Dashboard API token is not configured on the server. Set SITESENTRY_API_TOKEN in the dashboard environment or project .env file.")
    st.stop()

@st.fragment(run_every="10s")
def live_backend_activity():
    """Poll backend health and grouped per-profile scan logs every ten seconds."""
    try:
        backend_health = health()
        st.success(f"Backend ready · {backend_health.get('active_scans', 0)} active · {backend_health.get('queue_depth', 0)} queued")
        scan_logs = list_scans(50)
        for profile in ("quick", "standard", "advanced"):
            matching = [item for item in scan_logs if item.get("profile", "standard") == profile]
            with st.expander(f"{profile.title()} scan logs · {len(matching)}", expanded=False):
                if not matching:
                    st.caption(f"No {profile} scans recorded yet.")
                for item in matching:
                    created = item.get("created_at", "")[:19].replace("T", " ")
                    st.markdown(f"**{item.get('status', 'unknown').title()}** · {created}")
                    st.caption(item.get("target", ""))
    except BackendError as exc:
        st.error(f"Backend unavailable · {exc}")

with st.sidebar:
    st.header("Scan setup")
    live_backend_activity()

    profile_labels = {
        "Quick": "quick",
        "Standard": "standard",
        "Advanced": "advanced",
    }
    profile_label = st.radio("Scan level", list(profile_labels), index=1,
        help="Quick checks core HTTPS/TLS and key headers. Standard adds DNS and all baseline headers. Advanced adds TLS protocol/cipher and CSP directive review.")
    selected_profile = profile_labels[profile_label]
    st.divider()
    st.subheader("Scan history")
    try:
        history = list_scans(30)
    except BackendError as exc:
        st.error(str(exc))
        history = []
    if history:
        def history_label(item):
            created = item.get("created_at", "")[:16].replace("T", " ")
            profile = item.get("profile", "standard").title()
            return f"{created} · {item.get('target', '')} · {profile} · {item.get('status', '')}"

        history_by_id = {item["scan_id"]: item for item in history}
        history_ids = list(history_by_id)
        previous_id = st.session_state.get("selected_scan_id")
        selected_index = history_ids.index(previous_id) if previous_id in history_by_id else 0
        selected_id = st.selectbox("Recent scans", history_ids, index=selected_index,
            format_func=lambda scan_id: history_label(history_by_id[scan_id]))
        st.session_state.selected_scan_id = selected_id
    else:
        st.caption("No scans saved yet.")
        selected_id = None

    if st.button("Generate XAI report", disabled=not selected_id, type="primary"):
        try:
            report = get_xai_report(selected_id)
            st.session_state.xai_report = report
            st.session_state.xai_report_scan_id = selected_id
            st.rerun()
        except BackendError as exc:
            st.error(f"Could not generate the XAI report: {exc}")

    st.caption("The API token stays on this server and is not exposed to browser code.")

with st.form("scan_form", clear_on_submit=False):
    st.subheader(f"Start a {profile_label.lower()} scan")
    url_text = st.text_input("Website URL", placeholder="https://example.com")
    submitted = st.form_submit_button("Start scan", type="primary")

if submitted:
    target_url = normalize_url(url_text)
    if target_url is None:
        st.error("Enter a valid HTTP or HTTPS URL on a standard port.")
    else:
        try:
            accepted = create_scan(target_url, selected_profile)
            selected_id = accepted["scan_id"]
            st.session_state.selected_scan_id = selected_id
            state = accepted.get("status", "queued")
            with st.status(f"{profile_label} scan queued…", expanded=True) as status_box:
                deadline = time.monotonic() + 60
                while state not in {"completed", "partial", "error", "cancelled"} and time.monotonic() < deadline:
                    time.sleep(0.75)
                    state = get_scan(selected_id).get("status", "unknown")
                    status_box.update(label=f"Scan {state}", state="complete" if state in {"completed", "partial", "error", "cancelled"} else "running")
                if state not in {"completed", "partial", "error", "cancelled"}:
                    status_box.update(label=f"Scan remains {state}; refresh to see its result.", state="running")
            st.rerun()
        except BackendError as exc:
            st.error(str(exc))


def _display_status(value: str) -> str:
    value = (value or "").lower()
    if value == "pass":
        return "Pass"
    if value in {"fail", "error"}:
        return "Fail"
    return "Warn"


def _display_severity(value: str) -> str:
    return "Info" if value in {"informational", "info", None, ""} else str(value).title()


def _sankey(findings: list[dict]):
    if not findings:
        st.info("No findings are available for this scan.")
        return
    status_nodes = ["Pass", "Warn", "Fail"]
    severity_nodes = ["Critical", "High", "Medium", "Low", "Info"]
    checks = list(dict.fromkeys(item.get("check", item.get("check_id", "Check")) for item in findings))
    labels = status_nodes + severity_nodes + checks
    node_index = {label: index for index, label in enumerate(labels)}
    status_colors = {"Pass": "rgba(46, 160, 67, 0.62)", "Warn": "rgba(230, 159, 0, 0.68)", "Fail": "rgba(220, 53, 69, 0.72)"}
    status_severity_counts: dict[tuple[str, str], int] = {}
    severity_check_counts: dict[tuple[str, str, str], int] = {}
    for item in findings:
        status = _display_status(item.get("status"))
        severity = _display_severity(item.get("severity"))
        check = item.get("check", item.get("check_id", "Check"))
        status_severity_counts[(status, severity)] = status_severity_counts.get((status, severity), 0) + 1
        key = (status, severity, check)
        severity_check_counts[key] = severity_check_counts.get(key, 0) + 1
    sources, targets, values, colors = [], [], [], []
    for (status, severity), count in status_severity_counts.items():
        sources.append(node_index[status])
        targets.append(node_index[severity])
        values.append(count)
        colors.append(status_colors[status])
    # Preserve the originating status on the second segment so each full path
    # stays green, amber, or red from its start node through the check node.
    for (status, severity, check), count in severity_check_counts.items():
        source, target = severity, check
        sources.append(node_index[source])
        targets.append(node_index[target])
        values.append(count)
        colors.append(status_colors[status])
    chart = go.Figure(go.Sankey(
        arrangement="snap",
        node={"pad": 14, "thickness": 18, "line": {"color": "#536273", "width": 0.5}, "color": "#667788", "label": labels},
        link={"source": sources, "target": targets, "value": values, "color": colors},
    ))
    chart.update_layout(height=420, margin={"l": 10, "r": 10, "t": 10, "b": 10}, font_size=11)
    st.plotly_chart(chart, width="stretch")


if selected_id:
    try:
        scan_record = get_scan(selected_id)
        scan_state = scan_record.get("status", "unknown")
        saved_xai_report = st.session_state.get("xai_report")
        if saved_xai_report and st.session_state.get("xai_report_scan_id") == selected_id:
            with st.container(border=True):
                st.subheader(saved_xai_report.get("title", "Explainable scan report"))
                st.markdown(saved_xai_report.get("markdown", ""))
                st.download_button("Download XAI report", saved_xai_report.get("markdown", ""),
                    file_name=f"sitesentry-xai-{selected_id}.md", mime="text/markdown")
        header_left, header_right = st.columns([4, 1])
        header_left.subheader(scan_record.get("target", "Scan result"))
        header_right.metric("Status", scan_state.title())
        st.caption(f"{scan_record.get('profile', 'standard').title()} profile · Scan ID {selected_id}")

        action_left, action_right = st.columns([1, 5])
        if scan_state == "queued" and action_left.button("Cancel queued scan"):
            cancel_scan(selected_id)
            st.rerun()
        if scan_state not in {"completed", "partial", "error", "cancelled"}:
            if action_right.button("Refresh scan"):
                st.rerun()
            st.info("Scan is queued or running. Results will appear when collection finishes.")
        else:
            try:
                report = get_report(selected_id)
            except BackendError as exc:
                if exc.status_code == 409:
                    st.error(f"The scan did not produce a report: {scan_record.get('error') or 'No result stored.'}")
                    report = None
                else:
                    raise

            if report:
                findings = report.get("findings", [])
                metrics = report.get("metrics") or {}
                if report.get("scan_status") == "error":
                    st.error("Scan failed. A failed scan is not a security pass.")
                elif report.get("scan_status") == "partial":
                    st.warning("Scan completed partially. Uncollected checks are not counted as passes.")

                metric_cols = st.columns(5)
                metric_cols[0].metric("Checks passed", metrics.get("checks_passed", sum(item.get("status") == "pass" for item in findings)))
                metric_cols[1].metric("Findings to review", metrics.get("findings_to_review", 0))
                metric_cols[2].metric("High / critical", metrics.get("high_critical_findings", 0))
                tls_verified = metrics.get("tls_verified")
                metric_cols[3].metric("TLS verification", "Verified" if tls_verified is True else "Not verified" if tls_verified is False else "Not assessed")
                duration = metrics.get("scan_duration_seconds")
                metric_cols[4].metric("Scan duration", f"{duration:.1f} s" if isinstance(duration, (int, float)) else "—")

                st.subheader("Security findings")
                filter_cols = st.columns([2, 2, 2])
                display_statuses = ["Pass", "Warn", "Fail"]
                selected_statuses = filter_cols[0].multiselect("Status", display_statuses, default=display_statuses)
                severity_options = ["Critical", "High", "Medium", "Low", "Info"]
                selected_severities = filter_cols[1].multiselect("Severity", severity_options, default=severity_options)
                filter_cols[2].caption(f"{len(findings)} checks in this profile")
                rows = []
                for item in findings:
                    status = _display_status(item.get("status"))
                    severity = _display_severity(item.get("severity"))
                    if status not in selected_statuses or severity not in selected_severities:
                        continue
                    rows.append({
                        "Check": item.get("check", item.get("check_id", "Check")),
                        "Severity": severity,
                        "Status": status,
                        "Evidence": item.get("evidence", ""),
                        "Recommended fix": item.get("recommendation", ""),
                    })
                st.dataframe(pd.DataFrame(rows, columns=["Check", "Severity", "Status", "Evidence", "Recommended fix"]),
                    hide_index=True, width="stretch")
                with st.expander("Finding flow by status, severity, and check"):
                    _sankey(findings)

                with st.expander("TLS, HTTP, DNS evidence and scan limitations"):
                    evidence_left, evidence_right = st.columns(2)
                    evidence_left.markdown("**TLS**")
                    evidence_left.json((report.get("metadata") or {}).get("tls") or {"status": "TLS evidence unavailable"})
                    evidence_left.markdown("**HTTP**")
                    evidence_left.json((report.get("metadata") or {}).get("http") or {"status": "HTTP evidence unavailable"})
                    evidence_right.markdown("**DNS**")
                    evidence_right.json((report.get("metadata") or {}).get("dns") or {"status": "DNS not collected by this profile"})
                    st.write("Limitations:", report.get("limitations", []))

                with st.expander("Download reports"):
                    downloads = st.columns(2)
                    downloads[0].download_button("Canonical JSON", json.dumps(report, ensure_ascii=False, indent=2),
                        file_name=f"sitesentry-{selected_id}.json", mime="application/json")
                    try:
                        downloads[1].download_button("PDF report", get_pdf_report(selected_id),
                            file_name=f"sitesentry-{selected_id}.pdf", mime="application/pdf")
                    except BackendError as exc:
                        downloads[1].warning(str(exc))
    except BackendError as exc:
        st.error(str(exc))

st.caption("A pass describes only the checks run in the selected profile. It does not prove a website is fully secure.")
