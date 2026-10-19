"""Narrow fixed-argument adapters. Active tools require explicit scope approval."""

from __future__ import annotations

import json
from pathlib import Path

from .base import AdapterError, ToolAdapter
from ..url_validation import ValidatedTarget


class OpenSSLAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "openssl", ("openssl.exe", "openssl"), 12

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        if target.port != 443:
            raise AdapterError("OpenSSL adapter supports standard HTTPS only.", code="unsupported_port")
        return [executable, "s_client", "-connect", f"{target.hostname}:443", "-servername", target.hostname,
                "-verify_hostname", target.hostname, "-verify_return_error", "-brief"]

    def parse_output(self, output: str) -> list[dict]:
        return [{"check_id":"tool.openssl.tls","status":"inconclusive","evidence":output[:4000],"limitation":"Diagnostic output; Python ssl remains authoritative."}]

    def version(self, executable: str) -> str:
        return "unknown"


class TestSSLAdapter(ToolAdapter):
    __test__ = False
    name, executable_names, timeout_seconds = "testssl.sh", ("testssl.sh", "testssl"), 120

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable, "--jsonfile=-", "--fast", "--warnings", "off", target.url]

    def parse_output(self, output: str) -> list[dict]:
        rows = json.loads(output)
        if not isinstance(rows, list): raise ValueError("Expected JSON array")
        return [{"check_id":f"tool.testssl.{str(row.get('id','unknown'))[:80]}","status":"inconclusive","evidence":json.dumps(row,ensure_ascii=False)[:2000],"source":self.name} for row in rows if isinstance(row,dict)]

    def version(self, executable: str) -> str:
        return "unknown"


class WhatWebAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "whatweb", ("whatweb", "whatweb.exe"), 30

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable, "--color=never", "--no-errors", "--log-json=-", target.url]

    def parse_output(self, output: str) -> list[dict]:
        rows=[json.loads(line) for line in output.splitlines() if line.strip()]
        if not all(isinstance(row,dict) for row in rows): raise ValueError("Expected JSON objects")
        return [{"check_id":"tool.whatweb.fingerprint","status":"inconclusive","evidence":json.dumps(row,ensure_ascii=False)[:4000],"source":self.name,"limitation":"Fingerprint indicators are not vulnerability proof."} for row in rows]


class Wafw00fAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "wafw00f", ("wafw00f", "wafw00f.exe"), 30

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable, "-a", "-f", "json", target.url]

    def parse_output(self, output: str) -> list[dict]:
        rows=json.loads(output)
        if isinstance(rows,dict): rows=rows.get("results",[rows])
        if not isinstance(rows,list): raise ValueError("Expected JSON results")
        return [{"check_id":"tool.wafw00f.indicator","status":"inconclusive","evidence":json.dumps(row,ensure_ascii=False)[:2000],"source":self.name,"limitation":"WAF presence is indicative, not definitive."} for row in rows if isinstance(row,dict)]


class NmapAdapter(ToolAdapter):
    name, executable_names, timeout_seconds, network_module = "nmap", ("nmap.exe", "nmap"), 60, "network"

    def run(self, target: ValidatedTarget, *, authorization_ref: str | None = None, network_scope_authorized: bool = False):
        if not network_scope_authorized:
            raise AdapterError("Nmap requires explicit network-scope authorization.", code="network_scope_required")
        return super().run(target, authorization_ref=authorization_ref)

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable,"-sT","-T2","--top-ports","20","--open","-oX","-",target.hostname]

    def parse_output(self, output: str) -> list[dict]:
        import xml.etree.ElementTree as ET
        root=ET.fromstring(output)
        return [{"check_id":f"tool.nmap.port.{port.get('portid')}","status":"inconclusive","evidence":ET.tostring(port,encoding="unicode")[:2000],"source":self.name,"limitation":"Network exposure observation; no vulnerability claim."} for port in root.findall(".//port")]


class NiktoAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "nikto", ("nikto.exe", "nikto"), 90

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable,"-host",target.url,"-output","-","-Format","json"]

    def parse_output(self, output: str) -> list[dict]:
        payload=json.loads(output)
        rows=payload.get("vulnerabilities",payload if isinstance(payload,list) else [])
        if not isinstance(rows,list): raise ValueError("Expected vulnerability list")
        return [{"check_id":"tool.nikto.observation","status":"inconclusive","evidence":json.dumps(row,ensure_ascii=False)[:2000],"source":self.name} for row in rows]


class NucleiAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "nuclei", ("nuclei.exe", "nuclei"), 90

    def __init__(self, *, allowed_domains: set[str], template_dir: str, executable_dir: str | None = None):
        super().__init__(allowed_domains=allowed_domains, executable_dir=executable_dir)
        path=Path(template_dir).resolve()
        templates=list(path.rglob("*.yaml")) if path.is_dir() else []
        if not templates or any(("exploit" in item.read_text(encoding="utf-8",errors="ignore").lower() or "intrusive" in item.read_text(encoding="utf-8",errors="ignore").lower()) for item in templates):
            raise ValueError("Nuclei requires a non-empty curated template directory.")
        self.template_dir=str(path)

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable,"-u",target.url,"-t",self.template_dir,"-jsonl","-silent"]

    def parse_output(self, output: str) -> list[dict]:
        rows=[json.loads(line) for line in output.splitlines() if line.strip()]
        if not all(isinstance(row,dict) for row in rows): raise ValueError("Expected JSONL objects")
        return [{"check_id":f"tool.nuclei.{str(row.get('template-id','unknown'))[:80]}","status":"inconclusive","evidence":json.dumps(row,ensure_ascii=False)[:3000],"source":self.name,"limitation":"Template result needs rule validation before a finding is asserted."} for row in rows]


class SslyzeAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "sslyze", ("sslyze.exe", "sslyze"), 90

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable,"--json_out=-",f"{target.hostname}:443"]

    def parse_output(self, output: str) -> list[dict]:
        payload=json.loads(output)
        if not isinstance(payload,dict): raise ValueError("Expected JSON object")
        return [{"check_id":"tool.sslyze.tls","status":"inconclusive","evidence":json.dumps(payload,ensure_ascii=False)[:6000],"source":self.name}]


class ZapAdapter(ToolAdapter):
    name, executable_names, timeout_seconds = "zap-baseline", ("zap-baseline.py", "zap-baseline.bat"), 120

    def build_argv(self, executable: str, target: ValidatedTarget) -> list[str]:
        return [executable,"-t",target.url,"-J","-"]

    def parse_output(self, output: str) -> list[dict]:
        payload=json.loads(output)
        sites=payload.get("site",[])
        if not isinstance(sites,list): raise ValueError("Expected ZAP sites")
        findings=[]
        for site in sites:
            for alert in site.get("alerts",[]):
                findings.append({"check_id":f"tool.zap.{str(alert.get('pluginid','unknown'))[:80]}","status":"inconclusive","evidence":json.dumps(alert,ensure_ascii=False)[:3000],"source":self.name,"limitation":"Scanner alert is not confirmed vulnerability evidence."})
        return findings
