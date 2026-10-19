from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from scanner.tool_adapters.base import AdapterError, ToolAdapter, reconcile_observations
from scanner.tool_adapters.tools import NmapAdapter, NucleiAdapter, OpenSSLAdapter, TestSSLAdapter, WhatWebAdapter
from scanner.url_validation import ValidatedTarget


TARGET=ValidatedTarget("https://example.com/","example.com",443,("93.184.216.34",))


def test_external_tool_requires_domain_and_authorization():
    with pytest.raises(ValueError): OpenSSLAdapter(allowed_domains=set())
    with pytest.raises(ValueError): OpenSSLAdapter(allowed_domains={"example.com"})
    adapter=OpenSSLAdapter(allowed_domains={"example.com"},executable_dir=str(Path(__file__).parent))
    with pytest.raises(AdapterError) as caught: adapter.run(TARGET)
    assert caught.value.code=="authorization_required"


def test_network_tool_needs_explicit_network_permission():
    adapter=NmapAdapter(allowed_domains={"example.com"},executable_dir=str(Path(__file__).parent))
    with pytest.raises(AdapterError) as caught: adapter.run(TARGET,authorization_ref="approved")
    assert caught.value.code=="network_scope_required"


def test_nuclei_requires_curated_templates(tmp_path):
    with pytest.raises(ValueError): NucleiAdapter(allowed_domains={"example.com"},template_dir=str(tmp_path))
    (tmp_path/"safe.yaml").write_text("id: reviewed\ninfo:\n  name: harmless config observation\n",encoding="utf-8")
    adapter=NucleiAdapter(allowed_domains={"example.com"},template_dir=str(tmp_path),executable_dir=str(tmp_path))
    args=adapter.build_argv("/bin/nuclei",TARGET)
    assert args[args.index("-t")+1]==str(tmp_path.resolve())


def test_tool_json_and_xml_parsers():
    adapter=WhatWebAdapter(allowed_domains={"example.com"},executable_dir=str(Path(__file__).parent))
    assert adapter.parse_output('{"target":"https://example.com","plugins":{}}')[0]["status"]=="inconclusive"
    with pytest.raises(Exception): adapter.parse_output("not json")


def test_conflicting_tool_observations_are_preserved():
    rows=reconcile_observations([{"check_id":"tls.protocol","status":"finding","source":"a","evidence":"TLS1.0"},{"check_id":"tls.protocol","status":"pass","source":"b","evidence":"TLS1.2"}])
    assert rows[0]["status"]=="inconclusive" and rows[0]["conflict"] is True and len(rows[0]["sources"])==2


def test_adapter_rejects_path_lookup_without_explicit_directory():
    with pytest.raises(ValueError,match="explicit executable directory"):
        WhatWebAdapter(allowed_domains={"example.com"})


def test_tool_execution_is_fixed_shell_false_and_bounded(tmp_path,monkeypatch):
    if os.name=="nt":
        pytest.skip("Windows command wrappers are intentionally not executed with a shell")
    script=tmp_path/"whatweb"
    script.write_text(f"#!{sys.executable}\nprint('not json')\n",encoding="utf-8"); script.chmod(0o755)
    adapter=WhatWebAdapter(allowed_domains={"example.com"},executable_dir=str(tmp_path))
    result=adapter.run(TARGET,authorization_ref="approved")
    assert result.status=="error" and result.error_code=="parser_failed"


def test_tool_timeout(tmp_path):
    if os.name=="nt": pytest.skip("Windows command wrappers are intentionally not executed with a shell")
    script=tmp_path/"whatweb"; script.write_text(f"#!{sys.executable}\nimport time; time.sleep(1)\n",encoding="utf-8"); script.chmod(0o755)
    adapter=WhatWebAdapter(allowed_domains={"example.com"},executable_dir=str(tmp_path)); adapter.timeout_seconds=0.05
    result=adapter.run(TARGET,authorization_ref="approved")
    assert result.error_code=="tool_timeout"


def test_tool_nonzero_exit_is_error(tmp_path):
    if os.name=="nt": pytest.skip("Windows command wrappers are intentionally not executed with a shell")
    script=tmp_path/"whatweb"; script.write_text(f"#!{sys.executable}\nimport sys; sys.exit(7)\n",encoding="utf-8"); script.chmod(0o755)
    result=WhatWebAdapter(allowed_domains={"example.com"},executable_dir=str(tmp_path)).run(TARGET,authorization_ref="approved")
    assert result.status=="error" and result.error_code=="tool_nonzero_exit"
