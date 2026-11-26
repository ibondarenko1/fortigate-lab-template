"""Exercise log export boundaries and replay the published native capture."""

import json
from pathlib import Path
import runpy
from urllib.request import Request

import pytest

from deploy.scripts.forwarding_evidence import build_report


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "deploy/examples/forwarding/fortios-7.6.8"


def test_export_keeps_only_the_requested_tcp_connection_and_public_fields(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    exporter = runpy.run_path(str(ROOT / "scripts/export-forward-logs.py"))
    capture = json.loads((CAPTURE / "forward-traffic.json").read_text(encoding="utf-8"))
    target = capture["results"][0]
    assert target["dstport"] == 80
    received = []

    def fetch(filters):
        received.extend(filters)
        return {**capture, "results": [{**target, "serial": "example-device"}, *capture["results"][1:]]}

    key = target["srcip"], target["srcport"], target["dstip"], target["dstport"]
    result = exporter["export"]([key], fetch)
    assert result["results"] == [target]
    assert set(received) == {("filter", f"{field}=={target[field]}") for field in
                             ("srcip", "srcport", "dstip", "dstport", "proto")}
    with pytest.raises(ValueError, match="incomplete"):
        exporter["export"]([key], lambda _: {**capture, "completed": False})
    with pytest.raises(ValueError, match="outside its configured origin"):
        exporter["SameOriginRedirects"]().redirect_request(
            Request("https://firewall.example/api"), None, 302, "", {}, "https://elsewhere.example/")


def test_published_native_capture_reproduces_the_report():
    report = build_report(CAPTURE / "probes.jsonl", CAPTURE / "forward-traffic.json")
    published = json.loads((CAPTURE / "report.json").read_text(encoding="utf-8"))
    for record in (report, published):
        record.pop("generated_at")
    assert report == published
    assert report["errors"] == []
    assert report["fortios"]["build"] == 3744
    assert [row["verification"] for row in report["flows"]] == [
        "allow_with_evidence", "explicit_deny", "local_service_unavailable",
    ]
