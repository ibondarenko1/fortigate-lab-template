"""Tests for the redacted native forwarding evidence report."""

from __future__ import annotations

import json
import math
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace

from deploy.scripts.forwarding_evidence import _probe as run_probe, _report, build_report


ROOT = Path(__file__).resolve().parents[1]


def _probe(probe_id: str, port: int, source_port: int, *, result: str = "failed", local_service: str = "ready") -> dict[str, object]:
    record = {
        "schema_version": 1,
        "probe_id": probe_id,
        "started_at": "2026-11-25T22:00:00.000Z",
        "finished_at": "2026-11-25T22:00:01.000Z",
        "source_ip": "10.231.31.10",
        "source_port": source_port,
        "destination_ip": "10.231.32.10",
        "destination_port": port,
        "protocol": "tcp",
        "result": result,
        "local_service": local_service,
        "expected": "allow" if port == 80 else "deny",
    }
    if result == "connected":
        record.update(http_status=200, body_match=True)
    return record


def _log(port: int, source_port: int, action: str, policy_id: int, eventtime: object = "1795644000500000000") -> dict[str, object]:
    return {
        "eventtime": eventtime,
        "srcip": "10.231.31.10",
        "srcport": str(source_port),
        "dstip": "10.231.32.10",
        "dstport": str(port),
        "proto": "6",
        "type": "traffic",
        "subtype": "forward",
        "action": action,
        "policyid": str(policy_id),
        "password": "must not be copied to a report",
        "serial": "must not be copied to a report",
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def test_report_matches_allow_deny_and_implicit_deny_from_fortios_types(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.json"
    _write_json(probes, [_probe("http", 80, 41080, result="connected"), _probe("deny", 8080, 41081), _probe("implicit", 8443, 41082)])
    _write_json(logs, {"status": "success", "version": "v7.6.8", "build": 3744, "results": [_log(80, 41080, "close", 1), _log(8080, 41081, "deny", 2), _log(8443, 41082, "deny", "0")]})

    report = build_report(probes, logs, fortios_timezone="UTC")
    assert not report["errors"]
    assert [flow["verification"] for flow in report["flows"]] == ["allow_with_evidence", "explicit_deny", "implicit_deny"]
    assert report["flows"][0]["log"]["protocol"] == "tcp"
    assert report["flows"][1]["log"]["policy_id"] == 2
    assert report["flows"][2]["log"]["policy_id"] == 0
    assert report["fortios"] == {"status": "success", "version": "v7.6.8", "build": 3744}
    encoded = json.dumps(report)
    assert "password" not in encoded
    assert "serial" not in encoded


def test_eventtime_nanoseconds_and_date_time_are_normalized(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    _write_json(probes, [_probe("http", 80, 41080, result="connected")])
    logs.write_text(
        json.dumps({**_log(80, 41080, "accept", 1), "eventtime": None, "date": "2026-11-25", "time": "22:00:00"}) + "\n",
        encoding="utf-8",
    )
    report = build_report(probes, logs, fortios_timezone="UTC")
    assert not report["errors"]
    assert report["flows"][0]["verification"] == "allow_with_evidence"
    assert report["flows"][0]["log"]["timestamp_source"] == "date_time"


def test_date_time_without_timezone_is_an_input_error(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    _write_json(probes, [_probe("http", 80, 41080, result="connected")])
    logs.write_text(json.dumps({**_log(80, 41080, "accept", 1), "eventtime": None, "date": "2026-11-25", "time": "22:00:00"}) + "\n", encoding="utf-8")
    report = build_report(probes, logs)
    assert report["errors"][0]["code"] == "log_time_zone"
    assert report["flows"][0]["verification"] == "missing_forward_log"


def test_missing_log_does_not_turn_timeout_into_a_deny(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    _write_json(probes, [_probe("stopped", 8080, 41080, local_service="unavailable")])
    report = build_report(probes, None)
    assert not report["errors"]
    assert report["flows"][0]["verification"] == "local_service_unavailable"
    _write_json(probes, [_probe("ready-no-log", 8080, 41080)])
    report = build_report(probes, None)
    assert report["flows"][0]["verification"] == "missing_forward_log"


def test_conflicting_nearby_logs_are_ambiguous(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    _write_json(probes, [_probe("ambiguous", 80, 41080, result="connected")])
    logs.write_text("\n".join(json.dumps(_log(80, 41080, action, policy)) for action, policy in (("close", 1), ("deny", 2))) + "\n", encoding="utf-8")
    report = build_report(probes, logs)
    assert not report["errors"]
    assert report["flows"][0]["verification"] == "ambiguous_forward_log"
    assert report["flows"][0]["log"] is None


def test_http_and_expected_policy_controls_block_false_acceptance(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    bad_http = _probe("http-bad", 80, 41080, result="connected")
    bad_http["body_match"] = False
    bad_policy = _probe("wrong-policy", 80, 41081, result="connected")
    bad_policy["expected_policy_id"] = 99
    _write_json(probes, [bad_http, bad_policy])
    logs.write_text(
        "\n".join(json.dumps(_log(80, port, "close", 1)) for port in (41080, 41081)) + "\n",
        encoding="utf-8",
    )
    report = build_report(probes, logs)
    assert [flow["verification"] for flow in report["flows"]] == ["probe_http_mismatch", "unexpected_policy"]


def test_unknown_service_and_probe_result_cannot_confirm_policy_outcome(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    unknown_service = _probe("unknown-service", 8080, 41080, local_service="unknown")
    unknown_service["expected"] = "unknown"
    failed_allow = _probe("failed-allow", 80, 41081, local_service="ready")
    failed_allow["expected"] = "unknown"
    _write_json(probes, [unknown_service, failed_allow])
    logs.write_text(
        "\n".join(
            (
                json.dumps(_log(8080, 41080, "deny", 2)),
                json.dumps(_log(80, 41081, "close", 1)),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    report = build_report(probes, logs)
    assert [flow["verification"] for flow in report["flows"]] == ["service_readiness_unknown", "log_outcome_mismatch"]


def test_invalid_status_negative_policy_and_nan_time_never_verify(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.json"
    _write_json(probes, [_probe("deny", 8080, 41080)])
    _write_json(logs, {"status": "error", "results": [_log(8080, 41080, "deny", -1)]})
    report = build_report(probes, logs)
    assert report["errors"]
    assert report["flows"][0]["verification"] == "missing_forward_log"

    _write_json(logs, {"status": "success", "results": [_log(8080, 41080, "deny", 2, eventtime="NaN")]})
    report = build_report(probes, logs)
    assert report["errors"]
    assert report["flows"][0]["verification"] == "missing_forward_log"


def test_strict_report_requires_policy_evidence_and_allows_known_listener_control(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    policy = _probe("deny", 8080, 41080)
    policy["expected_policy_id"] = 2
    control = _probe("stopped", 18081, 41081, local_service="stopped")
    control["expected"] = "unknown"
    _write_json(probes, [policy, control])
    logs.write_text(json.dumps(_log(8080, 41080, "deny", 2)) + "\n", encoding="utf-8")
    output = tmp_path / "report.json"
    args = SimpleNamespace(probes=str(probes), logs=str(logs), output=str(output), skew=10.0, fortios_timezone=None, require_verified=True)
    assert _report(args) == 0

    policy.pop("expected_policy_id")
    _write_json(probes, [policy, control])
    assert _report(args) == 1


def test_skew_must_be_finite():
    try:
        build_report(Path("missing-probes.jsonl"), None, math.nan)
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("NaN skew was accepted")


def test_probe_reads_fragmented_http_headers_and_body(capsys):
    body = b"fortigate-lab dmz service\n"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        connection, unused = listener.accept()
        try:
            connection.recv(1024)
            header = f"HTTP/1.0 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            connection.sendall(header[:11])
            time.sleep(0.01)
            connection.sendall(header[11:] + body[:8])
            time.sleep(0.01)
            connection.sendall(body[8:])
        finally:
            connection.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        run_probe(SimpleNamespace(
            probe_id="fragmented",
            source_ip="127.0.0.1",
            source_port=0,
            destination="127.0.0.1",
            port=port,
            timeout=2.0,
            local_service="ready",
            expected="allow",
            expected_policy_id=None,
            expected_body="fortigate-lab dmz service",
        ))
        record = json.loads(capsys.readouterr().out)
        assert record["result"] == "connected"
        assert record["http_status"] == 200
        assert record["body_match"] is True
    finally:
        listener.close()
        thread.join(timeout=2)


def test_non_forward_logs_are_ignored_and_malformed_records_are_reported(tmp_path: Path):
    probes = tmp_path / "probes.jsonl"
    logs = tmp_path / "logs.jsonl"
    _write_json(probes, [_probe("http", 80, 41080, result="connected")])
    logs.write_text(
        "\n".join(
            (
                json.dumps({**_log(80, 41080, "close", 1), "subtype": "local"}),
                "not json",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    report = build_report(probes, logs)
    assert report["flows"][0]["verification"] == "missing_forward_log"
    assert report["errors"][0]["code"] == "invalid_json"


def test_shipped_examples_are_reportable():
    report = build_report(
        ROOT / "deploy/examples/forwarding/probes.jsonl",
        ROOT / "deploy/examples/forwarding/forward-logs.jsonl",
    )
    assert not report["errors"]
    assert [flow["verification"] for flow in report["flows"]] == [
        "allow_with_evidence",
        "explicit_deny",
        "implicit_deny",
        "local_service_unavailable",
    ]
    api_report = build_report(
        ROOT / "deploy/examples/forwarding/probes.jsonl",
        ROOT / "deploy/examples/forwarding/fortios-forward-response.json",
    )
    assert not api_report["errors"]
    assert api_report["fortios"] == {"status": "success", "version": "v7.6.8", "build": 3744}
