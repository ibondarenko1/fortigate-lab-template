import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from training.policy_lab import _EXERCISE_BY_ID
from training.server import Worksheet


def _server():
    instance = ThreadingHTTPServer(("127.0.0.1", 0), Worksheet)
    instance.native = "https://127.0.0.1:18843/"
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    return instance, thread


def _post(instance, path, payload):
    connection = HTTPConnection("127.0.0.1", instance.server_port, timeout=3)
    body = json.dumps(payload).encode("utf-8")
    connection.request(
        "POST",
        path,
        body,
        {"Host": f"127.0.0.1:{instance.server_port}", "Content-Type": "application/json"},
    )
    response = connection.getresponse()
    data = json.loads(response.read())
    connection.close()
    return response.status, data


def test_compare_endpoint_returns_stable_flow_and_scope_report():
    instance, thread = _server()
    try:
        exercise = _EXERCISE_BY_ID["scoped-http-allow"]
        before = exercise.config
        after = before.replace("set subnet 10.231.31.10 255.255.255.255", "set subnet 0.0.0.0 0.0.0.0")
        status, result = _post(
            instance,
            "/training/api/compare",
            {"exercise_id": "scoped-http-allow", "before": before, "after": after},
        )
        assert status == 200
        assert result["schema_version"] == 1
        assert result["summary"]["total"] >= 2
        assert result["summary"]["changed"] >= 1
        assert any(item["kind"] == "address" for item in result["scope_changes"])
        assert any(flow["changed"] for flow in result["flows"])
    finally:
        instance.shutdown()
        thread.join(timeout=3)
        instance.server_close()


def test_compare_endpoint_reports_invalid_revision_side_without_partial_flows():
    instance, thread = _server()
    try:
        status, result = _post(
            instance,
            "/training/api/compare",
            {
                "exercise_id": "scoped-http-allow",
                "before": "config firewall policy\n    edit 10\n",
                "after": _EXERCISE_BY_ID["scoped-http-allow"].config,
            },
        )
        assert status == 200
        assert result["flows"] == []
        assert any(error["side"] == "before" for error in result["errors"])
    finally:
        instance.shutdown()
        thread.join(timeout=3)
        instance.server_close()
