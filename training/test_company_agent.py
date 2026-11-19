"""Regression checks for FortiOS monitor results and fixed profile boundaries."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from company_agent import Native


@pytest.mark.parametrize("verdict,expected", [
    ("Access-Accept", True), ("Access-Reject", False), ("Unknown Response", False),
])
def test_radius_access_decision(verdict, expected):
    client = Native.__new__(Native)

    def request(method, path, data):
        assert method == "POST" and path == "/api/v2/monitor/user/radius/test-connect?vdom=root"
        assert data["mkey"] == "LABCO-RADIUS" and data["user"] == "labco.radius.student"
        assert "server" not in data and "secret" not in data
        return {"status": "success", "results": {"status": "ok", "access_status": verdict}}

    client.request = request
    assert client.check_radius("test-only") is expected


@pytest.mark.parametrize("table,name", [
    ("system/admin", "LABCO-ADMIN"), ("user/local", "guest"), ("user/group", "LABCO-FOO/bar")
])
def test_native_guard_refuses_nonprofile_objects(table, name):
    with pytest.raises(ValueError):
        Native.__new__(Native).object_path(table, name)
