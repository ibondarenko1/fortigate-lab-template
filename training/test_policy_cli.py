import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "training" / "policy_cli.py"
SCENARIOS = ROOT / "training" / "scenarios"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_lists_fixed_snapshot_paths():
    result = run_cli("list")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    bundle_ids = {
        path.name for path in SCENARIOS.iterdir()
        if path.is_dir() and (path / "scenario.json").is_file()
    }
    listed_ids = {item["id"] for item in payload["scenarios"]}
    assert listed_ids == bundle_ids
    assert {"scoped-http-allow", "ordered-exception", "custom-tcp-port"} <= listed_ids
    for item in payload["scenarios"]:
        assert item["starter"] == f"{item['id']}/starter.conf"
        assert item["reference"] == f"{item['id']}/reference.conf"


def test_cli_grade_has_nonpassing_exit_for_starter_and_success_for_reference():
    starter = SCENARIOS / "ordered-exception" / "starter.conf"
    reference = SCENARIOS / "ordered-exception" / "reference.conf"
    failed = run_cli("grade", "ordered-exception", str(starter))
    passed = run_cli("grade", "ordered-exception", str(reference))
    assert failed.returncode == 1
    assert json.loads(failed.stdout)["pass"] is False
    assert passed.returncode == 0
    assert json.loads(passed.stdout)["pass"] is True


def test_cli_grade_returns_two_for_unknown_scenario_or_invalid_config(tmp_path):
    starter = SCENARIOS / "ordered-exception" / "starter.conf"
    unknown = run_cli("grade", "not-a-scenario", str(starter))
    assert unknown.returncode == 2
    assert json.loads(unknown.stdout)["errors"][0]["code"] == "unknown_exercise"

    invalid_config = tmp_path / "invalid.conf"
    invalid_config.write_text("config firewall policy\n", encoding="utf-8")
    invalid = run_cli("grade", "ordered-exception", str(invalid_config))
    assert invalid.returncode == 2
    assert json.loads(invalid.stdout)["errors"]


def test_cli_compare_fail_on_change_and_invalid_snapshot_exit_codes():
    before = SCENARIOS / "custom-tcp-port" / "reference.conf"
    after = SCENARIOS / "custom-tcp-port" / "starter.conf"
    changed = run_cli("compare", "custom-tcp-port", str(before), str(after), "--fail-on-change")
    stable = run_cli("compare", "custom-tcp-port", str(before), str(before), "--fail-on-change")
    invalid = run_cli("compare", "custom-tcp-port", str(before), str(ROOT / "missing.conf"))
    assert changed.returncode == 1
    assert json.loads(changed.stdout)["summary"]["changed"] == 2
    assert stable.returncode == 0
    assert json.loads(stable.stdout)["summary"]["changed"] == 0
    assert invalid.returncode == 2
    assert json.loads(invalid.stdout)["errors"][0]["code"] == "invalid_input"


def test_cli_loads_relative_external_scenario_dir(tmp_path):
    external_root = tmp_path / "my-scenarios"
    external_bundle = external_root / "community-fourth"
    shutil.copytree(SCENARIOS / "scoped-http-allow", external_bundle)
    manifest_path = external_bundle / "scenario.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["id"] = "community-fourth"
    manifest["title"] = "Community fourth scenario"
    extra_case = dict(manifest["flows"][0])
    extra_case["id"] = "community-outside-client-blocked"
    extra_case["description"] = "The external bundle also grades its implicit boundary."
    manifest["cases"].append(extra_case)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    cwd = tmp_path / "work"
    cwd.mkdir()

    result = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--scenario-dir",
            "../my-scenarios",
            "list",
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload["scenarios"]] == ["community-fourth"]
    assert payload["scenarios"][0]["starter"] == "community-fourth/starter.conf"

    grade = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--scenario-dir",
            "../my-scenarios",
            "grade",
            "community-fourth",
            str(external_bundle / "reference.conf"),
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    assert grade.returncode == 0, grade.stderr
    grade_payload = json.loads(grade.stdout)
    assert grade_payload["pass"] is True
    assert grade_payload["summary"]["total"] == 3
