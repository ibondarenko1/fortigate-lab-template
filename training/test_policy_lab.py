import json
import re
import shutil
from pathlib import Path

import pytest

from training.policy_lab import _EXERCISE_BY_ID, catalog, compare, grade, load_scenarios


SCENARIO_ROOT = Path(__file__).resolve().parent / "scenarios"


def test_catalog_matches_bundle_dirs_and_retains_original_exercises():
    exercises = catalog()
    bundle_ids = {
        path.name for path in SCENARIO_ROOT.iterdir()
        if path.is_dir() and (path / "scenario.json").is_file()
    }
    catalog_ids = {exercise["id"] for exercise in exercises}
    assert catalog_ids == bundle_ids
    assert {
        "scoped-http-allow",
        "ordered-exception",
        "custom-tcp-port",
    } <= catalog_ids
    assert len(catalog_ids) >= 3
    assert all(exercise["config"].strip() for exercise in exercises)
    assert all(exercise["cases"] for exercise in exercises)
    assert all(exercise["title"] for exercise in exercises)
    assert all(exercise["description"] for exercise in exercises)
    assert all(exercise["task_prompt"] for exercise in exercises)
    assert all(exercise["help"] for exercise in exercises)
    assert all(exercise["firewall_policy_limit"] == 3 for exercise in exercises)
    json.dumps(exercises)

    def contains_russian(value):
        if isinstance(value, dict):
            return any(contains_russian(key) or contains_russian(item) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return any(contains_russian(item) for item in value)
        return isinstance(value, str) and any("\u0400" <= char <= "\u052f" for char in value)

    assert not contains_russian(exercises)


def test_load_scenarios_accepts_a_valid_fourth_contributor_bundle(tmp_path):
    target = tmp_path / "community-fourth"
    shutil.copytree(SCENARIO_ROOT / "scoped-http-allow", target)
    manifest_path = target / "scenario.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["id"] = "community-fourth"
    manifest["title"] = "Community fourth scenario"
    extra_case = dict(manifest["flows"][0])
    extra_case["id"] = "community-outside-client-blocked"
    extra_case["description"] = "The fourth bundle also exercises its implicit boundary as a graded case."
    manifest["cases"].append(extra_case)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_scenarios(tmp_path)

    assert [exercise.exercise_id for exercise in loaded] == ["community-fourth"]
    assert len(loaded[0].cases) == 3
    assert loaded[0].config.strip()
    assert loaded[0].starter_config.strip()


@pytest.mark.parametrize("invalid_kind", ["reference", "expected-policy", "passing-starter"])
def test_load_scenarios_rejects_invalid_contributor_bundle(tmp_path, invalid_kind):
    target = tmp_path / "invalid-bundle"
    shutil.copytree(SCENARIO_ROOT / "scoped-http-allow", target)
    manifest_path = target / "scenario.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["id"] = "invalid-bundle"
    if invalid_kind == "expected-policy":
        manifest["cases"][0]["expected_policy"] = 999
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    elif invalid_kind == "reference":
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (target / "reference.conf").write_text("config firewall policy\n", encoding="utf-8")
    else:
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (target / "starter.conf").write_text(
            (target / "reference.conf").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    with pytest.raises(ValueError):
        load_scenarios(tmp_path)


@pytest.mark.parametrize("bad_id", ["bad id", "../escape"])
def test_load_scenarios_rejects_non_kebab_case_ids(tmp_path, bad_id):
    target = tmp_path / "invalid-bundle"
    shutil.copytree(SCENARIO_ROOT / "scoped-http-allow", target)
    manifest_path = target / "scenario.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["id"] = bad_id
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="lowercase kebab-case"):
        load_scenarios(tmp_path)


def test_reference_configs_pass_and_public_starters_are_real_repairs():
    for exercise in catalog():
        reference = _EXERCISE_BY_ID[exercise["id"]].config
        reference_result = grade(exercise["id"], reference)
        starter_result = grade(exercise["id"], exercise["config"])
        assert reference_result["pass"], reference_result
        assert not starter_result["pass"], starter_result
        assert (
            any(not case["pass"] for case in starter_result["cases"])
            or any(not flow["pass"] for flow in starter_result.get("boundaries", []))
        )
        json.dumps(reference_result)
        json.dumps(starter_result)


def test_each_public_starter_fails_for_its_named_repair_reason():
    scoped = next(item for item in catalog() if item["id"] == "scoped-http-allow")
    scoped_result = grade(scoped["id"], scoped["config"])
    assert scoped_result["cases"][1]["actual_rule_identity"] is None
    assert "implicit default deny" in scoped_result["cases"][1]["feedback"]

    ordered = next(item for item in catalog() if item["id"] == "ordered-exception")
    ordered_result = grade(ordered["id"], ordered["config"])
    assert ordered_result["cases"][0]["actual_rule_identity"]["id"] == 20
    assert "policy order" in ordered_result["cases"][0]["feedback"]

    custom = next(item for item in catalog() if item["id"] == "custom-tcp-port")
    custom_result = grade(custom["id"], custom["config"])
    assert custom_result["cases"][0]["actual_rule_identity"] is None
    assert "implicit default deny" in custom_result["cases"][0]["feedback"]


def test_custom_port_reference_stays_within_three_policy_trial_limit():
    reference = _EXERCISE_BY_ID["custom-tcp-port"].config
    policy_block = reference.split("config firewall policy", 1)[1]
    policy_count = policy_block.count("\n    edit ")
    assert policy_count == 2
    assert policy_count <= 3


def test_scoped_http_requires_explicit_deny_not_implicit_default():
    exercise = next(item for item in catalog() if item["id"] == "scoped-http-allow")
    without_deny = _EXERCISE_BY_ID[exercise["id"]].config.replace(
        '    edit 20\n'
        '        set name "DENY-LAN-SSH"\n'
        '        set srcintf "port2"\n'
        '        set dstintf "port3"\n'
        '        set srcaddr "LAN-CLIENT"\n'
        '        set dstaddr "DMZ-WEB"\n'
        '        set action deny\n'
        '        set schedule "always"\n'
        '        set service "SSH"\n'
        '        set logtraffic all\n'
        "    next\n",
        "",
    )
    result = grade(exercise["id"], without_deny)
    assert not result["pass"]
    denied = result["cases"][1]
    assert denied["actual_rule_identity"] is None
    assert "implicit default deny" in denied["feedback"]


def test_ordered_exception_fails_if_broad_allow_is_moved_first():
    exercise = next(item for item in catalog() if item["id"] == "ordered-exception")
    config = _EXERCISE_BY_ID[exercise["id"]].config
    first = config.index("    edit 10\n")
    second = config.index("    edit 20\n")
    first_block = config[first:second]
    second_end = config.index("    next\n", second) + len("    next\n")
    second_block = config[second:second_end]
    swapped = config[:first] + second_block + first_block + config[second_end:]
    result = grade(exercise["id"], swapped)
    assert not result["pass"]
    restricted = result["cases"][0]
    assert restricted["actual_rule_identity"]["id"] == 20
    assert "policy order" in restricted["feedback"]


def test_custom_tcp_service_is_used_and_wrong_port_is_not_extrapolated():
    exercise = next(item for item in catalog() if item["id"] == "custom-tcp-port")
    result = grade(
        exercise["id"],
        _EXERCISE_BY_ID[exercise["id"]].config.replace("8081", "8082"),
    )
    assert not result["pass"]
    allowed = result["cases"][0]
    assert allowed["actual_rule_identity"] is None
    assert "implicit default deny" in allowed["feedback"]


def test_broad_catch_all_deny_does_not_satisfy_scoped_explicit_deny():
    exercise = next(item for item in catalog() if item["id"] == "scoped-http-allow")
    broad = _EXERCISE_BY_ID[exercise["id"]].config.replace(
        'set srcaddr "LAN-CLIENT"\n        set dstaddr "DMZ-WEB"\n        set action deny\n        set schedule "always"\n        set service "SSH"',
        'set srcaddr "all"\n        set dstaddr "all"\n        set action deny\n        set schedule "always"\n        set service "ALL"',
    )
    result = grade(exercise["id"], broad)
    assert not result["pass"]
    denied = result["cases"][1]
    assert denied["actual_rule_identity"]["id"] == 20
    assert "scope differs" in denied["feedback"]


def test_unsupported_operations_are_explicit_and_fail_closed():
    exercise = catalog()[0]
    unsupported = _EXERCISE_BY_ID[exercise["id"]].config.replace(
        "config firewall policy",
        "config system admin\n    edit admin\n        set password bad\n    next\nend\nconfig firewall policy",
    )
    result = grade(exercise["id"], unsupported)
    assert not result["pass"]
    assert any(error["code"] == "unsupported_operation" for error in result["errors"])
    assert any("system admin" in error["message"] for error in result["errors"])


def test_no_network_or_credential_commands_are_interpreted():
    exercise = catalog()[0]
    hostile = _EXERCISE_BY_ID[exercise["id"]].config + "\nexecute ping 10.231.32.10\n"
    result = grade(exercise["id"], hostile)
    assert not result["pass"]
    assert any(error["code"] == "unsupported_operation" for error in result["errors"])
    assert any("execute" in error["message"] for error in result["errors"])


def test_unknown_exercise_and_bad_input_remain_json_serializable():
    unknown = grade("missing", "")
    bad_input = grade("scoped-http-allow", None)
    assert unknown["pass"] is False
    assert bad_input["pass"] is False
    json.dumps(unknown)
    json.dumps(bad_input)


def test_broadened_address_scope_does_not_pass_the_scoped_exercise():
    exercise = _EXERCISE_BY_ID["scoped-http-allow"]
    broadened = re.sub(
        r"(?m)^([ \t]*set subnet) .+$",
        r"\1 0.0.0.0 0.0.0.0",
        exercise.config,
    )
    result = grade(exercise.exercise_id, broadened)
    assert not result["pass"]
    assert result["summary"]["passed"] == 0
    assert all("scope differs" in case["feedback"] for case in result["cases"])


def test_broadened_custom_service_does_not_pass_the_port_exercise():
    exercise = _EXERCISE_BY_ID["custom-tcp-port"]
    broadened = exercise.config.replace(
        "set tcp-portrange 8081",
        "set tcp-portrange 8081-65535",
    )
    result = grade(exercise.exercise_id, broadened)
    assert not result["pass"]
    assert "scope differs" in result["cases"][0]["feedback"]


def test_appended_broad_allow_fails_declared_implicit_boundaries():
    exercise = _EXERCISE_BY_ID["scoped-http-allow"]
    broad = exercise.config + '''
config firewall policy
    edit 99
        set name "ACCIDENTAL-BROAD-ALLOW"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
'''
    result = grade(exercise.exercise_id, broad)
    assert not result["pass"]
    assert any(not boundary["pass"] for boundary in result["boundaries"])
    assert result["summary"]["boundary_passed"] < result["summary"]["boundary_total"]


def test_compare_reports_flow_and_scope_changes_with_stable_contract():
    exercise = _EXERCISE_BY_ID["custom-tcp-port"]
    result = compare(exercise.exercise_id, exercise.config, exercise.starter_config)
    assert result["schema_version"] == 1
    assert result["errors"] == []
    assert result["summary"] == {"total": 5, "changed": 2}
    assert result["flows"][0]["changed"] is True
    assert result["flows"][2]["changed"] is True
    assert result["flows"][3]["changed"] is False
    assert {
        "kind": "service",
        "name": "LAB-API-TCP",
        "before": [[8081, 8081]],
        "after": [[8080, 8080]],
    } in result["scope_changes"]
    assert any(change["kind"] == "policy" and change["name"] == "10" for change in result["scope_changes"])
    json.dumps(result)


def test_compare_rejects_invalid_snapshot_without_partial_flow_results():
    exercise = _EXERCISE_BY_ID["scoped-http-allow"]
    result = compare(exercise.exercise_id, exercise.config, "config firewall policy\n")
    assert result["errors"]
    assert all(error["side"] == "after" for error in result["errors"])
    assert result["flows"] == []
    assert result["summary"] == {"total": 0, "changed": 0}


def test_compare_reports_policy_edit_even_when_sampled_flows_are_unchanged():
    exercise = _EXERCISE_BY_ID["scoped-http-allow"]
    edited = exercise.config + '''
config firewall service custom
    edit "UNSAMPLED-TCP"
        set tcp-portrange 9999
    next
end
config firewall policy
    edit 99
        set name "UNSAMPLED-EDIT"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "UNSAMPLED-TCP"
        set logtraffic all
    next
end
'''
    result = compare(exercise.exercise_id, exercise.config, edited)
    assert result["summary"]["changed"] == 0
    assert any(change["kind"] == "policy" and change["name"] == "99" for change in result["scope_changes"])
    assert not any(change["kind"] == "flow" for change in result["scope_changes"])
