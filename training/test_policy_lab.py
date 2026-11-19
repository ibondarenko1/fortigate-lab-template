import json

from training.policy_lab import _EXERCISE_BY_ID, catalog, grade


def test_catalog_has_three_standalone_exercises_and_json_safe_cases():
    exercises = catalog()
    assert [exercise["id"] for exercise in exercises] == [
        "scoped-http-allow",
        "ordered-exception",
        "custom-tcp-port",
    ]
    assert all(exercise["config"].strip() for exercise in exercises)
    assert all(len(exercise["cases"]) == 2 for exercise in exercises)
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


def test_reference_configs_pass_and_public_starters_are_real_repairs():
    for exercise in catalog():
        reference = _EXERCISE_BY_ID[exercise["id"]].config
        reference_result = grade(exercise["id"], reference)
        starter_result = grade(exercise["id"], exercise["config"])
        assert reference_result["pass"], reference_result
        assert not starter_result["pass"], starter_result
        assert starter_result["summary"]["passed"] < starter_result["summary"]["total"]
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
