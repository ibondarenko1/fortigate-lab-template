"""Offline validator for a deliberately small FortiOS policy-learning subset.

This module never opens a socket, contacts a device, evaluates CLI input, or
handles credentials. It parses only native FortiOS config snippets for:

* IPv4 address objects with set subnet;
* custom TCP services with set tcp-portrange; and
* ordered IPv4 firewall policies.

The exercises are intentionally finite. A passing answer must select the
expected first matching rule with the expected scope. An implicit default
deny, a differently scoped catch-all, or a policy with the wrong order cannot
pass an explicit-denial case.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SUPPORTED_SECTIONS = (
    "config firewall address",
    "config firewall service custom",
    "config firewall policy",
)

BUILTIN_TCP_SERVICES: Mapping[str, tuple[tuple[int, int], ...]] = {
    "HTTP": ((80, 80),),
    "HTTPS": ((443, 443),),
    "SSH": ((22, 22),),
    # Native syntax is accepted, but an ALL catch-all never substitutes for a
    # scoped expected service because policy fingerprints are compared exactly.
    "ALL": ((1, 65535),),
}

_ADDRESS_FIELDS = frozenset({"subnet"})
_SERVICE_FIELDS = frozenset({"tcp-portrange"})
_POLICY_FIELDS = frozenset(
    {
        "name",
        "srcintf",
        "dstintf",
        "srcaddr",
        "dstaddr",
        "action",
        "schedule",
        "service",
        "logtraffic",
        "status",
    }
)
_UNSAFE_COMMANDS = frozenset(
    {
        "append",
        "clear",
        "delete",
        "diagnose",
        "execute",
        "move",
        "purge",
        "rename",
        "restore",
        "show",
        "unset",
    }
)


@dataclass(frozen=True)
class _Address:
    name: str
    network: ipaddress.IPv4Network


@dataclass(frozen=True)
class _Service:
    name: str
    tcp_ports: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _Policy:
    policy_id: int
    name: str
    srcintf: tuple[str, ...]
    dstintf: tuple[str, ...]
    srcaddr: tuple[str, ...]
    dstaddr: tuple[str, ...]
    action: str
    schedule: str
    service: tuple[str, ...]
    logtraffic: str
    status: str


@dataclass(frozen=True)
class _Case:
    case_id: str
    description: str
    source: str
    destination: str
    incoming: str
    outgoing: str
    protocol: str
    destination_port: int
    expected_outcome: str
    expected_policy: _Policy | None


@dataclass(frozen=True)
class _Exercise:
    exercise_id: str
    title: str
    description: str
    config: str
    starter_config: str
    task_prompt: str
    help: str
    cases: tuple[_Case, ...]
    flows: tuple[_Case, ...] = ()


@dataclass
class _Parsed:
    addresses: dict[str, _Address]
    services: dict[str, _Service]
    policies: list[_Policy]
    errors: list[dict[str, Any]]


def _error(
    errors: list[dict[str, Any]],
    code: str,
    line: int,
    message: str,
    hint: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "code": code,
        "line": line,
        "message": message,
    }
    if hint:
        item["hint"] = hint
    errors.append(item)


def _tokens(line: str, line_number: int, errors: list[dict[str, Any]]) -> list[str] | None:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError as exc:
        _error(
            errors,
            "invalid_syntax",
            line_number,
            f"Could not parse CLI quoting: {exc}.",
            'Use FortiOS quoting such as edit "NAME".',
        )
        return None


def _single(values: Sequence[str], field: str) -> str | None:
    if len(values) != 1:
        return None
    value = values[0].strip()
    return value or None


def _list_values(values: Sequence[str]) -> tuple[str, ...] | None:
    cleaned = tuple(value.strip() for value in values if value.strip())
    return cleaned or None


def _parse_ports(values: Sequence[str]) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for value in values:
        for item in re.split(r"[\s,]+", value.strip()):
            if not item:
                continue
            if "-" in item:
                parts = item.split("-")
                if len(parts) != 2:
                    raise ValueError(f"invalid TCP port range {item!r}")
                first, last = (int(part) for part in parts)
            else:
                first = last = int(item)
            if not (1 <= first <= 65535 and 1 <= last <= 65535):
                raise ValueError(f"TCP port {item!r} is outside 1-65535")
            if first > last:
                raise ValueError(f"TCP range {item!r} is reversed")
            ranges.append((first, last))
    if not ranges:
        raise ValueError("at least one TCP port is required")
    ranges.sort()
    merged: list[list[int]] = []
    for first, last in ranges:
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    return tuple((first, last) for first, last in merged)


def _parse_config(config_text: str) -> _Parsed:
    parsed = _Parsed(addresses={}, services={}, policies=[], errors=[])
    section: str | None = None
    current: dict[str, Any] | None = None
    current_line = 0
    seen_ids: set[int] = set()
    seen_names: set[tuple[str, str]] = set()

    def finish() -> None:
        nonlocal current
        if current is None or section is None:
            return
        kind = section
        name = str(current.get("name", ""))
        if kind == "firewall address":
            if "subnet" not in current:
                _error(
                    parsed.errors,
                    "missing_field",
                    current_line,
                    f"Address {name or '<unnamed>'!r} has no subnet.",
                    "Add set subnet <IPv4-address> <netmask>.",
                )
            else:
                try:
                    address, mask = current["subnet"]
                    network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
                    if name in parsed.addresses:
                        _error(
                            parsed.errors,
                            "duplicate_object",
                            current_line,
                            f"Address object {name!r} is declared more than once.",
                            "Use one edit block per address object.",
                        )
                    else:
                        parsed.addresses[name] = _Address(name, network)
                except (ValueError, TypeError) as exc:
                    _error(
                        parsed.errors,
                        "invalid_ipv4",
                        current_line,
                        f"Address {name or '<unnamed>'!r} has an invalid IPv4 subnet: {exc}.",
                        "Use an IPv4 address and dotted-decimal netmask.",
                    )
        elif kind == "firewall service custom":
            if "tcp_ports" not in current:
                _error(
                    parsed.errors,
                    "missing_field",
                    current_line,
                    f"Custom service {name or '<unnamed>'!r} has no TCP port range.",
                    "Use set tcp-portrange <port>.",
                )
            elif name in parsed.services:
                _error(
                    parsed.errors,
                    "duplicate_object",
                    current_line,
                    f"Custom service {name!r} is declared more than once.",
                    "Use one edit block per custom service.",
                )
            else:
                parsed.services[name] = _Service(name, current["tcp_ports"])
        elif kind == "firewall policy":
            required = (
                "name",
                "srcintf",
                "dstintf",
                "srcaddr",
                "dstaddr",
                "action",
                "schedule",
                "service",
            )
            missing = [field for field in required if field not in current]
            if missing:
                _error(
                    parsed.errors,
                    "missing_field",
                    current_line,
                    f"Policy {name or '<unnamed>'!r} is missing: {', '.join(missing)}.",
                    "Complete the narrow policy fields before grading.",
                )
            else:
                policy_id = current["policy_id"]
                if policy_id in seen_ids:
                    _error(
                        parsed.errors,
                        "duplicate_policy_id",
                        current_line,
                        f"Policy ID {policy_id} is declared more than once.",
                        "Policy order is meaningful; use unique edit IDs.",
                    )
                else:
                    seen_ids.add(policy_id)
                    parsed.policies.append(
                        _Policy(
                            policy_id=policy_id,
                            name=current["name"],
                            srcintf=current["srcintf"],
                            dstintf=current["dstintf"],
                            srcaddr=current["srcaddr"],
                            dstaddr=current["dstaddr"],
                            action=current["action"],
                            schedule=current["schedule"],
                            service=current["service"],
                            logtraffic=current.get("logtraffic", "none"),
                            status=current.get("status", "enable"),
                        )
                    )
        current = None

    def set_field(tokens: Sequence[str], line_number: int) -> None:
        if current is None or section is None:
            _error(
                parsed.errors,
                "invalid_context",
                line_number,
                "set is only valid inside an edit block.",
                "Start an object with edit before using set.",
            )
            return
        if len(tokens) < 3:
            _error(
                parsed.errors,
                "invalid_syntax",
                line_number,
                "A set command needs a field and value.",
                "Use set <field> <value>.",
            )
            return
        field = tokens[1]
        values = list(tokens[2:])
        allowed = {
            "firewall address": _ADDRESS_FIELDS,
            "firewall service custom": _SERVICE_FIELDS,
            "firewall policy": _POLICY_FIELDS,
        }[section]
        if field not in allowed:
            _error(
                parsed.errors,
                "unsupported_operation",
                line_number,
                f"Unsupported field {field!r} in config firewall {section}.",
                "This offline lab accepts only IPv4 subnets, TCP custom services, and the documented policy fields.",
            )
            return
        try:
            if section == "firewall address":
                if field == "subnet":
                    if len(values) != 2:
                        raise ValueError("set subnet requires an IPv4 address and netmask")
                    ipaddress.IPv4Address(values[0])
                    ipaddress.IPv4Address(values[1])
                    current[field] = (values[0], values[1])
            elif section == "firewall service custom":
                current["tcp_ports"] = _parse_ports(values)
            else:
                if field == "name":
                    value = _single(values, field)
                    if value is None:
                        raise ValueError("name requires one non-empty value")
                    current[field] = value
                elif field in {"srcintf", "dstintf", "srcaddr", "dstaddr", "service"}:
                    value = _list_values(values)
                    if value is None:
                        raise ValueError(f"{field} requires at least one value")
                    current[field] = value
                elif field == "action":
                    value = _single(values, field)
                    if value not in {"accept", "deny"}:
                        raise ValueError("action must be accept or deny")
                    current[field] = value
                elif field == "schedule":
                    value = _single(values, field)
                    if value != "always":
                        raise ValueError("only schedule always is supported offline")
                    current[field] = value
                elif field == "logtraffic":
                    value = _single(values, field)
                    if value not in {"all", "none"}:
                        raise ValueError("logtraffic must be all or none")
                    current[field] = value
                elif field == "status":
                    value = _single(values, field)
                    if value not in {"enable", "disable"}:
                        raise ValueError("status must be enable or disable")
                    current[field] = value
        except ValueError as exc:
            _error(
                parsed.errors,
                "invalid_value",
                line_number,
                f"Invalid {field}: {exc}.",
                "Use the exact values documented by this offline policy subset.",
            )

    for line_number, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        tokens = _tokens(line, line_number, parsed.errors)
        if not tokens:
            continue
        command = tokens[0]
        if command == "config":
            if section is not None or current is not None:
                _error(
                    parsed.errors,
                    "invalid_nesting",
                    line_number,
                    "Nested config blocks are not supported.",
                    "Close the current edit and config block with next/end.",
                )
                continue
            candidate = " ".join(tokens)
            if candidate not in SUPPORTED_SECTIONS:
                _error(
                    parsed.errors,
                    "unsupported_operation",
                    line_number,
                    f"Unsupported configuration section {candidate!r}.",
                    "Supported sections: " + ", ".join(SUPPORTED_SECTIONS) + ".",
                )
            else:
                section = candidate.removeprefix("config ")
            continue
        if command == "edit":
            if section is None:
                _error(
                    parsed.errors,
                    "invalid_context",
                    line_number,
                    "edit is only valid inside a supported config section.",
                    "Start with one of the supported config firewall sections.",
                )
            elif current is not None:
                _error(
                    parsed.errors,
                    "invalid_nesting",
                    line_number,
                    "An edit block is already open.",
                    "Close the current object with next before the next edit.",
                )
            elif len(tokens) != 2 or not tokens[1]:
                _error(
                    parsed.errors,
                    "invalid_syntax",
                    line_number,
                    "edit requires one object name or numeric policy ID.",
                    "Use edit \"NAME\" or edit 10.",
                )
            elif section == "firewall policy":
                try:
                    policy_id = int(tokens[1], 10)
                    if policy_id < 1:
                        raise ValueError
                    current = {"policy_id": policy_id}
                    current_line = line_number
                except ValueError:
                    _error(
                        parsed.errors,
                        "invalid_policy_id",
                        line_number,
                        "Firewall policy edit IDs must be positive integers.",
                        "Use edit 10, edit 20, and so on.",
                    )
            else:
                name = tokens[1]
                key = (section, name)
                if key in seen_names:
                    _error(
                        parsed.errors,
                        "duplicate_object",
                        line_number,
                        f"Object {name!r} is declared more than once in {section}.",
                        "Use one edit block per object.",
                    )
                seen_names.add(key)
                current = {"name": name}
                current_line = line_number
            continue
        if command == "next":
            if section is None or current is None:
                _error(
                    parsed.errors,
                    "invalid_context",
                    line_number,
                    "next has no open edit block.",
                    "Open an object with edit before next.",
                )
            else:
                finish()
            continue
        if command == "end":
            if section is None:
                _error(
                    parsed.errors,
                    "invalid_context",
                    line_number,
                    "end has no open config block.",
                    "Use end only after a supported config section.",
                )
            elif current is not None:
                _error(
                    parsed.errors,
                    "invalid_nesting",
                    line_number,
                    "The config block ended before the current edit was closed.",
                    "Close the object with next, then close the section with end.",
                )
            else:
                section = None
            continue
        if command == "set":
            set_field(tokens, line_number)
            continue
        _error(
            parsed.errors,
            "unsupported_operation",
            line_number,
            f"Unsupported CLI operation {command!r}.",
            "Only native config/edit/set/next/end syntax for the three documented sections is accepted.",
        )

    if current is not None:
        _error(
            parsed.errors,
            "unterminated_edit",
            current_line,
            "The final edit block is missing next.",
            "Close every object with next.",
        )
    if section is not None:
        _error(
            parsed.errors,
            "unterminated_config",
            len(config_text.splitlines()) or 1,
            f"The {section!r} config block is missing end.",
            "Close every supported config section with end.",
        )

    for policy in parsed.policies:
        for reference in (*policy.srcaddr, *policy.dstaddr):
            if reference != "all" and reference not in parsed.addresses:
                _error(
                    parsed.errors,
                    "unknown_address",
                    0,
                    f"Policy {policy.policy_id} references unknown address {reference!r}.",
                    "Declare it in config firewall address or use the literal all deliberately.",
                )
        for reference in policy.service:
            if reference not in BUILTIN_TCP_SERVICES and reference not in parsed.services:
                _error(
                    parsed.errors,
                    "unknown_service",
                    0,
                    f"Policy {policy.policy_id} references unknown service {reference!r}.",
                    "Declare a custom TCP service or use HTTP, HTTPS, SSH, or ALL.",
                )
    return parsed


def _policy_signature(policy: _Policy) -> dict[str, Any]:
    return {
        "srcintf": list(policy.srcintf),
        "dstintf": list(policy.dstintf),
        "srcaddr": list(policy.srcaddr),
        "dstaddr": list(policy.dstaddr),
        "service": list(policy.service),
        "action": policy.action,
        "schedule": policy.schedule,
        "logtraffic": policy.logtraffic,
        "status": policy.status,
    }


def _canonical_policy_scope(policy: _Policy | None, parsed: _Parsed) -> dict[str, Any] | None:
    """Return the effective scope after resolving address and service objects."""

    if policy is None:
        return None

    def networks(references: Iterable[str]) -> list[str]:
        values: list[str] = []
        for reference in references:
            if reference == "all":
                values.append("0.0.0.0/0")
            elif reference in parsed.addresses:
                values.append(str(parsed.addresses[reference].network))
        return sorted(set(values))

    def ports(references: Iterable[str]) -> list[list[int]]:
        values: set[tuple[int, int]] = set()
        for reference in references:
            ranges = BUILTIN_TCP_SERVICES.get(reference)
            if ranges is None and reference in parsed.services:
                ranges = parsed.services[reference].tcp_ports
            if ranges:
                values.update(ranges)
        return [[first, last] for first, last in sorted(values)]

    signature = _policy_signature(policy)
    for field in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"):
        signature[field] = sorted(signature[field])
    return {
        **signature,
        "src_networks": networks(policy.srcaddr),
        "dst_networks": networks(policy.dstaddr),
        "tcp_ports": ports(policy.service),
    }


def _policy_public(policy: _Policy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "id": policy.policy_id,
        "name": policy.name,
        **_policy_signature(policy),
    }


def _rule_identity(policy: _Policy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "id": policy.policy_id,
        "name": policy.name,
        "action": policy.action,
    }


def _address_matches(
    references: Iterable[str],
    ip: ipaddress.IPv4Address,
    addresses: Mapping[str, _Address],
) -> bool:
    return any(
        reference == "all"
        or (reference in addresses and ip in addresses[reference].network)
        for reference in references
    )


def _service_matches(
    references: Iterable[str],
    port: int,
    services: Mapping[str, _Service],
) -> bool:
    for reference in references:
        ranges = BUILTIN_TCP_SERVICES.get(reference)
        if ranges is None and reference in services:
            ranges = services[reference].tcp_ports
        if ranges and any(first <= port <= last for first, last in ranges):
            return True
    return False


def _matches(policy: _Policy, case: _Case, parsed: _Parsed) -> bool:
    if policy.status != "enable" or policy.schedule != "always":
        return False
    if case.protocol.lower() != "tcp":
        return False
    try:
        source = ipaddress.IPv4Address(case.source)
        destination = ipaddress.IPv4Address(case.destination)
    except ValueError:
        return False
    return (
        case.incoming in policy.srcintf
        and case.outgoing in policy.dstintf
        and _address_matches(policy.srcaddr, source, parsed.addresses)
        and _address_matches(policy.dstaddr, destination, parsed.addresses)
        and _service_matches(policy.service, case.destination_port, parsed.services)
    )


def _expected_signature(case: _Case) -> dict[str, Any]:
    return _policy_signature(case.expected_policy) if case.expected_policy is not None else {}


def _case_public(case: _Case) -> dict[str, Any]:
    expected_identity = _rule_identity(case.expected_policy)
    return {
        "id": case.case_id,
        "description": case.description,
        "request": {
            "incoming": case.incoming,
            "outgoing": case.outgoing,
            "source": case.source,
            "destination": case.destination,
            "protocol": case.protocol,
            "destination_port": case.destination_port,
        },
        "expected": {
            "outcome": case.expected_outcome,
            "explicit": case.expected_policy is not None,
            "rule_identity": expected_identity,
            "policy": _expected_signature(case),
        },
    }


def _policy_from_data(data: Mapping[str, Any] | None) -> _Policy | None:
    if data is None:
        return None
    return _Policy(
        policy_id=int(data["policy_id"]),
        name=str(data["name"]),
        srcintf=tuple(str(item) for item in data["srcintf"]),
        dstintf=tuple(str(item) for item in data["dstintf"]),
        srcaddr=tuple(str(item) for item in data["srcaddr"]),
        dstaddr=tuple(str(item) for item in data["dstaddr"]),
        action=str(data["action"]),
        schedule=str(data.get("schedule", "always")),
        service=tuple(str(item) for item in data["service"]),
        logtraffic=str(data.get("logtraffic", "all")),
        status=str(data.get("status", "enable")),
    )


def _case_from_data(
    data: Mapping[str, Any],
    reference_policies: Mapping[int, _Policy] | None = None,
) -> _Case:
    required = {
        "id", "description", "source", "destination", "incoming", "outgoing",
        "protocol", "destination_port", "expected_outcome", "expected_policy",
    }
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"scenario flow is missing fields: {', '.join(missing)}")
    expected_data = data["expected_policy"]
    if isinstance(expected_data, (int, str)):
        if reference_policies is None:
            raise ValueError("expected_policy ID requires a parsed reference config")
        try:
            expected_policy = reference_policies[int(expected_data)]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"expected_policy references unknown policy {expected_data!r}") from exc
    elif expected_data is None or isinstance(expected_data, Mapping):
        expected_policy = _policy_from_data(expected_data)
    else:
        raise ValueError("expected_policy must be null, a policy ID, or an object")
    return _Case(
        case_id=str(data["id"]),
        description=str(data["description"]),
        source=str(data["source"]),
        destination=str(data["destination"]),
        incoming=str(data["incoming"]),
        outgoing=str(data["outgoing"]),
        protocol=str(data["protocol"]),
        destination_port=int(data["destination_port"]),
        expected_outcome=str(data["expected_outcome"]),
        expected_policy=expected_policy,
    )


def _scenario_case_pass(
    case: _Case,
    parsed: _Parsed,
    reference: _Parsed,
) -> bool:
    actual_policy = next(
        (policy for policy in parsed.policies if _matches(policy, case, parsed)),
        None,
    )
    if case.expected_policy is None:
        return actual_policy is None and case.expected_outcome == "blocked"
    return (
        actual_policy is not None
        and actual_policy.action == case.expected_policy.action
        and ((case.expected_outcome == "allowed" and actual_policy.action == "accept")
             or (case.expected_outcome == "blocked" and actual_policy.action == "deny"))
        and _rule_identity(actual_policy) == _rule_identity(case.expected_policy)
        and _canonical_policy_scope(actual_policy, parsed)
        == _canonical_policy_scope(case.expected_policy, reference)
    )


def _load_scenarios(scenario_dir: Path | None = None) -> tuple[_Exercise, ...]:
    """Load contributor-authored scenarios from versioned JSON bundles."""

    scenario_dir = scenario_dir or Path(
        os.environ.get("FORTIGATE_SCENARIO_DIR", Path(__file__).resolve().parent / "scenarios")
    ).resolve()
    exercises: list[_Exercise] = []
    seen_ids: set[str] = set()
    scenario_paths = sorted(scenario_dir.glob("*/scenario.json"))
    for path in scenario_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1:
            raise ValueError(f"{path.name}: schema_version must be 1")
        exercise_id = data.get("id")
        if not isinstance(exercise_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]+", exercise_id):
            raise ValueError(f"{path.name}: id must be a lowercase kebab-case string")
        if path.parent.name != exercise_id:
            raise ValueError(f"{path.name}: directory name must match id {exercise_id!r}")
        if exercise_id in seen_ids:
            raise ValueError(f"duplicate scenario id {exercise_id!r}")
        seen_ids.add(exercise_id)
        fields = ("title", "description", "task_prompt", "help")
        if any(not isinstance(data.get(field), str) or not data[field].strip() for field in fields):
            raise ValueError(f"{path.name}: title and descriptions are required")
        starter_path = path.parent / "starter.conf"
        reference_path = path.parent / "reference.conf"
        if starter_path.name != "starter.conf" or reference_path.name != "reference.conf":
            raise ValueError(f"{path.name}: scenario snapshots must use fixed file names")
        if not starter_path.is_file() or not reference_path.is_file():
            raise ValueError(f"{path.name}: starter.conf and reference.conf are required")
        reference = reference_path.read_text(encoding="utf-8").strip() + "\n"
        starter = starter_path.read_text(encoding="utf-8").strip() + "\n"
        parsed_reference = _parse_config(reference)
        if parsed_reference.errors:
            raise ValueError(f"{path.name}: reference config is invalid: {parsed_reference.errors}")
        parsed_starter = _parse_config(starter)
        if parsed_starter.errors:
            raise ValueError(f"{path.name}: starter config is invalid: {parsed_starter.errors}")
        reference_policies = {policy.policy_id: policy for policy in parsed_reference.policies}
        cases = tuple(_case_from_data(item, reference_policies) for item in data.get("cases", []))
        flows = tuple(_case_from_data(item, reference_policies) for item in data.get("flows", []))
        if not cases:
            raise ValueError(f"{path.name}: at least one graded case is required")
        if len({case.case_id for case in (*cases, *flows)}) != len(cases) + len(flows):
            raise ValueError(f"{path.name}: flow IDs must be unique")
        for case in (*cases, *flows):
            if case.expected_policy is None:
                if case.expected_outcome != "blocked":
                    raise ValueError(f"{path.name}: implicit flows must declare blocked")
            elif case.expected_outcome != (
                "allowed" if case.expected_policy.action == "accept" else "blocked"
            ):
                raise ValueError(f"{path.name}: expected outcome disagrees with reference policy")
        all_reference_flows_pass = all(
            _scenario_case_pass(case, parsed_reference, parsed_reference)
            for case in (*cases, *flows)
        )
        if not all_reference_flows_pass:
            raise ValueError(f"{path.name}: reference config does not satisfy its declared flows")
        all_starter_flows_pass = all(
            _scenario_case_pass(case, parsed_starter, parsed_reference)
            for case in (*cases, *flows)
        )
        if all_starter_flows_pass:
            raise ValueError(f"{path.name}: starter config already passes every declared flow")
        exercises.append(_Exercise(
            exercise_id=exercise_id,
            title=data["title"],
            description=data["description"],
            config=reference,
            starter_config=starter,
            task_prompt=data["task_prompt"],
            help=data["help"],
            cases=cases,
            flows=flows,
        ))
    if not exercises:
        raise ValueError(f"no scenario bundles found in {scenario_dir}")
    preferred_order = {
        "scoped-http-allow": 0,
        "ordered-exception": 1,
        "custom-tcp-port": 2,
    }
    exercises.sort(key=lambda item: (preferred_order.get(item.exercise_id, 1000), item.exercise_id))
    return tuple(exercises)


def load_scenarios(scenario_dir: Path | None = None) -> tuple[_Exercise, ...]:
    """Load and validate a scenario collection for contributor tooling."""

    return _load_scenarios(scenario_dir)


# The versioned scenario bundles are the source of the public catalog.
_EXERCISES = _load_scenarios()
_EXERCISE_BY_ID = {exercise.exercise_id: exercise for exercise in _EXERCISES}
def catalog() -> list[dict[str, Any]]:
    """Return independent, JSON-serializable exercise definitions."""

    result: list[dict[str, Any]] = []
    for exercise in _EXERCISES:
        result.append(
            {
                "id": exercise.exercise_id,
                "title": exercise.title,
                "description": exercise.description,
                # Public callers receive the repair starter, never the hidden
                # reference config kept in _Exercise.config for grading/tests.
                "config": exercise.starter_config,
                "task_prompt": exercise.task_prompt,
                "help": exercise.help,
                "firewall_policy_limit": 3,
                "boundary_flows": [_case_public(case) for case in exercise.flows],
                "supported_operations": [
                    "config firewall address / edit / set subnet / next / end",
                    "config firewall service custom / edit / set tcp-portrange / next / end",
                    "config firewall policy / edit / set / next / end",
                ],
                "cases": [_case_public(case) for case in exercise.cases],
            }
        )
    return copy.deepcopy(result)


def _base_result(exercise_id: str) -> dict[str, Any]:
    return {
        "exercise_id": exercise_id,
        "pass": False,
        "errors": [],
        "cases": [],
        "summary": {"passed": 0, "total": 0},
    }


def grade(exercise_id: str, config_text: str) -> dict[str, Any]:
    """Grade a native CLI snippet against one finite exercise.

    The return value contains only dicts, lists, strings, numbers, booleans,
    and nulls, so callers can pass it directly to json.dumps.
    """

    result = _base_result(str(exercise_id))
    exercise = _EXERCISE_BY_ID.get(exercise_id)
    if exercise is None:
        result["errors"].append(
            {
                "code": "unknown_exercise",
                "line": 0,
                "message": f"Unknown exercise {exercise_id!r}.",
                "hint": "Choose an id returned by catalog().",
            }
        )
        return result
    if not isinstance(config_text, str):
        result["errors"].append(
            {
                "code": "invalid_input",
                "line": 0,
                "message": "config_text must be a string containing native CLI text.",
                "hint": "Pass the editable FortiOS config snippet, not a parsed object.",
            }
        )
        return result

    parsed = _parse_config(config_text)
    result["errors"] = copy.deepcopy(parsed.errors)
    result["summary"]["total"] = len(exercise.cases)
    if parsed.errors:
        result["feedback"] = "Fix the configuration errors before grading traffic cases."
        result["cases"] = [
            {
                **_case_public(case),
                "expected_rule_identity": _rule_identity(case.expected_policy),
                "actual_rule_identity": None,
                "actual": None,
                "pass": False,
                "feedback": "Configuration parsing failed; this case was not evaluated.",
            }
            for case in exercise.cases
        ]
        return result

    expected_parsed = _parse_config(exercise.config)
    if expected_parsed.errors:
        result["errors"].append({
            "code": "invalid_reference",
            "line": 0,
            "message": "The bundled reference configuration is invalid.",
        })
        result["feedback"] = "The exercise reference is invalid and cannot be graded."
        return result

    for case in exercise.cases:
        actual_policy = _matching_policy(case, parsed)
        actual_outcome = (
            "allowed"
            if actual_policy is not None and actual_policy.action == "accept"
            else "blocked"
            if actual_policy is not None and actual_policy.action == "deny"
            else "implicit-deny"
        )
        expected_identity = _rule_identity(case.expected_policy)
        actual_identity = _rule_identity(actual_policy)
        identity_pass = actual_identity == expected_identity
        expected_policy = case.expected_policy
        scope_pass = (
            actual_policy is not None
            and expected_policy is not None
            and _canonical_policy_scope(actual_policy, parsed)
            == _canonical_policy_scope(expected_policy, expected_parsed)
        )
        if expected_policy is None:
            # A null expected policy is a deliberate implicit default-deny
            # boundary. It passes only when no explicit rule matches; an
            # explicit deny is still the wrong teaching outcome.
            case_pass = actual_policy is None and case.expected_outcome == "blocked"
        else:
            case_pass = (
                actual_outcome == case.expected_outcome
                and identity_pass
                and scope_pass
            )
        if case_pass:
            feedback = (
                "No explicit policy matched; the expected implicit default deny held."
                if expected_policy is None
                else "Matched the expected first rule and exact scope."
            )
        elif actual_policy is None:
            feedback = "No explicit policy matched; this is implicit default deny, but the case expected a different decision."
        elif not identity_pass:
            if expected_policy is None:
                feedback = (
                    f"First matching policy is {actual_policy.policy_id} "
                    f"{actual_policy.name!r}; expected implicit default deny."
                )
            else:
                feedback = (
                    f"First matching policy is {actual_policy.policy_id} "
                    f"{actual_policy.name!r}; expected {case.expected_policy.policy_id} "
                    f"{case.expected_policy.name!r}. Check policy order and narrower exceptions."
                )
        elif not scope_pass:
            feedback = (
                "The expected rule identity matched, but its scope differs. "
                "Do not replace the required address/service scope with a broad catch-all."
            )
        else:
            feedback = (
                f"Expected {case.expected_outcome}, but the first matching rule "
                f"returns {actual_outcome}."
            )
        result["cases"].append(
            {
                **_case_public(case),
                "expected_rule_identity": expected_identity,
                "actual_rule_identity": actual_identity,
                "expected_policy": _expected_signature(case),
                "actual_policy": _policy_public(actual_policy),
                "actual": {
                    "outcome": actual_outcome,
                    "rule_identity": actual_identity,
                },
                "pass": case_pass,
                "feedback": feedback,
            }
        )

    boundary_results: list[dict[str, Any]] = []
    boundary_passed = 0
    for boundary in exercise.flows:
        actual_policy = _matching_policy(boundary, parsed)
        actual = _flow_result(boundary, parsed)
        expected = {
            "outcome": boundary.expected_outcome,
            "explicit": boundary.expected_policy is not None,
            "rule_identity": _rule_identity(boundary.expected_policy),
        }
        expected_scope = _canonical_policy_scope(boundary.expected_policy, expected_parsed)
        actual_scope = _canonical_policy_scope(actual_policy, parsed)
        boundary_pass = (
            ((boundary.expected_policy is None
              and actual_policy is None
              and boundary.expected_outcome == "blocked")
             or (boundary.expected_policy is not None
                 and actual["outcome"] == boundary.expected_outcome
                 and _rule_identity(actual_policy) == _rule_identity(boundary.expected_policy)
                 and actual_scope == expected_scope)))
        if boundary_pass:
            boundary_passed += 1
        boundary_results.append({
            **_case_public(boundary),
            "expected": expected,
            "actual": {
                **actual,
                "explicit": actual_policy is not None,
                "policy": _policy_public(actual_policy),
            },
            "pass": boundary_pass,
            "feedback": (
                "Boundary flow retained the expected explicit or implicit decision."
                if boundary_pass
                else "Boundary flow changed. Check for an over-broad address, service, or appended policy."
            ),
        })
    result["boundaries"] = boundary_results
    passed = sum(1 for case in result["cases"] if case["pass"])
    result["summary"]["passed"] = passed
    result["summary"]["boundary_passed"] = boundary_passed
    result["summary"]["boundary_total"] = len(boundary_results)
    result["pass"] = passed == len(exercise.cases) and boundary_passed == len(boundary_results)
    result["feedback"] = (
        "All positive and explicit-negative cases passed."
        if result["pass"]
        else "At least one case failed; use each case's actionable feedback."
    )
    return result


def _flow_result(case: _Case, parsed: _Parsed) -> dict[str, Any]:
    actual_policy = _matching_policy(case, parsed)
    outcome = (
        "allowed"
        if actual_policy is not None and actual_policy.action == "accept"
        else "blocked"
        if actual_policy is not None and actual_policy.action == "deny"
        else "implicit-deny"
    )
    return {
        "outcome": outcome,
        "rule_identity": _rule_identity(actual_policy),
    }


def _matching_policy(case: _Case, parsed: _Parsed) -> _Policy | None:
    return next(
        (policy for policy in parsed.policies if _matches(policy, case, parsed)),
        None,
    )


def _compare_error(side: str, error: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "side": side,
        "code": str(error.get("code", "invalid_config")),
        "line": int(error.get("line", 0)),
        "message": str(error.get("message", "Configuration is invalid.")),
    }


def _canonical_objects(parsed: _Parsed, kind: str) -> dict[str, Any]:
    if kind == "address":
        return {name: str(value.network) for name, value in parsed.addresses.items()}
    return {
        name: [[first, last] for first, last in value.tcp_ports]
        for name, value in parsed.services.items()
    }


def _canonical_policies(parsed: _Parsed) -> dict[str, Any]:
    return {
        str(policy.policy_id): {
            "sequence": sequence,
            "scope": _canonical_policy_scope(policy, parsed),
        }
        for sequence, policy in enumerate(parsed.policies)
    }


def compare(exercise_id: str, before: str, after: str) -> dict[str, Any]:
    """Compare two configs using every graded and boundary flow in a scenario."""

    result: dict[str, Any] = {
        "schema_version": 1,
        "exercise_id": str(exercise_id),
        "errors": [],
        "flows": [],
        "scope_changes": [],
        "summary": {"total": 0, "changed": 0},
    }
    exercise = _EXERCISE_BY_ID.get(exercise_id)
    if exercise is None:
        result["errors"].append({
            "side": "request",
            "code": "unknown_exercise",
            "line": 0,
            "message": f"Unknown exercise {exercise_id!r}.",
        })
        return result
    if not isinstance(before, str) or not isinstance(after, str):
        result["errors"].append({
            "side": "request",
            "code": "invalid_input",
            "line": 0,
            "message": "before and after must be strings containing CLI configuration.",
        })
        return result
    before_parsed = _parse_config(before)
    after_parsed = _parse_config(after)
    for error in before_parsed.errors:
        result["errors"].append(_compare_error("before", error))
    for error in after_parsed.errors:
        result["errors"].append(_compare_error("after", error))
    if result["errors"]:
        return result

    flows = (*exercise.cases, *exercise.flows)
    result["summary"]["total"] = len(flows)
    for case in flows:
        before_flow = _flow_result(case, before_parsed)
        after_flow = _flow_result(case, after_parsed)
        changed = before_flow != after_flow
        result["flows"].append({
            "id": case.case_id,
            "source": case.source,
            "destination": case.destination,
            "destination_port": case.destination_port,
            "description": case.description,
            "before": before_flow,
            "after": after_flow,
            "changed": changed,
        })
        if changed:
            result["summary"]["changed"] += 1

    for kind in ("address", "service"):
        before_objects = _canonical_objects(before_parsed, kind)
        after_objects = _canonical_objects(after_parsed, kind)
        for name in sorted(set(before_objects) | set(after_objects)):
            old = before_objects.get(name)
            new = after_objects.get(name)
            if old != new:
                result["scope_changes"].append({
                    "kind": kind,
                    "name": name,
                    "before": old,
                    "after": new,
                })
    before_policies = _canonical_policies(before_parsed)
    after_policies = _canonical_policies(after_parsed)
    for policy_id in sorted(set(before_policies) | set(after_policies), key=int):
        old = before_policies.get(policy_id)
        new = after_policies.get(policy_id)
        if old != new:
            result["scope_changes"].append({
                "kind": "policy",
                "name": policy_id,
                "before": old,
                "after": new,
            })
    return result


__all__ = ["catalog", "compare", "grade"]
