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
import re
import shlex
import textwrap
from dataclasses import dataclass
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
    expected_policy: _Policy


@dataclass(frozen=True)
class _Exercise:
    exercise_id: str
    title: str
    description: str
    config: str
    starter_config: str
    task_prompt: str
    task_prompt_ru: str
    help: str
    help_ru: str
    cases: tuple[_Case, ...]


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
    return _policy_signature(case.expected_policy)


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
            "explicit": True,
            "rule_identity": expected_identity,
            "policy": _expected_signature(case),
        },
    }


def _exercise(
    exercise_id: str,
    title: str,
    description: str,
    config: str,
    cases: Sequence[_Case],
    *,
    starter_config: str,
    task_prompt: str,
    task_prompt_ru: str,
    help_text: str,
    help_ru: str,
) -> _Exercise:
    return _Exercise(
        exercise_id=exercise_id,
        title=title,
        description=description,
        config=textwrap.dedent(config).strip() + "\n",
        starter_config=textwrap.dedent(starter_config).strip() + "\n",
        task_prompt=task_prompt,
        task_prompt_ru=task_prompt_ru,
        help=help_text,
        help_ru=help_ru,
        cases=tuple(cases),
    )


def _policy(
    policy_id: int,
    name: str,
    *,
    srcaddr: Sequence[str],
    dstaddr: Sequence[str],
    service: Sequence[str],
    action: str,
    srcintf: Sequence[str] = ("port2",),
    dstintf: Sequence[str] = ("port3",),
    logtraffic: str = "all",
) -> _Policy:
    return _Policy(
        policy_id=policy_id,
        name=name,
        srcintf=tuple(srcintf),
        dstintf=tuple(dstintf),
        srcaddr=tuple(srcaddr),
        dstaddr=tuple(dstaddr),
        action=action,
        schedule="always",
        service=tuple(service),
        logtraffic=logtraffic,
        status="enable",
    )


_SCOPED_HTTP_CONFIG = """
config firewall address
    edit "LAN-CLIENT"
        set subnet 10.231.31.10 255.255.255.255
    next
    edit "DMZ-WEB"
        set subnet 10.231.32.10 255.255.255.255
    next
end
config firewall policy
    edit 10
        set name "ALLOW-LAN-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-CLIENT"
        set dstaddr "DMZ-WEB"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
    edit 20
        set name "DENY-LAN-SSH"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-CLIENT"
        set dstaddr "DMZ-WEB"
        set action deny
        set schedule "always"
        set service "SSH"
        set logtraffic all
    next
end
"""

_SCOPED_HTTP_STARTER_CONFIG = """
config firewall address
    edit "LAN-CLIENT"
        set subnet 10.231.31.10 255.255.255.255
    next
    edit "DMZ-WEB"
        set subnet 10.231.32.10 255.255.255.255
    next
end
config firewall policy
    edit 10
        set name "ALLOW-LAN-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-CLIENT"
        set dstaddr "DMZ-WEB"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end
"""

_ORDERED_EXCEPTION_CONFIG = """
config firewall address
    edit "LAN-USERS"
        set subnet 10.231.31.0 255.255.255.0
    next
    edit "LAN-RESTRICTED"
        set subnet 10.231.31.20 255.255.255.255
    next
    edit "DMZ-WEB"
        set subnet 10.231.32.10 255.255.255.255
    next
end
config firewall policy
    edit 10
        set name "DENY-RESTRICTED-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-RESTRICTED"
        set dstaddr "DMZ-WEB"
        set action deny
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
    edit 20
        set name "ALLOW-LAN-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-USERS"
        set dstaddr "DMZ-WEB"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end
"""

_ORDERED_EXCEPTION_STARTER_CONFIG = """
config firewall address
    edit "LAN-USERS"
        set subnet 10.231.31.0 255.255.255.0
    next
    edit "LAN-RESTRICTED"
        set subnet 10.231.31.20 255.255.255.255
    next
    edit "DMZ-WEB"
        set subnet 10.231.32.10 255.255.255.255
    next
end
config firewall policy
    edit 20
        set name "ALLOW-LAN-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-USERS"
        set dstaddr "DMZ-WEB"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
    edit 10
        set name "DENY-RESTRICTED-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-RESTRICTED"
        set dstaddr "DMZ-WEB"
        set action deny
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end
"""

_CUSTOM_PORT_CONFIG = """
config firewall address
    edit "LAN-CLIENT"
        set subnet 10.231.31.10 255.255.255.255
    next
    edit "DMZ-API"
        set subnet 10.231.32.10 255.255.255.255
    next
end
config firewall service custom
    edit "LAB-API-TCP"
        set tcp-portrange 8081
    next
end
config firewall policy
    edit 10
        set name "ALLOW-LAN-API"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-CLIENT"
        set dstaddr "DMZ-API"
        set action accept
        set schedule "always"
        set service "LAB-API-TCP"
        set logtraffic all
    next
    edit 20
        set name "DENY-LAN-HTTP"
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "LAN-CLIENT"
        set dstaddr "DMZ-API"
        set action deny
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end
"""

_CUSTOM_PORT_STARTER_CONFIG = _CUSTOM_PORT_CONFIG.replace(
    "set tcp-portrange 8081",
    "set tcp-portrange 8080",
)


_EXERCISES = (
    _exercise(
        "scoped-http-allow",
        "Scoped HTTP allow",
        "Allow one LAN client to one DMZ web object on TCP/80 and explicitly deny the same pair on SSH.",
        _SCOPED_HTTP_CONFIG,
        (
            _Case(
                "lan-http-allowed",
                "The scoped web request must hit the explicit allow.",
                "10.231.31.10",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                80,
                "allowed",
                _policy(
                    10,
                    "ALLOW-LAN-HTTP",
                    srcaddr=("LAN-CLIENT",),
                    dstaddr=("DMZ-WEB",),
                    service=("HTTP",),
                    action="accept",
                ),
            ),
            _Case(
                "lan-ssh-explicitly-denied",
                "The same scoped pair on SSH must hit an explicit deny, not implicit default deny.",
                "10.231.31.10",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                22,
                "blocked",
                _policy(
                    20,
                    "DENY-LAN-SSH",
                    srcaddr=("LAN-CLIENT",),
                    dstaddr=("DMZ-WEB",),
                    service=("SSH",),
                    action="deny",
                ),
            ),
        ),
        starter_config=_SCOPED_HTTP_STARTER_CONFIG,
        task_prompt="Add the missing explicit SSH deny for the scoped LAN client and DMZ web object.",
        task_prompt_ru="Добавьте явный запрет SSH для заданных клиента LAN и веб-объекта DMZ.",
        help_text="Required repair: policy ID 20 named DENY-LAN-SSH, srcaddr LAN-CLIENT, dstaddr DMZ-WEB, service SSH, action deny. Do not use ALL or rely on implicit deny.",
        help_ru="Требуемое исправление: policy ID 20 с именем DENY-LAN-SSH, srcaddr LAN-CLIENT, dstaddr DMZ-WEB, service SSH, action deny. Не используйте ALL и implicit deny.",
    ),
    _exercise(
        "ordered-exception",
        "Ordered exception before broad allow",
        "Deny a restricted LAN host before the broader LAN HTTP allow; both policies use the same DMZ destination.",
        _ORDERED_EXCEPTION_CONFIG,
        (
            _Case(
                "restricted-http-denied",
                "The restricted host must stop at the first, narrower deny.",
                "10.231.31.20",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                80,
                "blocked",
                _policy(
                    10,
                    "DENY-RESTRICTED-HTTP",
                    srcaddr=("LAN-RESTRICTED",),
                    dstaddr=("DMZ-WEB",),
                    service=("HTTP",),
                    action="deny",
                ),
            ),
            _Case(
                "regular-http-allowed",
                "A regular LAN host must continue to the broader allow.",
                "10.231.31.10",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                80,
                "allowed",
                _policy(
                    20,
                    "ALLOW-LAN-HTTP",
                    srcaddr=("LAN-USERS",),
                    dstaddr=("DMZ-WEB",),
                    service=("HTTP",),
                    action="accept",
                ),
            ),
        ),
        starter_config=_ORDERED_EXCEPTION_STARTER_CONFIG,
        task_prompt="Move the restricted deny before the broad LAN HTTP allow so first-match order protects the exception.",
        task_prompt_ru="Переместите узкий запрет для restricted-хоста перед общим разрешением HTTP LAN.",
        help_text="Required order: policy ID 10 DENY-RESTRICTED-HTTP must appear before policy ID 20 ALLOW-LAN-HTTP.",
        help_ru="Требуемый порядок: policy ID 10 DENY-RESTRICTED-HTTP должен идти перед policy ID 20 ALLOW-LAN-HTTP.",
    ),
    _exercise(
        "custom-tcp-port",
        "Custom TCP service",
        "Define a custom TCP service on 8081, allow only that service, and explicitly deny ordinary HTTP.",
        _CUSTOM_PORT_CONFIG,
        (
            _Case(
                "custom-api-allowed",
                "The custom service must allow TCP/8081.",
                "10.231.31.10",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                8081,
                "allowed",
                _policy(
                    10,
                    "ALLOW-LAN-API",
                    srcaddr=("LAN-CLIENT",),
                    dstaddr=("DMZ-API",),
                    service=("LAB-API-TCP",),
                    action="accept",
                ),
            ),
            _Case(
                "ordinary-http-denied",
                "The same API object must explicitly deny TCP/80.",
                "10.231.31.10",
                "10.231.32.10",
                "port2",
                "port3",
                "tcp",
                80,
                "blocked",
                _policy(
                    20,
                    "DENY-LAN-HTTP",
                    srcaddr=("LAN-CLIENT",),
                    dstaddr=("DMZ-API",),
                    service=("HTTP",),
                    action="deny",
                ),
            ),
        ),
        starter_config=_CUSTOM_PORT_STARTER_CONFIG,
        task_prompt="Repair the custom TCP service so the scoped API rule allows TCP/8081 and still explicitly denies HTTP.",
        task_prompt_ru="Исправьте собственную TCP-службу: scoped API должен разрешать TCP/8081 и явно запрещать HTTP.",
        help_text="Required service: LAB-API-TCP must use tcp-portrange 8081. Keep the exercise within the FortiOS trial limit of three firewall policies.",
        help_ru="Требуемая служба: LAB-API-TCP должна использовать tcp-portrange 8081. В упражнении должно быть не более трех firewall policy.",
    ),
)

_EXERCISE_BY_ID = {exercise.exercise_id: exercise for exercise in _EXERCISES}
_RUSSIAN_META = {
    "scoped-http-allow": {
        "title": "Ограниченное разрешение HTTP",
        "description": "Разрешите одному клиенту LAN доступ к веб-объекту DMZ по TCP/80 и явно запретите SSH для той же пары.",
    },
    "ordered-exception": {
        "title": "Приоритет исключения перед общим разрешением",
        "description": "Сначала запретите HTTP для ограниченного узла LAN, затем разрешите HTTP для более широкой сети LAN.",
    },
    "custom-tcp-port": {
        "title": "Собственная служба TCP",
        "description": "Определите TCP-службу 8081, разрешите только ее и явно запретите обычный HTTP.",
    },
}


def catalog() -> list[dict[str, Any]]:
    """Return independent, JSON-serializable exercise definitions."""

    result: list[dict[str, Any]] = []
    for exercise in _EXERCISES:
        result.append(
            {
                "id": exercise.exercise_id,
                "title": exercise.title,
                "title_ru": _RUSSIAN_META[exercise.exercise_id]["title"],
                "description": exercise.description,
                "description_ru": _RUSSIAN_META[exercise.exercise_id]["description"],
                # Public callers receive the repair starter, never the hidden
                # reference config kept in _Exercise.config for grading/tests.
                "config": exercise.starter_config,
                "task_prompt": exercise.task_prompt,
                "task_prompt_ru": exercise.task_prompt_ru,
                "help": exercise.help,
                "help_ru": exercise.help_ru,
                "firewall_policy_limit": 3,
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


def _case_feedback_ru(kind: str) -> str:
    messages = {
        "pass": "Совпали ожидаемое первое правило и его точная область действия.",
        "parse": "Конфигурация не разобрана; сначала исправьте ошибки CLI.",
        "implicit": "Явное правило не совпало: implicit deny не засчитывается для этого случая.",
        "identity": "Сработало другое первое правило; проверьте порядок и более узкое исключение.",
        "scope": "Идентификатор правила совпал, но область действия отличается; широкое правило не засчитывается.",
        "outcome": "Первое совпавшее правило возвращает другой результат.",
    }
    return messages[kind]


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
                "message_ru": f"Неизвестное упражнение {exercise_id!r}.",
                "hint": "Choose an id returned by catalog().",
                "hint_ru": "Выберите id, возвращенный catalog().",
            }
        )
        return result
    if not isinstance(config_text, str):
        result["errors"].append(
            {
                "code": "invalid_input",
                "line": 0,
                "message": "config_text must be a string containing native CLI text.",
                "message_ru": "config_text должен быть строкой с native CLI-конфигурацией.",
                "hint": "Pass the editable FortiOS config snippet, not a parsed object.",
                "hint_ru": "Передайте редактируемый CLI-фрагмент, а не разобранный объект.",
            }
        )
        return result

    parsed = _parse_config(config_text)
    result["errors"] = copy.deepcopy(parsed.errors)
    result["summary"]["total"] = len(exercise.cases)
    if parsed.errors:
        result["feedback"] = "Fix the configuration errors before grading traffic cases."
        result["feedback_ru"] = _case_feedback_ru("parse")
        result["cases"] = [
            {
                **_case_public(case),
                "expected_rule_identity": _rule_identity(case.expected_policy),
                "actual_rule_identity": None,
                "actual": None,
                "pass": False,
                "feedback": "Configuration parsing failed; this case was not evaluated.",
                "feedback_ru": _case_feedback_ru("parse"),
            }
            for case in exercise.cases
        ]
        return result

    for case in exercise.cases:
        actual_policy = next(
            (policy for policy in parsed.policies if _matches(policy, case, parsed)),
            None,
        )
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
        scope_pass = (
            actual_policy is not None
            and _policy_signature(actual_policy) == _expected_signature(case)
        )
        case_pass = (
            actual_outcome == case.expected_outcome
            and identity_pass
            and scope_pass
        )
        if case_pass:
            feedback = "Matched the expected first rule and exact scope."
            feedback_ru = _case_feedback_ru("pass")
        elif actual_policy is None:
            feedback = (
                "No explicit policy matched; this is implicit default deny and "
                "cannot satisfy an explicit-denial case."
            )
            feedback_ru = _case_feedback_ru("implicit")
        elif not identity_pass:
            feedback = (
                f"First matching policy is {actual_policy.policy_id} "
                f"{actual_policy.name!r}; expected {case.expected_policy.policy_id} "
                f"{case.expected_policy.name!r}. Check policy order and narrower exceptions."
            )
            feedback_ru = _case_feedback_ru("identity")
        elif not scope_pass:
            feedback = (
                "The expected rule identity matched, but its scope differs. "
                "Do not replace the required address/service scope with a broad catch-all."
            )
            feedback_ru = _case_feedback_ru("scope")
        else:
            feedback = (
                f"Expected {case.expected_outcome}, but the first matching rule "
                f"returns {actual_outcome}."
            )
            feedback_ru = _case_feedback_ru("outcome")
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
                "feedback_ru": feedback_ru,
            }
        )

    passed = sum(1 for case in result["cases"] if case["pass"])
    result["summary"]["passed"] = passed
    result["pass"] = passed == len(exercise.cases)
    result["feedback"] = (
        "All positive and explicit-negative cases passed."
        if result["pass"]
        else "At least one case failed; use each case's actionable feedback."
    )
    result["feedback_ru"] = (
        "Все позитивные и явно отрицательные случаи пройдены."
        if result["pass"]
        else "Есть ошибки; используйте пошаговые подсказки каждого случая."
    )
    return result


__all__ = ["catalog", "grade"]
