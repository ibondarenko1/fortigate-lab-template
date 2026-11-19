#!/usr/bin/env python3
"""Apply or remove the narrowly scoped Docker bridge fixture rules.

The command discovers the currently running Compose client/server containers,
their project-labelled internal bridge networks, and their exact IPv4
addresses. It then owns only matching IPv4 DOCKER-USER rules for TCP/80 and
TCP/8080 in both directions. No shell is evaluated and no broad chain or
address cleanup is attempted.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


DOCKER_COMPOSE_FILE = "compose.yaml"
COMPOSE_NETWORKS = {"client": "lan", "server": "dmz"}
PORTS = (80, 8080)
IPTABLES_WAIT = "5"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class FixtureError(RuntimeError):
    """A safe, actionable discovery or iptables error."""


@dataclass(frozen=True)
class Endpoint:
    service: str
    container_id: str
    project: str
    compose_network: str
    network_id: str
    network_name: str
    bridge_name: str
    ipv4: ipaddress.IPv4Address


@dataclass(frozen=True)
class Fixture:
    deploy_dir: Path
    project: str
    client: Endpoint
    server: Endpoint
    comment: str


def _run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        command = args[0] if args else "<empty>"
        raise FixtureError(f"Required command is not installed: {command}.") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise FixtureError(
            f"Command failed ({' '.join(args)}): {detail or 'no diagnostic output'}."
        )
    return result


def _json_command(args: Sequence[str], *, cwd: Path) -> Any:
    result = _run(args, cwd=cwd)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise FixtureError(
            f"Command returned invalid JSON ({' '.join(args)})."
        ) from exc


def _resolve_deploy_dir(value: str | None) -> Path:
    if value:
        deploy_dir = Path(value).expanduser().resolve()
    else:
        # fixture-bridge.py lives under deploy/scripts.
        deploy_dir = Path(__file__).resolve().parent.parent
    if not (deploy_dir / DOCKER_COMPOSE_FILE).is_file():
        raise FixtureError(
            f"Deployment directory {deploy_dir} does not contain {DOCKER_COMPOSE_FILE}."
        )
    return deploy_dir


def _compose_container_id(deploy_dir: Path, service: str) -> str:
    result = _run(
        ["docker", "compose", "-f", DOCKER_COMPOSE_FILE, "ps", "-q", service],
        cwd=deploy_dir,
    )
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(ids) != 1:
        raise FixtureError(
            f"Compose service {service!r} must have exactly one current container; "
            f"found {len(ids)}. Start the lab and avoid scaling this fixed fixture."
        )
    container_id = ids[0]
    if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id):
        raise FixtureError(f"Compose returned an invalid container ID for {service!r}.")
    return container_id


def _container_inspect(deploy_dir: Path, container_id: str) -> dict[str, Any]:
    payload = _json_command(["docker", "inspect", container_id], cwd=deploy_dir)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise FixtureError(f"Docker inspect returned no unique container {container_id}.")
    return payload[0]


def _network_inspect(deploy_dir: Path, network_id: str) -> dict[str, Any]:
    payload = _json_command(["docker", "network", "inspect", network_id], cwd=deploy_dir)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise FixtureError(f"Docker inspect returned no unique network {network_id}.")
    network = payload[0]
    actual_id = str(network.get("Id", ""))
    if actual_id and actual_id.lower() != network_id.lower():
        raise FixtureError(
            f"Docker network identity changed during discovery: expected {network_id}, "
            f"got {actual_id}."
        )
    return network


def _bridge_name(network: dict[str, Any], network_id: str) -> str:
    options = network.get("Options") or {}
    configured = options.get("com.docker.network.bridge.name")
    if configured:
        bridge = str(configured)
    else:
        # Docker's user-defined bridge driver uses br-<first-12-network-id>
        # when no explicit bridge name is configured.
        bridge = f"br-{network_id[:12]}"
    if not SAFE_NAME.fullmatch(bridge) or len(bridge) > 15:
        raise FixtureError(f"Unsafe or invalid Linux bridge name discovered: {bridge!r}.")
    return bridge


def _endpoint(
    deploy_dir: Path,
    service: str,
    container_id: str,
) -> Endpoint:
    container = _container_inspect(deploy_dir, container_id)
    config = container.get("Config") or {}
    labels = config.get("Labels") or {}
    project = str(labels.get("com.docker.compose.project") or "")
    service_label = str(labels.get("com.docker.compose.service") or "")
    if not SAFE_NAME.fullmatch(project):
        raise FixtureError(
            f"Container {container_id} has no safe com.docker.compose.project label."
        )
    if service_label != service:
        raise FixtureError(
            f"Container {container_id} is labelled as {service_label!r}, not {service!r}."
        )

    expected_network = COMPOSE_NETWORKS[service]
    networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
    candidates: list[Endpoint] = []
    for network_alias, membership in networks.items():
        if not isinstance(membership, dict):
            continue
        network_id = str(membership.get("NetworkID") or "")
        ipv4_text = str(membership.get("IPAddress") or "")
        if not network_id or not ipv4_text:
            continue
        try:
            ipv4 = ipaddress.IPv4Address(ipv4_text)
        except ipaddress.AddressValueError as exc:
            raise FixtureError(
                f"Container {service!r} has a non-IPv4 address on network {network_alias!r}."
            ) from exc
        network = _network_inspect(deploy_dir, network_id)
        network_labels = network.get("Labels") or {}
        if network_labels.get("com.docker.compose.project") != project:
            continue
        compose_network = str(network_labels.get("com.docker.compose.network") or "")
        if compose_network != expected_network:
            continue
        if network.get("Driver") != "bridge" or network.get("Internal") is not True:
            raise FixtureError(
                f"Compose network {compose_network!r} for {service!r} is not an internal "
                "Docker bridge; refusing to install fixture rules."
            )
        containers = network.get("Containers") or {}
        member = containers.get(container_id)
        if member is None:
            member = next(
                (value for key, value in containers.items() if key.startswith(container_id)),
                None,
            )
        if not isinstance(member, dict):
            raise FixtureError(
                f"Container {container_id} is not an exact member of network {network_id}."
            )
        network_ipv4 = str(member.get("IPv4Address") or "").split("/", 1)[0]
        if network_ipv4 != str(ipv4):
            raise FixtureError(
                f"Container {service!r} address disagrees between Docker endpoints "
                f"({ipv4}) and network membership ({network_ipv4})."
            )
        candidates.append(
            Endpoint(
                service=service,
                container_id=container_id,
                project=project,
                compose_network=compose_network,
                network_id=network_id,
                network_name=str(network.get("Name") or network_alias),
                bridge_name=_bridge_name(network, network_id),
                ipv4=ipv4,
            )
        )

    if len(candidates) != 1:
        raise FixtureError(
            f"Could not resolve exactly one labelled internal {expected_network!r} "
            f"bridge for {service!r}; found {len(candidates)}."
        )
    return candidates[0]


def discover(deploy_dir: Path) -> Fixture:
    """Discover one fixed client/server pair and their two internal bridges."""

    client_id = _compose_container_id(deploy_dir, "client")
    server_id = _compose_container_id(deploy_dir, "server")
    client = _endpoint(deploy_dir, "client", client_id)
    server = _endpoint(deploy_dir, "server", server_id)
    if client.project != server.project:
        raise FixtureError("Client and server belong to different Compose projects.")
    if client.ipv4 == server.ipv4:
        raise FixtureError("Client and server resolved to the same IPv4 address.")
    if client.network_id == server.network_id:
        raise FixtureError("Client and server must be on two distinct lab bridges.")
    if client.bridge_name == server.bridge_name:
        raise FixtureError("Client and server resolved to the same Linux bridge.")
    comment = (
        f"fortigate-lab-fixture:{client.project}:"
        f"{client.network_id[:12]}:{server.network_id[:12]}"
    )
    if len(comment) > 200:
        raise FixtureError("Generated iptables comment is unexpectedly long.")
    return Fixture(
        deploy_dir=deploy_dir,
        project=client.project,
        client=client,
        server=server,
        comment=comment,
    )


def _iptables_preflight() -> str:
    if shutil.which("iptables") is None:
        raise FixtureError(
            "iptables Docker backend is missing: the iptables command is not installed."
        )
    version = _run(["iptables", "--version"], check=False)
    if version.returncode != 0:
        detail = (version.stderr or version.stdout).strip()
        raise FixtureError(
            "iptables Docker backend is unavailable: "
            f"iptables --version failed ({detail or 'no diagnostic output'})."
        )
    chain = _run(
        ["iptables", "-w", IPTABLES_WAIT, "-t", "filter", "-S", "DOCKER-USER"],
        check=False,
    )
    if chain.returncode != 0:
        detail = (chain.stderr or chain.stdout).strip()
        raise FixtureError(
            "iptables Docker backend is missing the filter/DOCKER-USER chain; "
            "start Docker with its iptables integration enabled. "
            f"Diagnostic: {detail or 'no diagnostic output'}."
        )
    physdev = _run(
        ["iptables", "-w", IPTABLES_WAIT, "-m", "physdev", "--help"],
        check=False,
    )
    if physdev.returncode != 0:
        detail = (physdev.stderr or physdev.stdout).strip()
        raise FixtureError(
            "iptables Docker backend lacks the physdev match required for bridged "
            f"fixture traffic. Diagnostic: {detail or 'no diagnostic output'}."
        )
    return version.stdout.strip()


def _rule(
    *,
    incoming: str,
    outgoing: str,
    source: ipaddress.IPv4Address,
    destination: ipaddress.IPv4Address,
    ports: Sequence[int],
    source_port: bool,
    comment: str,
) -> tuple[str, ...]:
    port_flag = "--sports" if source_port else "--dports"
    return (
        "-i",
        incoming,
        "-o",
        outgoing,
        "-s",
        f"{source}/32",
        "-d",
        f"{destination}/32",
        "-m",
        "physdev",
        "--physdev-is-bridged",
        "-p",
        "tcp",
        "-m",
        "multiport",
        port_flag,
        ",".join(str(port) for port in ports),
        "-m",
        "comment",
        "--comment",
        comment,
        "-j",
        "ACCEPT",
    )


def rules(fixture: Fixture) -> tuple[tuple[str, ...], ...]:
    """Return the four exact rules owned by this fixture (two ports, two directions)."""

    result: list[tuple[str, ...]] = []
    for bridge in (fixture.client.bridge_name, fixture.server.bridge_name):
        result.append(
            _rule(
                incoming=bridge,
                outgoing=bridge,
                source=fixture.client.ipv4,
                destination=fixture.server.ipv4,
                ports=PORTS,
                source_port=False,
                comment=fixture.comment,
            )
        )
        result.append(
            _rule(
                incoming=bridge,
                outgoing=bridge,
                source=fixture.server.ipv4,
                destination=fixture.client.ipv4,
                ports=PORTS,
                source_port=True,
                comment=fixture.comment,
            )
        )
    generated = tuple(result)
    if len(generated) != 4 or any(
        rule[rule.index("-i") + 1] != rule[rule.index("-o") + 1]
        for rule in generated
    ):
        raise FixtureError("Internal fixture rule invariant failed: every rule must use one bridge for -i and -o.")
    return generated


def _rule_present(rule: Sequence[str]) -> bool:
    result = _run(
        ["iptables", "-w", IPTABLES_WAIT, "-t", "filter", "-C", "DOCKER-USER", *rule],
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = (result.stderr or result.stdout).strip()
    raise FixtureError(
        f"iptables could not check the exact DOCKER-USER rule: "
        f"{detail or 'no diagnostic output'}."
    )


def _insert(rule: Sequence[str]) -> None:
    _run(
        ["iptables", "-w", IPTABLES_WAIT, "-t", "filter", "-I", "DOCKER-USER", "1", *rule]
    )


def _delete(rule: Sequence[str]) -> None:
    _run(
        ["iptables", "-w", IPTABLES_WAIT, "-t", "filter", "-D", "DOCKER-USER", *rule]
    )


def apply_fixture(fixture: Fixture, *, dry_run: bool = False) -> int:
    version = _iptables_preflight()
    rule_set = rules(fixture)
    added = 0
    for rule in rule_set:
        if _rule_present(rule):
            continue
        if not dry_run:
            _insert(rule)
        added += 1
    print(
        json.dumps(
            {
                "action": "apply",
                "dry_run": dry_run,
                "project": fixture.project,
                "iptables": version,
                "client": str(fixture.client.ipv4),
                "server": str(fixture.server.ipv4),
                "bridges": [fixture.client.bridge_name, fixture.server.bridge_name],
                "rules": len(rule_set),
                "added": added,
                "comment": fixture.comment,
            },
            sort_keys=True,
        )
    )
    return 0


def remove_fixture(fixture: Fixture, *, dry_run: bool = False) -> int:
    version = _iptables_preflight()
    rule_set = rules(fixture)
    removed = 0
    for rule in rule_set:
        if not _rule_present(rule):
            continue
        if not dry_run:
            _delete(rule)
        removed += 1
    print(
        json.dumps(
            {
                "action": "remove",
                "dry_run": dry_run,
                "project": fixture.project,
                "iptables": version,
                "rules": len(rule_set),
                "removed": removed,
                "comment": fixture.comment,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely own the fixed FortiGate lab client/server DOCKER-USER fixture."
    )
    parser.add_argument("action", choices=("apply", "remove"))
    parser.add_argument(
        "--deploy-dir",
        help="directory containing compose.yaml (default: this script's parent deploy directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="discover and validate everything but do not insert or delete rules",
    )
    args = parser.parse_args(argv)
    try:
        deploy_dir = _resolve_deploy_dir(args.deploy_dir)
        fixture = discover(deploy_dir)
        if args.action == "apply":
            return apply_fixture(fixture, dry_run=args.dry_run)
        return remove_fixture(fixture, dry_run=args.dry_run)
    except FixtureError as exc:
        print(f"fixture-bridge: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
