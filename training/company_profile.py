"""Bounded native CMDB profile reconciliation for the LABCO training lab.

The profile is deliberately narrower than a general FortiOS provisioner. It
creates only LABCO-prefixed local users, user groups, one RADIUS definition,
IPv4 address objects, and address groups. It never touches interfaces, routes,
firewall policies, administrators, or any object outside its private manifest.

The client is intentionally tiny and injectable:

    get(table, name) -> dict | None
    create(table, data)
    delete(table, name)

No networking or vendor SDK is used here. A caller can adapt those three
operations to the native FortiOS REST API in a separate integration layer.
"""

from __future__ import annotations

import contextlib
import copy
import ipaddress
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows-only test fallback.
    fcntl = None


OWNER = "LABCO-company-profile-v1"
SCHEMA = 1
MANIFEST_NAME = ".labco-company-profile.json"
LOCK_NAME = ".labco-company-profile.lock"
MAX_NAME_LENGTH = 31
COUNT_KEYS = ("users", "groups", "radius", "addresses", "address_groups")

USER_TABLE = "user/local"
GROUP_TABLE = "user/group"
RADIUS_TABLE = "user/radius"
ADDRESS_TABLE = "firewall/address"
ADDRESS_GROUP_TABLE = "firewall/addrgrp"


class NativeClient(Protocol):
    def get(self, table: str, name: str) -> dict[str, Any] | None: ...

    def create(self, table: str, data: dict[str, Any]) -> Any: ...

    def delete(self, table: str, name: str) -> Any: ...


class ProfileConflict(RuntimeError):
    """A safe preflight or ownership conflict; no mutation should follow."""


@dataclass(frozen=True)
class _Resource:
    key: str
    kind: str
    table: str
    name: str
    payload: dict[str, Any]
    depends_on: tuple[str, ...] = ()


_USERS: tuple[tuple[str, str], ...] = (
    ("LABCO-HR-ALICE", "Human Resources"),
    ("LABCO-HR-BOB", "Human Resources"),
    ("LABCO-HR-CAROL", "Human Resources"),
    ("LABCO-FIN-DAVE", "Finance"),
    ("LABCO-FIN-EVE", "Finance"),
    ("LABCO-FIN-FRANK", "Finance"),
    ("LABCO-ENG-GRACE", "Engineering"),
    ("LABCO-ENG-HEIDI", "Engineering"),
    ("LABCO-ENG-IVAN", "Engineering"),
    ("LABCO-OPS-JUDY", "Operations"),
    ("LABCO-OPS-MALLORY", "Operations"),
    ("LABCO-OPS-NIA", "Operations"),
)

_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "LABCO-GRP-HR",
        ("LABCO-HR-ALICE", "LABCO-HR-BOB", "LABCO-HR-CAROL"),
    ),
    (
        "LABCO-GRP-FIN",
        ("LABCO-FIN-DAVE", "LABCO-FIN-EVE", "LABCO-FIN-FRANK"),
    ),
    (
        "LABCO-GRP-ENG",
        ("LABCO-ENG-GRACE", "LABCO-ENG-HEIDI", "LABCO-ENG-IVAN"),
    ),
    (
        "LABCO-GRP-OPS",
        ("LABCO-OPS-JUDY", "LABCO-OPS-MALLORY", "LABCO-OPS-NIA"),
    ),
    ("LABCO-GRP-STAFF", tuple(name for name, _ in _USERS)),
    ("LABCO-GRP-RADIUS", ("LABCO-RADIUS",)),
)

_ADDRESS_NAMES: tuple[str, ...] = (
    "LABCO-ADDR-LAN",
    "LABCO-ADDR-DMZ",
    "LABCO-ADDR-WEB",
    "LABCO-ADDR-RADIUS",
    "LABCO-ADDR-ADMIN",
    "LABCO-ADDR-VPN",
)

_ADDRESS_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("LABCO-AG-LAN", ("LABCO-ADDR-LAN", "LABCO-ADDR-ADMIN")),
    (
        "LABCO-AG-DMZ",
        ("LABCO-ADDR-DMZ", "LABCO-ADDR-WEB", "LABCO-ADDR-RADIUS"),
    ),
    (
        "LABCO-AG-CORP",
        ("LABCO-ADDR-LAN", "LABCO-ADDR-DMZ", "LABCO-ADDR-VPN"),
    ),
)


def _validate_static_names() -> None:
    names: list[str] = []
    names.extend(name for name, _ in _USERS)
    names.extend(name for name, _ in _GROUPS)
    names.append("LABCO-RADIUS")
    names.extend(_ADDRESS_NAMES)
    names.extend(name for name, _ in _ADDRESS_GROUPS)
    if len(names) != len(set(names)):
        raise RuntimeError("LABCO profile contains duplicate object names")
    if any(
        not name.startswith("LABCO-") or len(name) > MAX_NAME_LENGTH
        for name in names
    ):
        raise RuntimeError("LABCO profile contains an invalid FortiOS object name")


_validate_static_names()


def _zero_counts() -> dict[str, int]:
    return {key: 0 for key in COUNT_KEYS}


def _safe_error(action: str, resource: _Resource | None, exc: BaseException) -> dict[str, str]:
    """Return an error without serializing any native payload or secret."""

    location = ""
    if resource is not None:
        location = f" for {resource.table}/{resource.name}"
    return {
        "code": "native_operation_failed",
        "message": f"{action} failed{location}: {type(exc).__name__}.",
    }


def _resource_key(table: str, name: str) -> str:
    return f"{table}:{name}"


def _member_list(names: Iterable[str]) -> list[dict[str, str]]:
    return [{"name": name} for name in names]


class CompanyProfile:
    """Reconcile one fixed, namespaced corporate training profile."""

    def __init__(
        self,
        client: NativeClient,
        state_dir: str | os.PathLike[str],
        radius_ip: str,
        radius_source_ip: str | None,
        radius_secret: str,
        test_password: str | None,
        *,
        lan_cidr: str = "10.231.31.0/24",
        dmz_cidr: str = "10.231.32.0/24",
        lan_node: str = "10.231.31.10",
        dmz_node: str = "10.231.32.20",
    ) -> None:
        self.client = client
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.radius_ip = self._validate_ipv4(radius_ip, "radius_ip")
        self.radius_source_ip = (
            self._validate_ipv4(radius_source_ip, "radius_source_ip")
            if radius_source_ip
            else None
        )
        if not isinstance(radius_secret, str) or not radius_secret:
            raise ValueError("radius_secret must be a non-empty string")
        self._radius_secret = radius_secret
        self.lan_network = self._validate_cidr(lan_cidr, "lan_cidr")
        self.dmz_network = self._validate_cidr(dmz_cidr, "dmz_cidr")
        self.lan_node = self._validate_ipv4(lan_node, "lan_node")
        self.dmz_node = self._validate_ipv4(dmz_node, "dmz_node")
        if ipaddress.IPv4Address(self.lan_node) not in self.lan_network:
            raise ValueError("lan_node must be inside lan_cidr")
        if ipaddress.IPv4Address(self.dmz_node) not in self.dmz_network:
            raise ValueError("dmz_node must be inside dmz_cidr")
        if self.lan_network.overlaps(self.dmz_network):
            raise ValueError("lan_cidr and dmz_cidr must not overlap")
        # The supplied test password is accepted by the integration contract
        # for the caller's login exercise. Native profile passwords remain
        # unique random values and are never persisted or returned.
        if test_password is not None and not isinstance(test_password, str):
            raise ValueError("test_password must be a string or None")
        self._test_password = test_password

    @staticmethod
    def _validate_ipv4(value: str, field: str) -> str:
        try:
            address = ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
            raise ValueError(f"{field} must be an IPv4 address") from exc
        return str(address)

    @staticmethod
    def _validate_cidr(value: str, field: str) -> ipaddress.IPv4Network:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{field} must be an IPv4 CIDR") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError(f"{field} must be an IPv4 CIDR")
        return network

    @property
    def _manifest_path(self) -> Path:
        return self.state_dir / MANIFEST_NAME

    @property
    def _lock_path(self) -> Path:
        return self.state_dir / LOCK_NAME

    @contextlib.contextmanager
    def _lock(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.state_dir, 0o700)
        except OSError:
            pass
        handle = self._lock_path.open("a+", encoding="utf-8")
        try:
            try:
                os.chmod(self._lock_path, 0o600)
            except OSError:
                pass
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _random_password(self, used: set[str]) -> str:
        while True:
            value = secrets.token_urlsafe(24)
            if (
                value not in used
                and value != self._test_password
                and value != self._radius_secret
            ):
                used.add(value)
                return value

    def _resources(self) -> tuple[_Resource, ...]:
        used_passwords: set[str] = set()
        resources: list[_Resource] = []
        for name, _department in _USERS:
            resources.append(
                _Resource(
                    key=_resource_key(USER_TABLE, name),
                    kind="users",
                    table=USER_TABLE,
                    name=name,
                    payload={
                        "name": name,
                        "type": "password",
                        "passwd": self._random_password(used_passwords),
                        "status": "enable",
                        "email-to": f"{name.rsplit('-', 1)[-1].lower()}@labco.example",
                    },
                )
            )

        radius_payload: dict[str, Any] = {
            "name": "LABCO-RADIUS",
            "server": self.radius_ip,
            "radius-port": 1812,
            "auth-type": "pap",
            "secret": self._radius_secret,
        }
        if self.radius_source_ip:
            radius_payload["source-ip"] = self.radius_source_ip
        resources.append(
            _Resource(
                key=_resource_key(RADIUS_TABLE, "LABCO-RADIUS"),
                kind="radius",
                table=RADIUS_TABLE,
                name="LABCO-RADIUS",
                payload=radius_payload,
            )
        )

        for name, members in _GROUPS:
            dependencies = tuple(
                _resource_key(RADIUS_TABLE if member == "LABCO-RADIUS" else USER_TABLE, member)
                for member in members
            )
            resources.append(
                _Resource(
                    key=_resource_key(GROUP_TABLE, name),
                    kind="groups",
                    table=GROUP_TABLE,
                    name=name,
                    payload={
                        "name": name,
                        "group-type": "firewall",
                        "member": _member_list(members),
                    },
                    depends_on=dependencies,
                )
            )

        address_specs = (
            ("LABCO-ADDR-LAN", str(self.lan_network.network_address), str(self.lan_network.netmask)),
            ("LABCO-ADDR-DMZ", str(self.dmz_network.network_address), str(self.dmz_network.netmask)),
            ("LABCO-ADDR-WEB", self.dmz_node, "255.255.255.255"),
            ("LABCO-ADDR-RADIUS", self.radius_ip, "255.255.255.255"),
            ("LABCO-ADDR-ADMIN", self.lan_node, "255.255.255.255"),
            # Documentation-only reserved range for future VPN exercises.
            ("LABCO-ADDR-VPN", "192.0.2.0", "255.255.255.0"),
        )
        for name, address, mask in address_specs:
            # Validate the fixed topology before it reaches a native client.
            network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            resources.append(
                _Resource(
                    key=_resource_key(ADDRESS_TABLE, name),
                    kind="addresses",
                    table=ADDRESS_TABLE,
                    name=name,
                    payload={
                        "name": name,
                        "type": "ipmask",
                        "subnet": f"{network.network_address} {network.netmask}",
                    },
                )
            )

        for name, members in _ADDRESS_GROUPS:
            dependencies = tuple(_resource_key(ADDRESS_TABLE, member) for member in members)
            resources.append(
                _Resource(
                    key=_resource_key(ADDRESS_GROUP_TABLE, name),
                    kind="address_groups",
                    table=ADDRESS_GROUP_TABLE,
                    name=name,
                    payload={
                        "name": name,
                        "member": _member_list(members),
                    },
                    depends_on=dependencies,
                )
            )
        return tuple(resources)

    @property
    def _radius_secret(self) -> str:
        # Keep the secret only on the instance and only in the create payload.
        return self.__dict__["_radius_secret_value"]

    @_radius_secret.setter
    def _radius_secret(self, value: str) -> None:
        self.__dict__["_radius_secret_value"] = value

    def _resource_metadata(self, resources: Sequence[_Resource]) -> list[dict[str, Any]]:
        return [
            {
                "key": resource.key,
                "kind": resource.kind,
                "table": resource.table,
                "name": resource.name,
                "depends_on": list(resource.depends_on),
            }
            for resource in resources
        ]

    def _profile_identity(self) -> dict[str, str | None]:
        """Return non-secret inputs that determine the native object topology."""

        return {
            "radius_ip": self.radius_ip,
            "radius_source_ip": self.radius_source_ip,
            "lan_cidr": str(self.lan_network),
            "dmz_cidr": str(self.dmz_network),
            "lan_node": self.lan_node,
            "dmz_node": self.dmz_node,
        }

    def _new_manifest(self, resources: Sequence[_Resource]) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "owner": OWNER,
            "state": "pending",
            "profile": self._profile_identity(),
            "resources": self._resource_metadata(resources),
            # ``owned`` contains only resources whose native create call
            # returned successfully.  A name merely listed in resources is
            # never enough to authorize adoption or deletion.
            "owned": [],
            # A create is recorded before the native call.  If the process
            # dies or the call raises after a remote side effect, a later
            # run can stop on the ambiguous object instead of deleting it.
            "pending": None,
            # Keep the old progress-shaped field as a public-on-disk
            # compatibility aid, but mirror only confirmed ownership in it.
            "completed": [],
            "removed": [],
            "updated_at": time.time(),
        }

    def _load_manifest(self) -> dict[str, Any] | None:
        if not self._manifest_path.exists():
            return None
        try:
            value = json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileConflict("profile manifest is unreadable") from exc
        if not isinstance(value, dict) or value.get("owner") != OWNER:
            raise ProfileConflict("profile manifest owner does not match LABCO")
        if value.get("schema") != SCHEMA:
            raise ProfileConflict("profile manifest schema is unsupported")
        return value

    def _validate_manifest(
        self,
        manifest: Mapping[str, Any],
        resources: Sequence[_Resource],
    ) -> None:
        if manifest.get("profile") != self._profile_identity():
            raise ProfileConflict("profile manifest topology does not match this profile")
        expected = self._resource_metadata(resources)
        if manifest.get("resources") != expected:
            raise ProfileConflict("profile manifest resources do not match this profile")
        state = manifest.get("state")
        if not isinstance(state, str) or state not in {"pending", "partial", "applied", "removed"}:
            raise ProfileConflict("profile manifest state is invalid")
        owned = manifest.get("owned")
        if (
            not isinstance(owned, list)
            or any(not isinstance(item, str) for item in owned)
            or len(set(owned)) != len(owned)
        ):
            raise ProfileConflict("profile manifest ownership set is invalid")
        keys = {resource.key for resource in resources}
        if not set(owned).issubset(keys):
            raise ProfileConflict("profile manifest ownership set is invalid")
        pending = manifest.get("pending")
        if pending is not None and (not isinstance(pending, str) or pending not in keys):
            raise ProfileConflict("profile manifest pending resource is invalid")
        completed = manifest.get("completed", [])
        removed = manifest.get("removed", [])
        if (
            not isinstance(completed, list)
            or any(not isinstance(item, str) for item in completed)
            or len(set(completed)) != len(completed)
            or not set(completed).issubset(keys)
        ):
            raise ProfileConflict("profile manifest completed set is invalid")
        if set(completed) != set(owned):
            raise ProfileConflict("profile manifest progress does not match ownership")
        if (
            not isinstance(removed, list)
            or any(not isinstance(item, str) for item in removed)
            or len(set(removed)) != len(removed)
            or not set(removed).issubset(keys)
        ):
            raise ProfileConflict("profile manifest removed set is invalid")

    @staticmethod
    def _ownership_conflicts(
        resources: Sequence[_Resource],
        manifest: Mapping[str, Any],
        present: Mapping[str, dict[str, Any] | None],
    ) -> list[dict[str, str]]:
        """Return present names that are not safely owned by this manifest."""

        owned = set(manifest.get("owned", []))
        pending = manifest.get("pending")
        conflicts: list[dict[str, str]] = []
        for resource in resources:
            if present.get(resource.key) is None:
                continue
            if resource.key not in owned or resource.key == pending:
                conflicts.append({"table": resource.table, "name": resource.name})
        return conflicts

    def _write_manifest(self, manifest: Mapping[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=".labco-company-profile.",
            suffix=".tmp",
            dir=self.state_dir,
        )
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                # Windows has no fchmod.  The state directory and atomic
                # replace still provide the private-file boundary there.
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._manifest_path)
            try:
                directory_fd = os.open(self.state_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _snapshot(
        self,
        resources: Sequence[_Resource],
    ) -> tuple[dict[str, dict[str, Any] | None], dict[str, dict[str, str]]]:
        present: dict[str, dict[str, Any] | None] = {}
        failures: dict[str, dict[str, str]] = {}
        for resource in resources:
            try:
                value = self.client.get(resource.table, resource.name)
                present[resource.key] = value
            except Exception as exc:
                failures[resource.key] = _safe_error("get", resource, exc)
                present[resource.key] = None
        return present, failures

    @staticmethod
    def _counts(
        resources: Sequence[_Resource],
        present: Mapping[str, dict[str, Any] | None],
    ) -> dict[str, int]:
        counts = _zero_counts()
        for resource in resources:
            if present.get(resource.key) is not None:
                counts[resource.kind] += 1
        return counts

    def _result(
        self,
        state: str,
        resources: Sequence[_Resource],
        present: Mapping[str, dict[str, Any] | None],
        *,
        error: Mapping[str, str] | None = None,
        conflicts: Sequence[Mapping[str, str]] = (),
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "state": state,
            "counts": self._counts(resources, present),
        }
        if error:
            result["error"] = dict(error)
        if conflicts:
            result["conflicts"] = [dict(item) for item in conflicts]
        return result

    def status(self) -> dict[str, Any]:
        resources = self._resources()
        with self._lock():
            try:
                manifest = self._load_manifest()
                present, failures = self._snapshot(resources)
            except ProfileConflict as exc:
                present, failures = self._snapshot(resources)
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={"code": "manifest_conflict", "message": f"{exc}."},
                )
            if failures:
                return self._result(
                    "partial",
                    resources,
                    present,
                    error=next(iter(failures.values())),
                )
            if manifest is None:
                collisions = [
                    {"table": resource.table, "name": resource.name}
                    for resource in resources
                    if present.get(resource.key) is not None
                ]
                if collisions:
                    return self._result("conflict", resources, present, conflicts=collisions)
                return self._result("available", resources, present)
            try:
                self._validate_manifest(manifest, resources)
            except ProfileConflict as exc:
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={"code": "manifest_conflict", "message": f"{exc}."},
                )
            if manifest.get("state") == "removed":
                collisions = self._collision_preflight(resources, present)
                if collisions:
                    return self._result("conflict", resources, present, conflicts=collisions)
            ownership_conflicts = self._ownership_conflicts(resources, manifest, present)
            if ownership_conflicts:
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={
                        "code": "ownership_conflict",
                        "message": "a LABCO name is present without confirmed profile ownership",
                    },
                    conflicts=ownership_conflicts,
                )
            if manifest.get("pending") is not None:
                return self._result(
                    "partial",
                    resources,
                    present,
                    error={
                        "code": "pending_create",
                        "message": "a profile create operation is pending retry",
                    },
                )
            state = str(manifest.get("state"))
            total = len(resources)
            present_count = sum(value is not None for value in present.values())
            if state == "removed" and present_count == 0:
                return self._result("available", resources, present)
            if state == "applied" and present_count == total:
                return self._result("applied", resources, present)
            return self._result("partial", resources, present)

    def _collision_preflight(
        self,
        resources: Sequence[_Resource],
        present: Mapping[str, dict[str, Any] | None],
    ) -> list[dict[str, str]]:
        return [
            {"table": resource.table, "name": resource.name}
            for resource in resources
            if present.get(resource.key) is not None
        ]

    def apply(self) -> dict[str, Any]:
        resources = self._resources()
        with self._lock():
            try:
                manifest = self._load_manifest()
                present, failures = self._snapshot(resources)
            except ProfileConflict as exc:
                present, failures = self._snapshot(resources)
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={"code": "manifest_conflict", "message": f"{exc}."},
                )
            if failures:
                return self._result("partial", resources, present, error=next(iter(failures.values())))
            if manifest is None:
                collisions = self._collision_preflight(resources, present)
                if collisions:
                    return self._result("conflict", resources, present, conflicts=collisions)
                manifest = self._new_manifest(resources)
                self._write_manifest(manifest)
            else:
                try:
                    self._validate_manifest(manifest, resources)
                except ProfileConflict as exc:
                    return self._result(
                        "conflict",
                        resources,
                        present,
                        error={"code": "manifest_conflict", "message": f"{exc}."},
                    )
                # A removed manifest no longer grants ownership of names that
                # have reappeared.  Re-run the complete collision preflight
                # before starting a new deployment.
                if manifest.get("state") == "removed":
                    collisions = self._collision_preflight(resources, present)
                    if collisions:
                        return self._result("conflict", resources, present, conflicts=collisions)
                    manifest["owned"] = []
                    manifest["completed"] = []
                    manifest["removed"] = []
                else:
                    ownership_conflicts = self._ownership_conflicts(resources, manifest, present)
                    if ownership_conflicts:
                        return self._result(
                            "conflict",
                            resources,
                            present,
                            error={
                                "code": "ownership_conflict",
                                "message": "a LABCO name is present without confirmed profile ownership",
                            },
                            conflicts=ownership_conflicts,
                        )
                    # A pending call with no visible object is safe to retry;
                    # a visible pending object was rejected above as unknown.
                    manifest["pending"] = None
            owned = set(manifest.get("owned", []))
            manifest["state"] = "pending"
            manifest.pop("error", None)
            manifest["pending"] = None
            manifest["owned"] = sorted(owned)
            manifest["completed"] = sorted(owned)
            self._write_manifest(manifest)
            for resource in resources:
                try:
                    current = self.client.get(resource.table, resource.name)
                except Exception as exc:
                    manifest["state"] = "partial"
                    manifest["error"] = _safe_error("apply", resource, exc)
                    manifest["updated_at"] = time.time()
                    self._write_manifest(manifest)
                    current_present, _ = self._snapshot(resources)
                    return self._result(
                        "partial",
                        resources,
                        current_present,
                        error=manifest["error"],
                    )
                if current is not None:
                    if resource.key not in owned:
                        # A name appeared between the preflight and the
                        # operation.  Never adopt it.
                        return self._result(
                            "conflict",
                            resources,
                            present,
                            error={
                                "code": "ownership_conflict",
                                "message": "a LABCO name appeared without confirmed profile ownership",
                            },
                            conflicts=[{"table": resource.table, "name": resource.name}],
                        )
                    continue
                if resource.key in owned:
                    # The profile owns this key and can safely repair a
                    # manually deleted object.
                    pass
                else:
                    # Persist the uncertain operation before invoking the
                    # native adapter.  If the adapter raises after creating
                    # remotely, the next run will see pending + present and
                    # stop with a conflict rather than deleting/adopting it.
                    manifest["pending"] = resource.key
                    manifest["updated_at"] = time.time()
                    self._write_manifest(manifest)
                    try:
                        self.client.create(resource.table, copy.deepcopy(resource.payload))
                    except Exception as exc:
                        manifest["state"] = "partial"
                        manifest["error"] = _safe_error("apply", resource, exc)
                        manifest["updated_at"] = time.time()
                        self._write_manifest(manifest)
                        current_present, _ = self._snapshot(resources)
                        if current_present.get(resource.key) is not None:
                            return self._result(
                                "conflict",
                                resources,
                                current_present,
                                error={
                                    "code": "uncertain_create",
                                    "message": "native create outcome is uncertain; manual review is required",
                                },
                                conflicts=[{"table": resource.table, "name": resource.name}],
                            )
                        return self._result(
                            "partial",
                            resources,
                            current_present,
                            error=manifest["error"],
                        )
                    owned.add(resource.key)
                    manifest["pending"] = None
                manifest["owned"] = sorted(owned)
                manifest["completed"] = sorted(owned)
                manifest["updated_at"] = time.time()
                self._write_manifest(manifest)
            manifest["state"] = "applied"
            manifest["owned"] = sorted(owned)
            manifest["completed"] = sorted(owned)
            manifest["pending"] = None
            manifest["removed"] = []
            manifest.pop("error", None)
            manifest["updated_at"] = time.time()
            self._write_manifest(manifest)
            final_present, failures = self._snapshot(resources)
            if failures:
                manifest["state"] = "partial"
                manifest["error"] = next(iter(failures.values()))
                manifest["updated_at"] = time.time()
                self._write_manifest(manifest)
                return self._result(
                    "partial",
                    resources,
                    final_present,
                    error=next(iter(failures.values())),
                )
            return self._result("applied", resources, final_present)

    def remove(self) -> dict[str, Any]:
        resources = self._resources()
        with self._lock():
            try:
                manifest = self._load_manifest()
            except ProfileConflict as exc:
                present, _ = self._snapshot(resources)
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={"code": "manifest_conflict", "message": f"{exc}."},
                )
            if manifest is None:
                present, failures = self._snapshot(resources)
                if failures:
                    return self._result("partial", resources, present, error=next(iter(failures.values())))
                collisions = self._collision_preflight(resources, present)
                if collisions:
                    return self._result("conflict", resources, present, conflicts=collisions)
                return self._result("available", resources, present)
            try:
                self._validate_manifest(manifest, resources)
            except ProfileConflict as exc:
                present, _ = self._snapshot(resources)
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={"code": "manifest_conflict", "message": f"{exc}."},
                )
            present, failures = self._snapshot(resources)
            if failures:
                return self._result("partial", resources, present, error=next(iter(failures.values())))
            if manifest.get("state") == "removed":
                collisions = self._collision_preflight(resources, present)
                if collisions:
                    return self._result("conflict", resources, present, conflicts=collisions)
            ownership_conflicts = self._ownership_conflicts(resources, manifest, present)
            if ownership_conflicts:
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={
                        "code": "ownership_conflict",
                        "message": "a LABCO name is present without confirmed profile ownership",
                    },
                    conflicts=ownership_conflicts,
                )
            # A pending create was never confirmed as owned.  Even when its
            # name is currently absent, remove cannot safely claim it.
            if manifest.get("pending") is not None:
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={
                        "code": "pending_create",
                        "message": "a profile create outcome is unresolved; manual review is required",
                    },
                )
            manifest["state"] = "partial"
            manifest.pop("error", None)
            self._write_manifest(manifest)
            owned = set(manifest.get("owned", []))
            removed = set(manifest.get("removed", []))
            for resource in reversed(resources):
                if resource.key not in owned:
                    continue
                try:
                    current = self.client.get(resource.table, resource.name)
                    if current is not None:
                        self.client.delete(resource.table, resource.name)
                    removed.add(resource.key)
                    manifest["removed"] = sorted(removed)
                    manifest["updated_at"] = time.time()
                    self._write_manifest(manifest)
                except Exception as exc:
                    manifest["state"] = "partial"
                    manifest["error"] = _safe_error("remove", resource, exc)
                    manifest["removed"] = sorted(removed)
                    manifest["updated_at"] = time.time()
                    self._write_manifest(manifest)
                    present, _ = self._snapshot(resources)
                    return self._result(
                        "partial",
                        resources,
                        present,
                        error=manifest["error"],
                    )
            manifest["state"] = "removed"
            manifest["pending"] = None
            manifest["updated_at"] = time.time()
            manifest.pop("error", None)
            self._write_manifest(manifest)
            present, failures = self._snapshot(resources)
            if failures:
                return self._result(
                    "partial",
                    resources,
                    present,
                    error=next(iter(failures.values())),
                )
            ownership_conflicts = self._ownership_conflicts(resources, manifest, present)
            if ownership_conflicts:
                return self._result(
                    "conflict",
                    resources,
                    present,
                    error={
                        "code": "ownership_conflict",
                        "message": "a LABCO name appeared without confirmed profile ownership",
                    },
                    conflicts=ownership_conflicts,
                )
            if any(value is not None for value in present.values()):
                return self._result(
                    "partial",
                    resources,
                    present,
                    error={
                        "code": "remove_incomplete",
                        "message": "some owned objects remain after remove",
                    },
                )
            return self._result("available", resources, present)


__all__ = ["CompanyProfile", "NativeClient"]
