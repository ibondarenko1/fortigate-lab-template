"""Offline tests for the bounded native LABCO profile reconciler.

The fake client deliberately behaves like the three-operation native adapter
without opening a socket.  These tests exercise ownership, retry and
dependency ordering rather than a vendor API or a live FortiGate.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from training.company_profile import CompanyProfile


COUNTS = {
    "users": 12,
    "groups": 6,
    "radius": 1,
    "addresses": 6,
    "address_groups": 3,
}


class FakeClient:
    """Small in-memory native CMDB double with one-shot failure injection."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict] = {}
        self.created: list[tuple[str, str, dict]] = []
        self.deleted: list[tuple[str, str]] = []
        self.fail_get: set[tuple[str, str]] = set()
        self.fail_create: set[tuple[str, str]] = set()
        self.fail_create_after_store: set[tuple[str, str]] = set()
        self.fail_delete: set[tuple[str, str]] = set()

    def get(self, table: str, name: str):
        key = (table, name)
        if key in self.fail_get:
            self.fail_get.remove(key)
            raise RuntimeError("synthetic get failure")
        value = self.objects.get(key)
        return None if value is None else json.loads(json.dumps(value))

    def create(self, table: str, data: dict):
        name = data["name"]
        key = (table, name)
        if key in self.fail_create:
            self.fail_create.remove(key)
            raise RuntimeError("synthetic create failure")
        if key in self.objects:
            raise RuntimeError("native duplicate")
        stored = json.loads(json.dumps(data))
        self.objects[key] = stored
        self.created.append((table, name, stored))
        if key in self.fail_create_after_store:
            self.fail_create_after_store.remove(key)
            raise RuntimeError("synthetic post-create failure")

    def delete(self, table: str, name: str):
        key = (table, name)
        if key in self.fail_delete:
            self.fail_delete.remove(key)
            raise RuntimeError("synthetic delete failure")
        if key not in self.objects:
            raise RuntimeError("native missing object")
        self.deleted.append(key)
        del self.objects[key]


def make_profile(
    client: FakeClient,
    state_dir: Path,
    *,
    source_ip: str | None = "10.231.31.2",
    **kwargs,
):
    return CompanyProfile(
        client,
        state_dir,
        radius_ip="10.231.32.53",
        radius_source_ip=source_ip,
        radius_secret="offline-radius-shared-secret",
        test_password="offline-radius-test-password",
        **kwargs,
    )


def test_fresh_apply_creates_fixed_profile_and_keeps_secrets_private():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)

        assert profile.status() == {"state": "available", "counts": {key: 0 for key in COUNTS}}
        result = profile.apply()

        assert result["state"] == "applied"
        assert result["counts"] == COUNTS
        assert len(client.created) == sum(COUNTS.values())

        local_users = [
            payload
            for table, _, payload in client.created
            if table == "user/local"
        ]
        assert len(local_users) == 12
        passwords = {payload["passwd"] for payload in local_users}
        assert len(passwords) == 12
        assert "offline-radius-test-password" not in passwords
        assert all(payload["type"] == "password" for payload in local_users)

        radius = client.objects[("user/radius", "LABCO-RADIUS")]
        assert radius["server"] == "10.231.32.53"
        assert radius["source-ip"] == "10.231.31.2"
        assert radius["auth-type"] == "pap"
        assert radius["radius-port"] == 1812
        assert radius["secret"] == "offline-radius-shared-secret"

        for table, name, payload in client.created:
            assert name.startswith("LABCO-")
            assert len(name) <= 31
            assert "comment" not in payload

        manifest_text = (state_dir / ".labco-company-profile.json").read_text()
        assert "offline-radius-shared-secret" not in manifest_text
        assert "offline-radius-test-password" not in manifest_text
        assert all(password not in manifest_text for password in passwords)
        json.dumps(result)


def test_radius_source_ip_is_optional_and_gui_edits_are_preserved():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(client, Path(temporary), source_ip=None)
        assert profile.apply()["state"] == "applied"
        client.objects[("user/radius", "LABCO-RADIUS")].pop("source-ip", None)
        client.objects[("user/local", "LABCO-HR-ALICE")]["email-to"] = "edited@example.invalid"
        created_before = len(client.created)

        repeated = profile.apply()

        assert repeated["state"] == "applied"
        assert repeated["counts"] == COUNTS
        assert len(client.created) == created_before
        assert "source-ip" not in client.objects[("user/radius", "LABCO-RADIUS")]
        assert client.objects[("user/local", "LABCO-HR-ALICE")]["email-to"] == "edited@example.invalid"


def test_remove_is_reverse_dependency_order_and_preserves_unrelated_objects():
    client = FakeClient()
    unrelated = ("user/local", "OTHER-USER")
    client.objects[unrelated] = {"name": unrelated[1], "type": "password"}
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(client, Path(temporary))
        assert profile.apply()["state"] == "applied"
        assert profile.remove() == {"state": "available", "counts": {key: 0 for key in COUNTS}}

        assert unrelated in client.objects
        assert client.deleted[:3] == [
            ("firewall/addrgrp", "LABCO-AG-CORP"),
            ("firewall/addrgrp", "LABCO-AG-DMZ"),
            ("firewall/addrgrp", "LABCO-AG-LAN"),
        ]
        address_group_end = 3
        address_start = address_group_end
        assert all(table == "firewall/address" for table, _ in client.deleted[address_start:address_start + 6])
        assert all(table == "user/group" for table, _ in client.deleted[address_start + 6 + 0:address_start + 6 + 6])
        assert client.deleted[-1] == ("user/local", "LABCO-HR-ALICE")
        delete_count = len(client.deleted)
        assert profile.remove()["state"] == "available"
        assert len(client.deleted) == delete_count


def test_collision_is_rejected_before_manifest_or_mutation():
    client = FakeClient()
    client.objects[("user/local", "LABCO-HR-ALICE")] = {"name": "LABCO-HR-ALICE"}
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(client, Path(temporary))
        result = profile.apply()

        assert result["state"] == "conflict"
        assert result["conflicts"] == [{"table": "user/local", "name": "LABCO-HR-ALICE"}]
        assert client.created == []
        assert not (Path(temporary) / ".labco-company-profile.json").exists()


def test_partial_apply_recovers_without_duplicates():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)
        client.fail_create.add(("user/group", "LABCO-GRP-HR"))

        first = profile.apply()

        assert first["state"] == "partial"
        assert first["counts"]["users"] == 12
        assert first["counts"]["radius"] == 1
        created_before_retry = len(client.created)
        second = profile.apply()

        assert second["state"] == "applied"
        assert second["counts"] == COUNTS
        assert len(client.created) - created_before_retry == 15
        assert len(client.objects) == sum(COUNTS.values())
        manifest = json.loads((state_dir / ".labco-company-profile.json").read_text())
        assert manifest["state"] == "applied"
        assert "passwd" not in json.dumps(manifest)


def test_partial_remove_recovers_and_does_not_delete_unrelated_object():
    client = FakeClient()
    unrelated = ("firewall/address", "OTHER-ADDR")
    client.objects[unrelated] = {"name": unrelated[1]}
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(client, Path(temporary))
        assert profile.apply()["state"] == "applied"
        client.fail_delete.add(("firewall/addrgrp", "LABCO-AG-CORP"))

        first = profile.remove()

        assert first["state"] == "partial"
        assert unrelated in client.objects
        second = profile.remove()

        assert second["state"] == "available"
        assert unrelated in client.objects
        assert not any(name == "OTHER-ADDR" for _, name in client.deleted)


def test_native_payload_shape_is_bounded_to_supported_tables():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(client, Path(temporary))
        assert profile.apply()["state"] == "applied"

    tables = {table for table, _, _ in client.created}
    assert tables == {
        "user/local",
        "user/group",
        "user/radius",
        "firewall/address",
        "firewall/addrgrp",
    }
    assert all("comment" not in payload for _, _, payload in client.created)


def test_pending_foreign_name_is_never_adopted_or_deleted():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)
        client.fail_create.add(("user/group", "LABCO-GRP-HR"))
        assert profile.apply()["state"] == "partial"

        # A name appears while the manifest still records an unconfirmed
        # create.  It must not be adopted on apply or deleted on remove.
        client.objects[("user/group", "LABCO-GRP-HR")] = {
            "name": "LABCO-GRP-HR",
            "member": [{"name": "EXTERNAL-USER"}],
        }
        created_before = len(client.created)
        applied = profile.apply()
        removed = profile.remove()

        assert applied["state"] == "conflict"
        assert removed["state"] == "conflict"
        assert len(client.created) == created_before
        assert ("user/group", "LABCO-GRP-HR") in client.objects
        assert ("user/group", "LABCO-GRP-HR") not in client.deleted


def test_uncertain_create_that_left_a_remote_object_fails_closed():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)
        key = ("user/group", "LABCO-GRP-HR")
        client.fail_create_after_store.add(key)

        result = profile.apply()

        assert result["state"] == "conflict"
        assert result["error"]["code"] == "uncertain_create"
        assert key in client.objects
        manifest = json.loads((state_dir / ".labco-company-profile.json").read_text())
        assert manifest["pending"] == "user/group:LABCO-GRP-HR"
        assert manifest["pending"] not in manifest["owned"]


def test_reapply_after_removed_profile_rejects_new_collision():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)
        assert profile.apply()["state"] == "applied"
        assert profile.remove()["state"] == "available"
        collision = ("firewall/address", "LABCO-ADDR-LAN")
        client.objects[collision] = {"name": collision[1], "subnet": "198.51.100.0 255.255.255.0"}
        created_before = len(client.created)

        result = profile.apply()
        remove_result = profile.remove()

        assert result["state"] == "conflict"
        assert result["conflicts"] == [{"table": collision[0], "name": collision[1]}]
        assert remove_result["state"] == "conflict"
        assert len(client.created) == created_before
        assert client.objects[collision]["subnet"] == "198.51.100.0 255.255.255.0"


def test_address_objects_follow_supplied_fixture_topology():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        profile = make_profile(
            client,
            Path(temporary),
            lan_cidr="10.77.10.0/24",
            dmz_cidr="10.77.20.0/24",
            lan_node="10.77.10.47",
            dmz_node="10.77.20.48",
        )
        assert profile.apply()["state"] == "applied"

    assert client.objects[("firewall/address", "LABCO-ADDR-LAN")]["subnet"] == "10.77.10.0 255.255.255.0"
    assert client.objects[("firewall/address", "LABCO-ADDR-DMZ")]["subnet"] == "10.77.20.0 255.255.255.0"
    assert client.objects[("firewall/address", "LABCO-ADDR-WEB")]["subnet"] == "10.77.20.48 255.255.255.255"
    assert client.objects[("firewall/address", "LABCO-ADDR-ADMIN")]["subnet"] == "10.77.10.47 255.255.255.255"


def test_malformed_manifest_fails_closed_without_native_mutation():
    client = FakeClient()
    with tempfile.TemporaryDirectory() as temporary:
        state_dir = Path(temporary)
        profile = make_profile(client, state_dir)
        assert profile.apply()["state"] == "applied"
        manifest_path = state_dir / ".labco-company-profile.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["owned"] = [{}]
        manifest_path.write_text(json.dumps(manifest))
        deleted_before = list(client.deleted)

        status = profile.status()
        removed = profile.remove()

        assert status["state"] == "conflict"
        assert removed["state"] == "conflict"
        assert client.deleted == deleted_before
