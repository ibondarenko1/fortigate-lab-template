#!/usr/bin/env python3
"""Run the pinned FortiGate adapter with the local admin secret.

The firmware and the adapter remain vendor/community components. This small
entrypoint only supplies a local secret without putting it on a process
command line, fixes the tested NIC count, and makes the VM UUID explicit.
"""

from __future__ import annotations

import os
from pathlib import Path

import common.launch as upstream_launch
from common.launch import FortiOS_vm, main


ORIGINAL_INIT = FortiOS_vm.__init__


def read_admin_password() -> str:
    value = Path("/run/secrets/admin_password").read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("admin password secret is empty")
    return value


def lab_init(self, *args, **kwargs):
    positional = list(args)
    if "password" in kwargs and kwargs["password"] is None:
        kwargs["password"] = read_admin_password()
    elif len(positional) >= 3 and positional[2] is None:
        positional[2] = read_admin_password()
    elif len(positional) < 3 and kwargs.get("password") is None:
        kwargs["password"] = read_admin_password()
    # vrnetlab creates a writable sibling named fortios-overlay.qcow2. On a
    # restart the upstream FortiOS adapter scans every *.qcow2 in cwd and can
    # accidentally select that overlay as its next base. Limit only that
    # short discovery call to the immutable image symlink; all other runtime
    # directory operations keep their upstream behavior.
    original_listdir = upstream_launch.os.listdir
    discovery_dir = os.path.abspath(os.getcwd())

    def listdir(path="."):
        entries = original_listdir(path)
        try:
            requested_dir = os.path.abspath(path)
        except (TypeError, ValueError):
            return entries
        if requested_dir == discovery_dir:
            return [
                entry for entry in entries
                if not entry.endswith(".qcow2") or entry == "fortios.qcow2"
            ]
        return entries

    upstream_launch.os.listdir = listdir
    try:
        ORIGINAL_INIT(self, *positional, **kwargs)
    finally:
        upstream_launch.os.listdir = original_listdir
    configured_uuid = os.environ.get("UUID")
    if not configured_uuid:
        raise RuntimeError("UUID must be set for a reproducible appliance identity")
    self.uuid = configured_uuid
    # The FortiGate container has management plus two data interfaces.
    self.num_nics = 2


FortiOS_vm.__init__ = lab_init


if __name__ == "__main__":
    main("FortiGate")
