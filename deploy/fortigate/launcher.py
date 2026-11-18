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
from common.launch import FeatureFileWatcher, FortiOS_vm, main


ORIGINAL_INIT = FortiOS_vm.__init__
ORIGINAL_WORK = FortiOS_vm.work
PROVISIONED = Path("/state/.lab-provisioned")


def read_admin_password() -> str:
    value = Path("/run/secrets/admin_password").read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("admin password secret is empty")
    return value


def lab_init(self, *args, **kwargs):
    secret = read_admin_password()
    positional = list(args)
    if "password" in kwargs and kwargs["password"] is None:
        kwargs["password"] = secret
    elif len(positional) >= 3 and positional[2] is None:
        positional[2] = secret
    elif len(positional) < 3 and kwargs.get("password") is None:
        kwargs["password"] = secret
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
    # Use the same local password for the mandatory first-login change and
    # subsequent logins. On a pristine disk the driver still handles FortiOS's
    # blank-password first login. If bootstrap is interrupted before the
    # configuration is ready, the next attempt can use the saved password.
    self._bootstrap_password = secret
    self.credentials.password = secret
    self.driver._bootstrap_password = secret
    if PROVISIONED.is_file() and Path("fortios-overlay.qcow2").is_file():
        if self.commander.busy or self.commander._active_feature is not None:
            raise RuntimeError("Cannot discard an active provisioning queue")
        self._features = []
        self._file_watcher = FeatureFileWatcher([], self.logger)
        self.commander._features.clear()
        self.driver._blank_fallback_available = False
        self.driver.set_prompt_patterns(self.hostname)


def lab_work(self):
    ORIGINAL_WORK(self)
    if self.running and self.driver.ready and not self.commander.feature_errors and not PROVISIONED.exists():
        temporary = PROVISIONED.with_suffix(".tmp")
        temporary.write_text("1\n", encoding="utf-8")
        temporary.replace(PROVISIONED)


FortiOS_vm.__init__ = lab_init
FortiOS_vm.work = lab_work


if __name__ == "__main__":
    main("FortiGate")
