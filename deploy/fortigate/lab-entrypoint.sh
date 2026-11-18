#!/bin/sh
set -eu

cd /state
if [ -e fortios.qcow2 ] && [ ! -L fortios.qcow2 ]; then
  echo "refusing to replace an existing non-symlink fortios.qcow2" >&2
  exit 1
fi
if [ ! -e fortios.qcow2 ]; then
  ln -s /fortios.qcow2 fortios.qcow2
fi
test -s /run/secrets/admin_password

# Existing overlay/state files are intentionally left in place. The adapter
# resumes the appliance from the mounted state after the first boot.
exec uv run /launcher.py --hostname "${LAB_HOSTNAME:-fortigate-lab}" --username admin --connection-mode tc
