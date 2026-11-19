#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: bash training/start-company.sh DEPLOY_DIR RADIUS_DMZ_IP TRUSTED_GUI_CERT_PEM" >&2
    exit 2
fi
training_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy="$(cd "$1" && pwd)"
export RADIUS_IP="$2"
export NATIVE_CERT_FILE
NATIVE_CERT_FILE="$(realpath "$3")"
cd "$deploy"
test -s .env && test -s "$NATIVE_CERT_FILE"
set -a
. ./.env
set +a
vm="$(docker compose --env-file .env -f compose.yaml ps -q fortigate)"
test -n "$vm"
export NATIVE_HOSTNAME="${LAB_HOSTNAME:?}"
export NATIVE_IP="${LAB_MGMT_GUEST_IP:?}"
export RADIUS_CLIENT_IP="${LAB_DMZ_GUEST_IP:?}"
export NATIVE_PASSWORD_FILE="$deploy/secrets/admin-password"
export COMPANY_SECRET_DIR="$deploy/secrets/company"
test -s "$NATIVE_PASSWORD_FILE"
project="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$vm")"
export PRACTICE_MGMT_NETWORK="${project}_management"
export PRACTICE_DMZ_NETWORK="${project}_dmz"
export NATIVE_GUI_URL="${NATIVE_GUI_URL:-https://127.0.0.1:${LAB_GUI_PORT:-18843}/}"
python3 - "$vm" <<'PY'
import ipaddress, json, os, secrets, subprocess, sys
from pathlib import Path
vm = json.loads(subprocess.check_output(["docker", "inspect", sys.argv[1]]))[0]
assert vm["Config"]["Hostname"] == os.environ["NATIVE_HOSTNAME"], "Unexpected appliance hostname"
networks = vm["NetworkSettings"]["Networks"]
assert networks[os.environ["PRACTICE_MGMT_NETWORK"]]["IPAddress"] == os.environ["NATIVE_IP"]
dmz = json.loads(subprocess.check_output(["docker", "network", "inspect", os.environ["PRACTICE_DMZ_NETWORK"]]))[0]
assert dmz["Internal"] and dmz["Id"] == networks[dmz["Name"]]["NetworkID"]
ip = ipaddress.IPv4Address(os.environ["RADIUS_IP"])
source = ipaddress.IPv4Address(os.environ["RADIUS_CLIENT_IP"])
subnet = ipaddress.IPv4Network(dmz["IPAM"]["Config"][0]["Subnet"])
assert ip in subnet and source in subnet and ip not in {source, subnet.network_address, subnet.broadcast_address}
os.umask(0o077)
root = Path(os.environ["COMPANY_SECRET_DIR"])
root.mkdir(mode=0o700, exist_ok=True)
for name in ("radius_shared", "radius_password"):
    try:
        with (root / name).open("x") as f:
            f.write(secrets.token_hex(24) + "\n")
    except FileExistsError:
        pass
PY
cd "$training_dir"
docker compose -p "${WORKSHEET_PROJECT:-fortigate-worksheet}" -f compose.yaml -f company.compose.yaml up -d --build --wait
