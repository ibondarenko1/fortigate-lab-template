#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
TEMPLATE="$DEPLOY_DIR/config/startup.conf.template"
TARGET="$DEPLOY_DIR/state/startup.conf"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

: "${LAB_HOSTNAME:=fortigate-lab}"
: "${LAB_MGMT_CIDR:=10.231.30.0/24}"
: "${LAB_MGMT_GUEST_IP:=10.231.30.2}"
: "${LAB_MGMT_BRIDGE_GATEWAY:=10.231.30.254}"
: "${LAB_LAN_CIDR:=10.231.31.0/24}"
: "${LAB_LAN_GUEST_IP:=10.231.31.1}"
: "${LAB_DMZ_CIDR:=10.231.32.0/24}"
: "${LAB_DMZ_GUEST_IP:=10.231.32.1}"

if [[ -e "$TARGET" ]]; then
  printf 'Preserving existing native startup config: %s\n' "$TARGET"
  exit 0
fi

mkdir -p "$DEPLOY_DIR/state/vm"

python3 - "$TEMPLATE" "$TARGET" "$LAB_HOSTNAME" "$LAB_MGMT_CIDR" "$LAB_MGMT_GUEST_IP" "$LAB_MGMT_BRIDGE_GATEWAY" "$LAB_LAN_CIDR" "$LAB_LAN_GUEST_IP" "$LAB_DMZ_CIDR" "$LAB_DMZ_GUEST_IP" <<'PY'
import ipaddress
import pathlib
import re
import sys

(
    template_name,
    target_name,
    hostname,
    mgmt_cidr,
    mgmt_guest,
    mgmt_bridge,
    lan_cidr,
    lan_guest,
    dmz_cidr,
    dmz_guest,
) = sys.argv[1:]

if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,30}", hostname):
    raise SystemExit("LAB_HOSTNAME must be 1-31 ASCII letters, digits, '_' or '-'")

def network_and_host(cidr_text, host_text, label):
    network = ipaddress.ip_network(cidr_text, strict=False)
    host = ipaddress.ip_address(host_text)
    if host.version != 4 or host not in network:
        raise SystemExit(f"{label} guest address must be inside {label} CIDR")
    return network, host

mgmt, mgmt_ip = network_and_host(mgmt_cidr, mgmt_guest, "management")
lan, lan_ip = network_and_host(lan_cidr, lan_guest, "LAN")
dmz, dmz_ip = network_and_host(dmz_cidr, dmz_guest, "DMZ")
bridge_ip = ipaddress.ip_address(mgmt_bridge)
if bridge_ip not in mgmt:
    raise SystemExit("LAB_MGMT_BRIDGE_GATEWAY must be inside LAB_MGMT_CIDR")
if len({mgmt, lan, dmz}) != 3 or mgmt.overlaps(lan) or mgmt.overlaps(dmz) or lan.overlaps(dmz):
    raise SystemExit("management, LAN and DMZ CIDRs must be distinct and non-overlapping")

values = {
    "@HOSTNAME@": hostname,
    "@MGMT_GUEST_IP@": str(mgmt_ip),
    "@MGMT_MASK@": str(mgmt.netmask),
    "@LAN_GUEST_IP@": str(lan_ip),
    "@LAN_NETWORK@": str(lan.network_address),
    "@LAN_MASK@": str(lan.netmask),
    "@DMZ_GUEST_IP@": str(dmz_ip),
    "@DMZ_NETWORK@": str(dmz.network_address),
    "@DMZ_MASK@": str(dmz.netmask),
}
text = pathlib.Path(template_name).read_text(encoding="utf-8")
for marker, value in values.items():
    text = text.replace(marker, value)
if "@" in text:
    raise SystemExit("startup template still contains an unresolved marker")
pathlib.Path(target_name).write_text(text, encoding="utf-8")
PY

printf 'Rendered native startup config: %s\n' "$TARGET"
