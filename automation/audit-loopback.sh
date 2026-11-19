#!/usr/bin/env bash
set -euo pipefail

port=${1:?Usage: audit-loopback.sh PORT FILE_WITH_EXISTING_LAB_PASSWORD}
password_file=${2:?Usage: audit-loopback.sh PORT FILE_WITH_EXISTING_LAB_PASSWORD}
if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
    echo "Use a valid loopback port." >&2
    exit 2
fi
test -f "$password_file" && test -r "$password_file"
bridge_host=${3:-127.0.0.1}
case "$bridge_host" in 127.0.0.1|localhost) ;; *) echo "Use a loopback bridge name." >&2; exit 2 ;; esac

export FORTIOS_LOCAL_PASSWORD_FILE
FORTIOS_LOCAL_PASSWORD_FILE=$(realpath -- "$password_file")
unset FORTIOS_ACCESS_TOKEN
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
exec ansible-playbook -i inventory.example.yml audit.yml \
    -e "ansible_host=$bridge_host" -e "ansible_httpapi_port=$port" -e ansible_httpapi_use_ssl=false
