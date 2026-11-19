#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
SECRET_FILE="$DEPLOY_DIR/secrets/admin-password"

command -v docker >/dev/null || { printf 'docker is required.\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'python3 is required to create the instance UUID.\n' >&2; exit 1; }

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$DEPLOY_DIR/.env.example" "$ENV_FILE"
  printf 'Created %s from .env.example.\n' "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1091
. "$ENV_FILE"
set +a
: "${FORTIGATE_IMAGE:=local/fortigate-lab:7.6.8}"

if [[ -z "${FORTIGATE_UUID:-}" ]]; then
  FORTIGATE_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  printf '\nFORTIGATE_UUID=%s\n' "$FORTIGATE_UUID" >> "$ENV_FILE"
  export FORTIGATE_UUID
  printf 'Generated a unique appliance UUID in %s.\n' "$ENV_FILE"
fi

if [[ ! -s "$SECRET_FILE" ]]; then
  printf 'Create a non-empty local admin password at %s before starting.\n' "$SECRET_FILE" >&2
  exit 1
fi

if ! docker image inspect "$FORTIGATE_IMAGE" >/dev/null 2>&1; then
  printf 'Local image %s is not present. Run scripts/build-fortigate.sh with the official qcow2 first.\n' "$FORTIGATE_IMAGE" >&2
  exit 1
fi

"$SCRIPT_DIR/render-startup-config.sh"
cd "$DEPLOY_DIR"
docker compose --env-file "$ENV_FILE" -f compose.yaml config --quiet
docker compose --env-file "$ENV_FILE" -f compose.yaml up -d --wait --wait-timeout 300
if [[ ${LAB_FIXTURE_BRIDGE:-0} == 1 ]]; then
  python3 "$SCRIPT_DIR/fixture-bridge.py" apply
fi

gui_port="${LAB_GUI_PORT:-18843}"
printf 'Waiting for the FortiOS login page on port %s.\n' "$gui_port"
python3 - "$gui_port" <<'PY'
import http.client
import ssl
import sys
import time

port = int(sys.argv[1])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# This readiness probe only contacts the local lab and sends no credentials.
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
deadline = time.monotonic() + 60

while time.monotonic() < deadline:
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=context)
    try:
        connection.request("GET", "/login")
        if 200 <= connection.getresponse().status < 400:
            break
    except (OSError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    time.sleep(2)
else:
    raise SystemExit(f"FortiOS login page did not respond at https://127.0.0.1:{port}/login.")
PY

printf 'FortiOS is ready at https://127.0.0.1:%s/\n' "$gui_port"
