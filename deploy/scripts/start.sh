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
docker compose --env-file "$ENV_FILE" -f compose.yaml up -d
printf 'FortiGate lab started. GUI: https://127.0.0.1:%s\n' "${LAB_GUI_PORT:-18843}"
