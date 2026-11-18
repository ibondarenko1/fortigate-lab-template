#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$DEPLOY_DIR"

COMPOSE_ARGS=(-f compose.yaml)
if [[ -f .env ]]; then
  COMPOSE_ARGS=(--env-file .env "${COMPOSE_ARGS[@]}")
fi
docker compose "${COMPOSE_ARGS[@]}" ps
