#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
COMPOSE_ARGS=(-f compose.yaml)
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  . ./.env
  COMPOSE_ARGS=(--env-file .env "${COMPOSE_ARGS[@]}")
fi

dmz_host="${LAB_DMZ_NODE:-10.231.32.10}"
body='fortigate-lab dmz service'
for port in 80 8080; do
  if ! response=$(docker compose "${COMPOSE_ARGS[@]}" exec -T server wget -T 5 -qO- "http://$dmz_host:$port/") ||
     [[ "$response" != "$body" ]]; then
    printf 'The DMZ fixture did not return the expected response on port %s.\n' "$port" >&2
    exit 1
  fi
done

if ! response=$(docker compose "${COMPOSE_ARGS[@]}" exec -T client wget -T 5 -qO- "http://$dmz_host:80/") ||
   [[ "$response" != "$body" ]]; then
  printf 'The LAN client did not receive the expected response from DMZ port 80.\n' >&2
  exit 1
fi
printf 'LAN reached the DMZ HTTP fixture on port 80.\n'

result=$(docker compose "${COMPOSE_ARGS[@]}" exec -T client sh -c '
  if wget -T 5 -qO /dev/null "$1"; then
    printf "reachable\n"
  else
    printf "unreachable\n"
  fi
' sh "http://$dmz_host:8080/")
if [[ "$result" != 'unreachable' ]]; then
  printf 'The LAN client could reach DMZ port 8080. Check the FortiOS policy.\n' >&2
  exit 1
fi
printf 'The DMZ fixture answered locally on port 8080 and was unreachable from LAN.\n'
