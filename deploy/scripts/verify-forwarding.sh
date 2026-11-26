#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$DEPLOY_DIR"

COMPOSE_ARGS=(-f compose.yaml)
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a
  . ./.env
  set +a
  COMPOSE_ARGS=(--env-file .env "${COMPOSE_ARGS[@]}")
fi

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-forwarding.sh [--output PATH]
       bash scripts/verify-forwarding.sh --probes PATH --logs PATH [--output PATH]

With no --probes, the script checks the fixture locally, sends two LAN probes
with exact source ports, and writes a redacted report. Use the saved probes
with --logs after exporting FortiOS records; this prevents matching a log to
newly-created source ports. --logs accepts either a FortiOS memory-log JSON
response with a results array or JSONL exported rows.
EOF
}

logs_path="${FORWARDING_LOGS:-}"
probes_path="${FORWARDING_PROBES:-}"
output_path="${FORWARDING_OUTPUT:-}"
while (($#)); do
  case "$1" in
    --probes)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      probes_path="$2"
      shift 2
      ;;
    --logs)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      logs_path="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      output_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v python3 >/dev/null || { printf 'python3 is required for the evidence report.\n' >&2; exit 1; }
if [[ -n "$logs_path" && -z "$probes_path" ]]; then
  printf '%s\n' '--logs must be paired with --probes from the same capture; it cannot be attached to newly-created probes.' >&2
  exit 2
fi

artifact_dir="${FORWARDING_ARTIFACT_DIR:-$DEPLOY_DIR/state/forwarding}"
umask 077
mkdir -p "$artifact_dir"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$output_path" ]]; then
  output_path="$artifact_dir/report-$run_stamp-$$.json"
fi

run_report() {
  local probe_path="$1"
  local legacy_status="$2"
  local report_args=(report --probes "$probe_path" --output "$output_path")
  if [[ -n "$logs_path" ]]; then
    report_args+=(--logs "$logs_path")
    report_args+=(--require-verified)
  fi
  if [[ -n "${FORWARDING_FORTIOS_TIMEZONE:-}" ]]; then
    report_args+=(--fortios-timezone "$FORWARDING_FORTIOS_TIMEZONE")
  fi
  set +e
  python3 "$SCRIPT_DIR/forwarding_evidence.py" "${report_args[@]}"
  local report_status=$?
  set -e
  printf 'Forwarding evidence report: %s\n' "$output_path"
  if [[ -z "$logs_path" ]]; then
    printf 'No FortiOS log export was supplied. Re-run with --probes %s --logs PATH to attach policy evidence.\n' "$probe_path"
  fi

  local evidence_status=0
  if [[ -n "$logs_path" ]]; then
    if ! python3 - "$output_path" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
accepted = {"allow_with_evidence", "explicit_deny", "implicit_deny"}
flows = report.get("flows", [])
policy_flows = [flow for flow in flows if flow.get("expected") in {"allow", "deny"}]
control_flows = [flow for flow in flows if flow.get("expected") not in {"allow", "deny"}]
if (
    not flows
    or not policy_flows
    or any(flow.get("verification") not in accepted for flow in policy_flows)
    or any(flow.get("expected_policy_id") is None for flow in policy_flows)
    or any(flow.get("verification") != "local_service_unavailable" for flow in control_flows)
):
    raise SystemExit(1)
PY
    then
      printf 'The exported logs did not prove every probe. Review the redacted report.\n' >&2
      evidence_status=1
    fi
  fi

  if (( legacy_status != 0 || report_status != 0 || evidence_status != 0 )); then
    printf 'The LAN forwarding control failed. Review the report before changing a policy.\n' >&2
    return 1
  fi
  return 0
}

if [[ -n "$probes_path" ]]; then
  [[ -f "$probes_path" ]] || { printf 'Probe capture does not exist: %s\n' "$probes_path" >&2; exit 2; }
  run_report "$probes_path" 0
  exit $?
fi

command -v docker >/dev/null || { printf 'docker is required to capture probes.\n' >&2; exit 1; }

dmz_host="${LAB_DMZ_NODE:-10.231.32.10}"
lan_host="${LAB_LAN_NODE:-10.231.31.10}"
body='fortigate-lab dmz service'
probe_image="${FORWARD_PROBE_IMAGE:-python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e}"
expected_body="${FORWARD_PROBE_EXPECTED_BODY:-$body}"
source_port="${FORWARD_PROBE_SOURCE_PORT:-0}"
expected_allow_policy="${FORTIOS_EXPECTED_ALLOW_POLICY_ID:-1}"
expected_deny_policy="${FORTIOS_EXPECTED_DENY_POLICY_ID:-2}"
probe_file="$(mktemp "$artifact_dir/probes-$run_stamp-XXXXXX.jsonl")"
for expected_policy in "$expected_allow_policy" "$expected_deny_policy"; do
  if [[ -n "$expected_policy" && ! "$expected_policy" =~ ^[0-9]+$ ]]; then
    printf 'Expected policy IDs must be non-negative integers.\n' >&2
    exit 2
  fi
done
if [[ ! "$source_port" =~ ^[0-9]+$ ]]; then
  printf 'FORWARD_PROBE_SOURCE_PORT must be 0 or an integer between 1 and 65535.\n' >&2
  exit 2
fi
source_port=$((10#$source_port))
if (( source_port < 0 || source_port > 65535 )); then
  printf 'FORWARD_PROBE_SOURCE_PORT must be 0 or an integer between 1 and 65535.\n' >&2
  exit 2
fi
if (( source_port == 65535 )); then
  printf 'FORWARD_PROBE_SOURCE_PORT=65535 leaves no valid distinct port for the second probe.\n' >&2
  exit 2
fi

server_override="${FORWARD_SERVER_CONTAINER:-}"
client_override="${FORWARD_CLIENT_CONTAINER:-}"
if [[ -n "$server_override" ]]; then
  server_container="$server_override"
else
  server_container="$(docker compose "${COMPOSE_ARGS[@]}" ps -q server | tr -d '\r\n')"
fi
if [[ -n "$client_override" ]]; then
  client_container="$client_override"
else
  client_container="$(docker compose "${COMPOSE_ARGS[@]}" ps -q client | tr -d '\r\n')"
fi
if [[ -z "$server_container" || -z "$client_container" ]]; then
  printf 'The LAN client and DMZ server containers must be running.\n' >&2
  exit 1
fi
if [[ -n "$server_override" || -n "$client_override" ]]; then
  for container in "$server_container" "$client_container"; do
    [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" == true ]] || {
      printf 'Override container %s is not running.\n' "$container" >&2
      exit 1
    }
  done
fi

local_ok=0
local_state_80=ready
local_state_8080=ready
for port in 80 8080; do
  if [[ -n "$server_override" ]]; then
    service_probe=(docker exec "$server_container" wget -T 5 -qO- "http://$dmz_host:$port/")
  else
    service_probe=(docker compose "${COMPOSE_ARGS[@]}" exec -T server wget -T 5 -qO- "http://$dmz_host:$port/")
  fi
  if ! response=$("${service_probe[@]}") ||
     [[ "$response" != "$expected_body" ]]; then
    printf 'The DMZ fixture is unavailable or returned an unexpected body on TCP %s.\n' "$port" >&2
    local_ok=1
    if [[ "$port" == 80 ]]; then
      local_state_80=unavailable
    else
      local_state_8080=unavailable
    fi
  else
    printf 'The DMZ fixture is ready on TCP %s.\n' "$port"
  fi
done

capture_probe() {
  local probe_id="$1"
  local port="$2"
  local service_state="$3"
  local expected="$4"
  local requested_source_port="$5"
  local expected_policy_id="${6:-}"
  local captured
  local command=(docker run --rm --pull=missing --network "container:$client_container" \
      --read-only --cap-drop ALL --security-opt no-new-privileges:true \
      --pids-limit 32 --memory 64m --tmpfs /tmp:mode=1777,size=4m \
      -v "$SCRIPT_DIR/forwarding_evidence.py:/tmp/forwarding_evidence.py:ro" \
      "$probe_image" python /tmp/forwarding_evidence.py probe \
      --probe-id "$probe_id" --source-ip "$lan_host" --source-port "$requested_source_port" \
      --destination "$dmz_host" --port "$port" --local-service "$service_state" \
      --expected "$expected" --expected-body "$expected_body" --timeout 5)
  if [[ -n "$expected_policy_id" ]]; then
    command+=(--expected-policy-id "$expected_policy_id")
  fi
  if captured=$("${command[@]}"); then
    printf '%s\n' "$captured" >> "$probe_file"
    return 0
  fi
  # A helper failure is never presented as a policy decision.
  python3 - "$probe_file" "$probe_id" "$port" "$service_state" "$expected" "$requested_source_port" "$lan_host" "$dmz_host" "$expected_policy_id" <<'PY'
import json
from datetime import UTC, datetime
from pathlib import Path
import sys

output, probe_id, port, service, expected, source_port, source_ip, destination, expected_policy_id = sys.argv[1:]
now = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
record = {
    "schema_version": 1,
    "probe_id": probe_id,
    "started_at": now,
    "finished_at": now,
    "source_ip": source_ip,
    "source_port": int(source_port),
    "destination_ip": destination,
    "destination_port": int(port),
    "protocol": "tcp",
    "result": "error",
    "local_service": service,
    "expected": expected,
    "error": "probe_helper_unavailable",
}
if expected_policy_id:
    record["expected_policy_id"] = int(expected_policy_id)
with Path(output).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, separators=(",", ":")) + "\n")
PY
  return 0
}

: > "$probe_file"
capture_probe "lan-http-allow" 80 "$local_state_80" allow "$source_port" "$expected_allow_policy"
second_source_port="$source_port"
if [[ "$source_port" != 0 ]]; then
  second_source_port="$((source_port + 1))"
fi
capture_probe "lan-http-deny-8080" 8080 "$local_state_8080" deny "$second_source_port" "$expected_deny_policy"
printf 'Probe capture: %s\n' "$probe_file"

if ! python3 - "$probe_file" "$local_ok" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
legacy_failure = int(sys.argv[2])
records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
by_port = {int(record["destination_port"]): record for record in records}
if by_port.get(80, {}).get("result") != "connected":
    legacy_failure = 1
if by_port.get(8080, {}).get("result") == "connected":
    legacy_failure = 1
if any(record.get("result") == "error" for record in records):
    legacy_failure = 1
assigned_ports = [int(record.get("source_port", 0)) for record in records if record.get("result") != "error"]
if len(assigned_ports) != len(set(assigned_ports)) or any(port <= 0 or port > 65535 for port in assigned_ports):
    legacy_failure = 1
if legacy_failure:
    raise SystemExit(1)
PY
then
  legacy_status=1
else
  legacy_status=0
fi

run_report "$probe_file" "$legacy_status"
exit $?
