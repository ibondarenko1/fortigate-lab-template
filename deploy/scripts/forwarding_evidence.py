#!/usr/bin/env python3
"""Capture a TCP probe or build a redacted FortiOS forwarding report.

The report intentionally accepts exported FortiOS traffic records instead of
logging in to an appliance.  A report is evidence only when a probe and a
matching forward log agree on the same five-tuple and a nearby timestamp.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import sys
import time
from typing import Any, Iterable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCHEMA_VERSION = 1
DEFAULT_SKEW_SECONDS = 10.0
_LOG_FIELDS = (
    "eventtime",
    "itime",
    "date",
    "time",
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "proto",
    "type",
    "subtype",
    "action",
    "policyid",
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _iso_epoch(value: str) -> float:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).timestamp()


def _event_epoch(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            try:
                return _iso_epoch(text)
            except ValueError:
                return None
    if not math.isfinite(number):
        return None
    # FortiOS eventtime is normally epoch nanoseconds.  Keep this heuristic
    # broad enough for itime seconds and millisecond or microsecond exports.
    magnitude = abs(number)
    if magnitude >= 1e18:
        return number / 1e9
    if magnitude >= 1e15:
        return number / 1e6
    if magnitude >= 1e12:
        return number / 1e3
    return number


def _int(value: Any) -> int | None:
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(str(value).strip(), 10)
    except (TypeError, ValueError):
        return None


def _address(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
        return str(parsed) if isinstance(parsed, ipaddress.IPv4Address) else None
    except ValueError:
        return None


def _strip_terminal_newline(value: bytes) -> bytes:
    """Remove one agreed HTTP line ending, never arbitrary trailing bytes."""
    if value.endswith(b"\r\n"):
        return value[:-2]
    if value.endswith(b"\n") or value.endswith(b"\r"):
        return value[:-1]
    return value


def _is_unicast_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_reserved or address.is_link_local)


def _proto(value: Any) -> str | None:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"6", "tcp"}:
        return "tcp"
    if text in {"17", "udp"}:
        return "udp"
    return text or None


def _timestamp_from_log(record: Mapping[str, Any], fortios_timezone: str | None) -> tuple[float | None, str | None, str | None]:
    for key in ("eventtime", "itime", "timestamp", "event_time"):
        parsed = _event_epoch(record.get(key))
        if parsed is not None:
            return parsed, key, None
    date = record.get("date")
    clock = record.get("time")
    if date and clock:
        if not fortios_timezone:
            return None, None, "log_time_zone"
        try:
            timezone = ZoneInfo(fortios_timezone)
        except ZoneInfoNotFoundError:
            return None, None, "log_time_zone"
        for value in (f"{date}T{clock}Z", f"{date} {clock}"):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "")).replace(tzinfo=timezone)
                return parsed.astimezone(UTC).timestamp(), "date_time", None
            except ValueError:
                continue
    return None, None, "log_time"


def _read_json_records(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [{"code": "read_error", "message": f"Could not read {path.name}: {exc.strerror or 'I/O error'}"}], metadata
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    def collect_metadata(container: Mapping[str, Any], side: str) -> None:
        def put(key: str, value: Any) -> None:
            if key in metadata and metadata[key] != value:
                errors.append({"code": "metadata_conflict", "message": f"FortiOS response contains conflicting {key} metadata."})
            else:
                metadata[key] = value

        for key in ("status", "version", "build"):
            if key not in container:
                continue
            value = container[key]
            if key == "build":
                build = _int(value)
                if build is None or build < 0:
                    errors.append({"code": "metadata_build", "message": f"{side} build must be a non-negative integer."})
                else:
                    put(key, build)
            elif isinstance(value, bool) or not isinstance(value, (str, int)):
                errors.append({"code": f"metadata_{key}", "message": f"{side} {key} must be a string or integer."})
            else:
                put(key, value)

    if parsed is not None:
        if isinstance(parsed, list):
            candidates: Iterable[Any] = parsed
        elif isinstance(parsed, dict):
            collect_metadata(parsed, "FortiOS response")
            nested = parsed.get("results")
            if isinstance(nested, list):
                candidates = nested
            elif isinstance(parsed.get("data"), dict) and isinstance(parsed["data"].get("results"), list):
                candidates = parsed["data"]["results"]
                collect_metadata(parsed["data"], "FortiOS response data")
            else:
                candidates = [parsed]
        else:
            candidates = []
        for line_number, item in enumerate(candidates, start=1):
            if isinstance(item, dict):
                records.append(item)
            else:
                errors.append({"code": "record_type", "line": line_number, "message": "Record must be a JSON object."})
        return records, errors, metadata
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            errors.append({"code": "invalid_json", "line": line_number, "message": "Line is not valid JSON."})
            continue
        if isinstance(item, dict):
            records.append(item)
        else:
            errors.append({"code": "record_type", "line": line_number, "message": "Record must be a JSON object."})
    return records, errors, metadata


def _probe_record(item: Mapping[str, Any], line_number: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if item.get("schema_version") != SCHEMA_VERSION:
        return None, {"code": "probe_schema", "line": line_number, "message": "Probe schema_version must be 1."}
    required = ("probe_id", "started_at", "finished_at", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "result", "local_service")
    missing = [key for key in required if key not in item]
    if missing:
        return None, {"code": "probe_fields", "line": line_number, "message": "Probe is missing required fields: " + ", ".join(missing) + "."}
    probe_id = str(item["probe_id"])
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", probe_id):
        return None, {"code": "probe_id", "line": line_number, "message": "probe_id must contain only letters, numbers, dot, underscore, or hyphen."}
    try:
        started = _iso_epoch(str(item["started_at"]))
        finished = _iso_epoch(str(item["finished_at"]))
    except ValueError:
        return None, {"code": "probe_time", "line": line_number, "message": "Probe timestamps must be ISO-8601 values."}
    source = _address(item["source_ip"])
    destination = _address(item["destination_ip"])
    source_port = _int(item["source_port"])
    destination_port = _int(item["destination_port"])
    protocol = _proto(item["protocol"])
    if source is None or destination is None or source_port is None or destination_port is None or protocol != "tcp":
        return None, {"code": "probe_value", "line": line_number, "message": "Probe addresses, ports, and protocol must be valid."}
    if not _is_unicast_ipv4(source) or not _is_unicast_ipv4(destination):
        return None, {"code": "probe_scope", "line": line_number, "message": "Probe addresses must be unicast IPv4 endpoints."}
    if not 0 <= source_port <= 65535 or not 1 <= destination_port <= 65535 or finished < started:
        return None, {"code": "probe_range", "line": line_number, "message": "Probe ports or timestamp range is invalid."}
    local_service = str(item["local_service"]).strip().lower()
    if local_service not in {"ready", "stopped", "unavailable", "unknown"}:
        return None, {"code": "probe_service", "line": line_number, "message": "local_service must be ready, stopped, unavailable, or unknown."}
    result = str(item["result"]).strip().lower()
    if result not in {"connected", "failed", "error"}:
        return None, {"code": "probe_result", "line": line_number, "message": "result must be connected, failed, or error."}
    if source_port == 0 and result != "error":
        return None, {"code": "probe_port", "line": line_number, "message": "A successful probe must record its assigned source port."}
    http_status = _int(item.get("http_status")) if item.get("http_status") is not None else None
    if http_status is not None and not 100 <= http_status <= 599:
        return None, {"code": "probe_http", "line": line_number, "message": "http_status must be an HTTP status code."}
    body_match = item.get("body_match")
    if body_match is not None and not isinstance(body_match, bool):
        return None, {"code": "probe_http", "line": line_number, "message": "body_match must be a boolean."}
    expected = item.get("expected")
    if expected is not None and str(expected).strip().lower() not in {"allow", "deny", "unknown"}:
        return None, {"code": "probe_expected", "line": line_number, "message": "expected must be allow, deny, or unknown."}
    expected_policy_id = item.get("expected_policy_id")
    if expected_policy_id is not None:
        expected_policy_id = _int(expected_policy_id)
        if expected_policy_id is None or expected_policy_id < 0:
            return None, {"code": "probe_policy", "line": line_number, "message": "expected_policy_id must be a non-negative integer."}
    return {
        "probe_id": probe_id,
        "started_at": str(item["started_at"]),
        "finished_at": str(item["finished_at"]),
        "started_epoch": started,
        "finished_epoch": finished,
        "source_ip": source,
        "source_port": source_port,
        "destination_ip": destination,
        "destination_port": destination_port,
        "protocol": protocol,
        "result": result,
        "local_service": local_service,
        "error": str(item.get("error", ""))[:120] if item.get("error") else None,
        "expected": str(expected).strip().lower() if expected is not None else None,
        "expected_policy_id": expected_policy_id,
        "http_status": http_status,
        "body_match": body_match,
    }, None


def _forward_log(item: Mapping[str, Any], line_number: int, fortios_timezone: str | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    log_type = str(item.get("type", "")).strip().lower()
    subtype = str(item.get("subtype", "")).strip().lower()
    if log_type != "traffic" or subtype != "forward":
        return None, None
    timestamp, timestamp_source, timestamp_error = _timestamp_from_log(item, fortios_timezone)
    if timestamp_error:
        return None, {"code": timestamp_error, "line": line_number, "message": "FortiOS date/time logs require --fortios-timezone. Prefer eventtime when exporting memory logs."}
    source = _address(item.get("srcip"))
    destination = _address(item.get("dstip"))
    source_port = _int(item.get("srcport"))
    destination_port = _int(item.get("dstport"))
    protocol = _proto(item.get("proto"))
    policy_id = _int(item.get("policyid"))
    if timestamp is None or source is None or destination is None or source_port is None or destination_port is None or protocol is None or policy_id is None:
        return None, {"code": "log_fields", "line": line_number, "message": "Forward log needs event time, addresses, ports, protocol, and policyid."}
    if protocol != "tcp":
        return None, None
    if not _is_unicast_ipv4(source) or not _is_unicast_ipv4(destination):
        return None, {"code": "log_scope", "line": line_number, "message": "Forward log addresses must be unicast IPv4 endpoints."}
    if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535 or policy_id < 0:
        return None, {"code": "log_range", "line": line_number, "message": "Forward log ports and policyid must be non-negative in-range values."}
    action = str(item.get("action", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9-]{1,32}", action):
        return None, {"code": "log_action", "line": line_number, "message": "Forward log action is missing or too long."}
    return {
        "timestamp_epoch": timestamp,
        "timestamp_source": timestamp_source,
        "source_ip": source,
        "source_port": source_port,
        "destination_ip": destination,
        "destination_port": destination_port,
        "protocol": protocol,
        "type": "traffic",
        "subtype": "forward",
        "action": action,
        "policy_id": policy_id,
    }, None


def _verification(probe: Mapping[str, Any], log: Mapping[str, Any] | None, ambiguous: bool) -> str:
    if probe["result"] == "error":
        return "probe_error"
    if probe["result"] == "connected" and (probe.get("http_status") != 200 or probe.get("body_match") is not True):
        return "probe_http_mismatch"
    if probe["local_service"] in {"stopped", "unavailable"}:
        return "service_check_mismatch" if probe["result"] == "connected" else "local_service_unavailable"
    expected = probe.get("expected")
    if expected == "allow" and probe["result"] != "connected":
        return "probe_failed"
    if expected == "deny" and probe["result"] == "connected":
        return "unexpected_allow"
    if ambiguous:
        return "ambiguous_forward_log"
    if log is None:
        return "missing_forward_log"
    expected_policy_id = probe.get("expected_policy_id")
    if expected_policy_id is not None and log["policy_id"] != expected_policy_id:
        return "unexpected_policy"
    action = str(log["action"])
    if expected == "allow" and action in {"deny", "blocked"}:
        return "log_outcome_mismatch"
    if expected == "deny" and action in {"accept", "close", "client-rst", "server-rst"}:
        return "log_outcome_mismatch"
    allow_action = action in {"accept", "close", "client-rst", "server-rst"}
    deny_action = action in {"deny", "blocked"}
    if probe["result"] == "connected" and allow_action:
        return "allow_with_evidence"
    if probe["result"] == "connected" and deny_action:
        return "log_outcome_mismatch"
    if probe["result"] != "connected" and allow_action:
        return "log_outcome_mismatch"
    if deny_action:
        if probe["local_service"] != "ready":
            return "service_readiness_unknown"
        return "explicit_deny" if log["policy_id"] > 0 else "implicit_deny"
    return "matched_other_action"


def build_report(probes_path: Path, logs_path: Path | None, skew_seconds: float = DEFAULT_SKEW_SECONDS, fortios_timezone: str | None = None) -> dict[str, Any]:
    if not math.isfinite(skew_seconds) or skew_seconds < 0:
        raise ValueError("skew_seconds must be a finite non-negative number")
    probes_raw, probe_errors, _ = _read_json_records(probes_path)
    probes: list[dict[str, Any]] = []
    probe_ids: set[str] = set()
    errors = [{"side": "probe", **error} for error in probe_errors]
    for line_number, item in enumerate(probes_raw, start=1):
        probe, error = _probe_record(item, line_number)
        if error:
            errors.append({"side": "probe", **error})
        elif probe:
            if probe["probe_id"] in probe_ids:
                errors.append({"side": "probe", "code": "probe_duplicate", "line": line_number, "message": "probe_id must be unique."})
            else:
                probe_ids.add(probe["probe_id"])
                probes.append(probe)
    logs: list[dict[str, Any]] = []
    logs_metadata: dict[str, Any] = {}
    if logs_path is not None:
        logs_raw, log_errors, logs_metadata = _read_json_records(logs_path)
        errors.extend({"side": "log", **error} for error in log_errors)
        status = logs_metadata.get("status")
        if status is not None and str(status).strip().lower() not in {"success", "ok"}:
            errors.append({"side": "log", "code": "fortios_status", "message": "FortiOS log response status is not successful."})
        for line_number, item in enumerate(logs_raw, start=1):
            log, error = _forward_log(item, line_number, fortios_timezone)
            if error:
                errors.append({"side": "log", **error})
            elif log:
                logs.append(log)
    flows: list[dict[str, Any]] = []
    for probe in probes:
        candidates = [
            log for log in logs
            if log["source_ip"] == probe["source_ip"]
            and log["source_port"] == probe["source_port"]
            and log["destination_ip"] == probe["destination_ip"]
            and log["destination_port"] == probe["destination_port"]
            and log["protocol"] == probe["protocol"]
            and probe["started_epoch"] - skew_seconds <= log["timestamp_epoch"] <= probe["finished_epoch"] + skew_seconds
        ]
        candidates.sort(key=lambda log: abs(log["timestamp_epoch"] - probe["started_epoch"]))
        distinct = {(log["action"], log["policy_id"]) for log in candidates}
        ambiguous = len(distinct) > 1 and len(candidates) > 1
        selected = None if ambiguous else (candidates[0] if candidates else None)
        before = {
            "probe_id": probe["probe_id"],
            "started_at": probe["started_at"],
            "finished_at": probe["finished_at"],
            "source_ip": probe["source_ip"],
            "source_port": probe["source_port"],
            "destination_ip": probe["destination_ip"],
            "destination_port": probe["destination_port"],
            "protocol": probe["protocol"],
            "result": probe["result"],
            "local_service": probe["local_service"],
            "expected": probe["expected"],
            "expected_policy_id": probe["expected_policy_id"],
            "http_status": probe["http_status"],
            "body_match": probe["body_match"],
        }
        flow = {**before, "verification": _verification(probe, selected, ambiguous), "log": None}
        if selected is not None:
            flow["log"] = {
                "timestamp": datetime.fromtimestamp(selected["timestamp_epoch"], UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "timestamp_source": selected["timestamp_source"],
                "source_ip": selected["source_ip"],
                "source_port": selected["source_port"],
                "destination_ip": selected["destination_ip"],
                "destination_port": selected["destination_port"],
                "protocol": selected["protocol"],
                "type": selected["type"],
                "subtype": selected["subtype"],
                "action": selected["action"],
                "policy_id": selected["policy_id"],
            }
        flows.append(flow)
    counts: dict[str, int] = {}
    for flow in flows:
        status = str(flow["verification"])
        counts[status] = counts.get(status, 0) + 1
    fortios_metadata = None
    if logs_path is not None:
        version = logs_metadata.get("version")
        build = _int(logs_metadata.get("build"))
        status = logs_metadata.get("status")
        if version is not None or build is not None or status is not None:
            fortios_metadata = {
                "status": str(status) if status is not None else None,
                "version": str(version) if version is not None else None,
                "build": build,
            }
    return {
        "report_schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "probe_source": probes_path.name,
        "log_source": logs_path.name if logs_path is not None else None,
        "match_window_seconds": skew_seconds,
        "fortios_timezone": fortios_timezone,
        "fortios": fortios_metadata,
        "flows": flows,
        "errors": errors,
        "summary": {"probes": len(probes), "forward_logs": len(logs), "flows": len(flows), "statuses": counts},
    }


def _probe(args: argparse.Namespace) -> int:
    started = time.time()
    source_ip = str(args.source_ip)
    source_port = args.source_port
    result = "failed"
    error = None
    response_bytes = 0
    actual_source_ip = source_ip
    actual_source_port = source_port
    http_status = None
    body_match = False
    for attempt in range(10):
        candidate = 0 if source_port == 0 else source_port + attempt
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client.bind((source_ip, candidate))
                actual_source_ip, actual_source_port = client.getsockname()
                client.settimeout(args.timeout)
                client.connect((args.destination, args.port))
                request = f"GET / HTTP/1.0\r\nHost: {args.destination}\r\nConnection: close\r\n\r\n".encode()
                client.sendall(request)
                response = http.client.HTTPResponse(client)
                response.begin()
                body = response.read(65537)
                response_bytes = len(body)
                http_status = response.status
                expected_body = args.expected_body.encode()
                body_match = len(body) <= 65536 and _strip_terminal_newline(body) == _strip_terminal_newline(expected_body)
                if http_status == 200 and body_match:
                    result = "connected"
                else:
                    result = "error"
                    error = "unexpected_http_response"
                break
        except http.client.HTTPException:
            error = "invalid_http_response"
            break
        except socket.timeout:
            error = "timeout"
            break
        except ConnectionRefusedError:
            error = "connection_refused"
            break
        except OSError as exc:
            if exc.errno in {98, 99, 10048} and attempt < 9:
                continue
            error = f"socket_error_{exc.errno or 'unknown'}"
            break
    finished = time.time()
    item = {
        "schema_version": SCHEMA_VERSION,
        "probe_id": args.probe_id,
        "started_at": datetime.fromtimestamp(started, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "finished_at": datetime.fromtimestamp(finished, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source_ip": actual_source_ip,
        "source_port": actual_source_port,
        "destination_ip": _address(args.destination),
        "destination_port": args.port,
        "protocol": "tcp",
        "result": result,
        "local_service": args.local_service,
        "expected": args.expected,
        "expected_policy_id": args.expected_policy_id,
        "response_bytes": response_bytes,
        "http_status": http_status,
        "body_match": body_match,
    }
    if error:
        item["error"] = error
    print(json.dumps(item, separators=(",", ":")))
    return 0


def _report(args: argparse.Namespace) -> int:
    report = build_report(Path(args.probes), Path(args.logs) if args.logs else None, args.skew, args.fortios_timezone)
    encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    if report["errors"]:
        return 1
    if args.require_verified:
        accepted = {"allow_with_evidence", "explicit_deny", "implicit_deny"}
        policy_flows = [flow for flow in report["flows"] if flow.get("expected") in {"allow", "deny"}]
        control_flows = [flow for flow in report["flows"] if flow.get("expected") not in {"allow", "deny"}]
        if (
            not report["flows"]
            or not policy_flows
            or any(flow["verification"] not in accepted for flow in policy_flows)
            or any(flow.get("expected_policy_id") is None for flow in policy_flows)
            or any(flow["verification"] != "local_service_unavailable" for flow in control_flows)
        ):
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    probe = commands.add_parser("probe", help="run one exact-source-port TCP probe")
    probe.add_argument("--probe-id", required=True)
    probe.add_argument("--source-ip", required=True)
    probe.add_argument("--source-port", required=True, type=int)
    probe.add_argument("--destination", required=True)
    probe.add_argument("--port", required=True, type=int)
    probe.add_argument("--timeout", type=float, default=5.0)
    probe.add_argument("--local-service", choices=("ready", "stopped", "unavailable", "unknown"), default="unknown")
    probe.add_argument("--expected", choices=("allow", "deny", "unknown"), default=None)
    probe.add_argument("--expected-policy-id", type=int, default=None)
    probe.add_argument("--expected-body", default="fortigate-lab dmz service")
    probe.set_defaults(handler=_probe)
    report = commands.add_parser("report", help="match probe JSONL to exported FortiOS forward logs")
    report.add_argument("--probes", required=True)
    report.add_argument("--logs")
    report.add_argument("--output")
    report.add_argument("--skew", type=float, default=DEFAULT_SKEW_SECONDS)
    report.add_argument("--fortios-timezone", default=None, help="IANA timezone required when logs contain date/time instead of eventtime")
    report.add_argument("--require-verified", action="store_true", help="fail unless every flow has a matching policy-evidence status")
    report.set_defaults(handler=_report)
    args = parser.parse_args()
    if args.command == "probe" and not (0 <= args.source_port <= 65535 and 1 <= args.port <= 65535):
        parser.error("source port must be 0 or between 1 and 65535, destination port must be between 1 and 65535")
    if args.command == "report" and (not math.isfinite(args.skew) or args.skew < 0):
        parser.error("--skew must be a finite non-negative number")
    if args.command == "probe" and args.expected_policy_id is not None and args.expected_policy_id < 0:
        parser.error("--expected-policy-id must be non-negative")
    if args.command == "probe" and (not math.isfinite(args.timeout) or args.timeout <= 0):
        parser.error("--timeout must be a finite positive number")
    if args.command == "probe" and (not _is_unicast_ipv4(args.source_ip) or not _is_unicast_ipv4(args.destination)):
        parser.error("source and destination must be unicast IPv4 addresses")
    if args.command == "probe" and not args.expected_body:
        parser.error("--expected-body must not be empty")
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
