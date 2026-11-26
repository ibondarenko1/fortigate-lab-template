"""Export Forward Traffic rows for this lab's captured IPv4/TCP probes."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from fortios_http import SameOriginRedirects, open_lab_bridge, read_body


def flow_key(src, sport, dst, dport):
    if not isinstance(src, str) or not isinstance(dst, str):
        raise ValueError("Probe addresses must be IPv4 strings")
    if not all(re.fullmatch(r"[0-9]{1,5}", str(port)) and 1 <= int(port) <= 65535
               for port in (sport, dport)):
        raise ValueError("Probe ports must be between 1 and 65535")
    return str(ipaddress.IPv4Address(src)), int(sport), str(ipaddress.IPv4Address(dst)), int(dport)


def read_probe_keys(path):
    keys = set()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            probe = json.loads(line)
            if type(probe["schema_version"]) is not int or probe["schema_version"] != 1 or probe["protocol"] != "tcp":
                raise ValueError("Use the version 1 TCP probe JSONL from verify-forwarding.sh")
            keys.add(flow_key(probe["source_ip"], probe["source_port"],
                              probe["destination_ip"], probe["destination_port"]))
    if not keys:
        raise ValueError("The probe file is empty")
    return sorted(keys)


def export(keys, fetch):
    result = {"status": "success", "results": []}
    for src, sport, dst, dport in keys:
        filters = [("filter", f"{name}=={value}") for name, value in (
            ("srcip", src), ("srcport", sport), ("dstip", dst), ("dstport", dport), ("proto", 6))]
        data = fetch(filters)
        if not isinstance(data, dict):
            raise ValueError("FortiOS returned an invalid memory/traffic/forward response")
        rows = data.get("results")
        if data.get("status") != "success" or not isinstance(rows, list):
            raise ValueError("FortiOS did not return a successful memory/traffic/forward export")
        if data.get("completed") is False or int(data.get("total_lines", len(rows))) > len(rows):
            raise ValueError("The FortiOS log query is incomplete. Retry or use a fresh probe source port.")
        version, build = data.get("version"), data.get("build")
        if not re.fullmatch(r"v?\d+\.\d+\.\d+", str(version)) or not str(build).isdigit():
            raise ValueError("The log response is missing its FortiOS version or build")
        if "version" in result and (version, int(build)) != (result["version"], result["build"]):
            raise ValueError("FortiOS version or build changed during collection")
        result.update(version=version, build=int(build))
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("FortiOS returned an invalid Forward Traffic record")
            if row.get("type") != "traffic" or row.get("subtype") != "forward" or str(row.get("proto")) != "6":
                continue
            if flow_key(row["srcip"], row["srcport"], row["dstip"], row["dstport"]) != (src, sport, dst, dport):
                continue
            result["results"].append({field: row[field] for field in (
                "eventtime", "type", "subtype", "srcip", "srcport", "dstip", "dstport",
                "proto", "action", "policyid")})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    connection = parser.add_mutually_exclusive_group(required=True)
    connection.add_argument("--url", help="HTTPS origin of the FortiGate REST API")
    connection.add_argument("--bridge-port", type=int, help="port of an existing local lab sign-in bridge")
    parser.add_argument("--ca", help="CA file for the appliance HTTPS certificate")
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--probes", type=Path, required=True, help="exact-port probe JSONL")
    parser.add_argument("--output", type=Path, help="write UTF-8 JSON to this file (default: stdout)")
    args = parser.parse_args()
    try:
        if args.output and args.output.resolve() == args.probes.resolve():
            parser.error("--output must differ from the input probe file")
        keys = read_probe_keys(args.probes)
        headers = {"Accept": "application/json"}
        if args.url:
            parsed = urlsplit(args.url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
                parser.error("--url requires a plain HTTPS origin")
            token = os.environ.get("FORTIOS_ACCESS_TOKEN")
            if not token:
                parser.error("Set FORTIOS_ACCESS_TOKEN to a read-only API administrator token")
            if not token.isascii() or not token.isprintable() or any(ch.isspace() for ch in token):
                parser.error("The API token contains an invalid character")
            headers["Authorization"] = "Bearer " + token
            origin = args.url.rstrip("/")
            browser = build_opener(ProxyHandler({}), SameOriginRedirects(),
                                   HTTPSHandler(context=ssl.create_default_context(cafile=args.ca)))
        else:
            origin, browser = open_lab_bridge(args.bridge_port)

        def fetch(filters):
            query = urlencode([("vdom", args.vdom), ("rows", 250), *filters])
            req = Request(origin + "/api/v2/log/memory/traffic/forward?" + query, headers=headers)
            with browser.open(req, timeout=10) as response:
                return json.loads(read_body(response, limit=4 * 1024 * 1024))

        payload = json.dumps(export(keys, fetch), indent=2)
        if args.output:
            args.output.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
    except (OSError, URLError, ValueError, KeyError, TypeError) as exc:
        print(f"Could not export the lab traffic logs: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
