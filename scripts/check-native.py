#!/usr/bin/env python3
"""Check the native dashboard and firmware through the existing local lab tunnel."""

import argparse
import json
import re
from urllib.error import URLError
from urllib.parse import urlsplit

from fortios_http import open_lab_bridge, read_body


def check(port: int) -> dict:
    origin, browser = open_lab_bridge(port)
    with browser.open(origin + "/system/dashboard/1", timeout=10) as response:
        content = read_body(response)
        title = re.search(rb"<title>\s*FortiGate[^<]*</title>", content, re.I)
        if not title or urlsplit(response.geturl()).path != "/system/dashboard/1":
            raise ValueError("The native dashboard did not load")
    with browser.open(origin + "/api/v2/monitor/system/status", timeout=10) as response:
        status = json.loads(read_body(response))
    version = status.get("version", "")
    if status.get("status") != "success" or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("The dashboard did not report a valid FortiOS version")
    return {"dashboard": origin + "/system/dashboard/1", "version": version, "build": status.get("build")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default=18787, type=int, metavar="PORT")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        print(json.dumps(check(args.port)))
    except (OSError, URLError, ValueError) as exc:
        parser.exit(1, f"Native FortiGate check failed: {exc}\n")


if __name__ == "__main__":
    main()
