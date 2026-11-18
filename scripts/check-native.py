#!/usr/bin/env python3
"""Check the native dashboard and firmware through the existing local lab tunnel."""

import argparse
import gzip
import json
import re
from http.cookiejar import CookieJar
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, build_opener


class SameOriginRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urlsplit(req.full_url)
        new = urlsplit(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise ValueError("The lab server redirected outside the local tunnel")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check(port: int) -> dict:
    origin = f"http://127.0.0.1:{port}"
    browser = build_opener(ProxyHandler({}), SameOriginRedirects(), HTTPCookieProcessor(CookieJar()))
    with browser.open(origin + "/_lab/open", timeout=10):
        pass
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


def read_body(response) -> bytes:
    if response.headers.get("Content-Encoding", "").lower() == "gzip":
        with gzip.GzipFile(fileobj=response) as decoded:
            return decoded.read(1024 * 1024)
    return response.read(1024 * 1024)


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
