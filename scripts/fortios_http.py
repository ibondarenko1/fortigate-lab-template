"""Read-only HTTP helpers for the training appliance."""

import gzip
from http.cookiejar import CookieJar
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, build_opener


class SameOriginRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            raise ValueError("The appliance redirected outside its configured origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_lab_bridge(port):
    if not 1 <= port <= 65535:
        raise ValueError("Invalid loopback bridge port")
    origin = f"http://127.0.0.1:{port}"
    browser = build_opener(ProxyHandler({}), SameOriginRedirects(), HTTPCookieProcessor(CookieJar()))
    with browser.open(origin + "/_lab/open", timeout=10):
        pass
    return origin, browser


def read_body(response, limit=1024 * 1024):
    if response.headers.get("Content-Encoding", "").lower() == "gzip":
        with gzip.GzipFile(fileobj=response) as decoded:
            body = decoded.read(limit + 1)
    else:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("The appliance response exceeded the size limit")
    return body
