"""Serve the local training worksheet. The default entry opens native FortiOS."""

import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from policy_lab import catalog, grade


STATIC = Path(__file__).resolve().parent / "static"
ASSETS = {
    "/training/": ("index.html", "text/html; charset=utf-8"),
    "/training/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/training/style.css": ("style.css", "text/css; charset=utf-8"),
}
MAX_BODY = 256 * 1024
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "practice.localhost"}


def native_url(raw):
    parsed = urlsplit(raw)
    if (parsed.scheme not in {"https", "http"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path not in {"", "/", "/_lab/open"}
            or any(ord(c) < 33 for c in raw)):
        raise ValueError("Set the native URL to your local FortiOS HTTPS tunnel or lab bridge.")
    if not parsed.port:
        raise ValueError("Specify the local port forwarded to the native VM.")
    return raw


class Worksheet(BaseHTTPRequestHandler):
    def log_request(self, code="-", size="-"):
        # Worksheet drafts, browser paths, headers and query strings stay out of logs.
        pass

    def send_bytes(self, code, content=b"", kind="text/plain; charset=utf-8", location=None):
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(content)

    def json(self, code, payload):
        self.send_bytes(code, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def allowed_host(self):
        host = self.headers.get("Host", "")
        try:
            parsed = urlsplit("http://" + host)
            if parsed.hostname in LOCAL_HOSTS and parsed.netloc == host and parsed.username is None:
                return True
        except ValueError:
            pass
        self.json(403, {"error": "Откройте локальный адрес тренажёра."})
        return False

    def do_GET(self):
        if not self.allowed_host():
            return
        path = urlsplit(self.path).path
        if path in {"/", "/_lab/open"}:
            self.send_bytes(303, location=self.server.native)
        elif path == "/training":
            self.send_bytes(303, location="/training/")
        elif path == "/training/api/catalog":
            self.json(200, {"exercises": catalog()})
        elif path in ASSETS:
            name, kind = ASSETS[path]
            self.send_bytes(200, (STATIC / name).read_bytes(), kind)
        else:
            self.send_bytes(404)

    def do_POST(self):
        if not self.allowed_host():
            return
        if self.path != "/training/api/grade":
            return self.send_bytes(404)
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.headers["Host"]:
            return self.json(403, {"error": "Откройте локальный адрес тренажёра."})
        if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
            return self.json(415, {"error": "Требуется JSON."})
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            return self.json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Проверьте размер конфигурации."})
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or not all(isinstance(payload.get(key), str) for key in ("exercise_id", "config")):
                raise ValueError("Ожидаются exercise_id и config.")
            if payload["exercise_id"] not in {exercise["id"] for exercise in catalog()}:
                return self.json(404, {"error": "Такого упражнения нет."})
            result = grade(payload["exercise_id"], payload["config"])
        except (ValueError, UnicodeError, RecursionError) as exc:
            return self.json(422, {"error": str(exc)})
        self.json(200, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18846)
    parser.add_argument("--native-url", default=os.getenv("NATIVE_GUI_URL", "https://127.0.0.1:18843/"))
    args = parser.parse_args()
    with ThreadingHTTPServer((args.bind, args.port), Worksheet) as server:
        server.native = native_url(args.native_url)
        server.serve_forever()
