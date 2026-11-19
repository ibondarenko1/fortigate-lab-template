"""Restricted local broker for the native company preset. No TCP listener."""

import hashlib
import http.client
import ipaddress
import json
import os
import socketserver
import ssl
from pathlib import Path
from urllib.parse import quote

from company_profile import CompanyProfile


TABLES = {"user/local", "user/radius", "user/group", "firewall/address", "firewall/addrgrp"}
SOCKET = Path("/run/company/agent.sock")
SECRETS = Path("/run/secrets")


class Native:
    def __init__(self):
        self.ip = str(ipaddress.IPv4Address(os.environ["NATIVE_IP"]))
        self.name = os.environ["NATIVE_HOSTNAME"]
        public_cert = (SECRETS / "native_cert").read_text()
        self.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(public_cert)).digest()
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.load_verify_locations(cadata=public_cert)
        self.tls.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        self.session = None
        self.cookies = {}
        self.connection = None

    def request(self, method, path, data=None, missing_ok=False):
        if self.connection is None:
            self.connection = http.client.HTTPSConnection(self.ip, timeout=12, context=self.tls)
        if self.connection.sock is None:
            self.connection.connect()
            peer = self.connection.sock.getpeercert(binary_form=True)
            if hashlib.sha256(peer).digest() != self.pin:
                self.connection.close()
                raise ValueError("The training VM certificate has changed.")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.session:
            headers["Authorization"] = "Bearer " + self.session
        elif self.cookies:
            headers["Cookie"] = "; ".join(k + "=" + v for k, v in self.cookies.items())
            csrf = next((v for k, v in self.cookies.items() if k.startswith(("ccsrf_token", "ccsrftoken"))), None)
            if csrf:
                headers["X-CSRFTOKEN"] = csrf.strip('"')
        try:
            self.connection.request(method, path, body=json.dumps(data).encode() if data is not None else None, headers=headers)
            response = self.connection.getresponse()
            for header, value in response.getheaders():
                if header.lower() == "set-cookie":
                    key, cookie = value.split(";", 1)[0].split("=", 1)
                    self.cookies[key] = cookie
            payload = response.read(2 * 1024 * 1024)
        except (OSError, http.client.HTTPException):
            self.connection.close()
            raise
        if missing_ok and response.status == 404:
            return None
        if response.status == 401:
            self.session = None
            self.cookies.clear()
            raise PermissionError("FortiOS requires a new login.")
        result = json.loads(payload) if payload else {}
        if response.status >= 400 or result.get("status") == "error":
            code = result.get("error")
            raise ValueError(f"FortiOS rejected {method} {path.split('?')[0]} (HTTP {response.status}, code {code}).")
        return result

    def identify(self):
        if self.session or self.cookies:
            try:
                status = self.request("GET", "/api/v2/monitor/system/status")
            except (PermissionError, OSError, http.client.HTTPException):
                self.session = None
                self.cookies.clear()
        if not self.session and not self.cookies:
            password = (SECRETS / "native_password").read_text().strip()
            login = self.request("POST", "/api/v2/authentication", {"username": os.getenv("NATIVE_USER", "admin"), "password": password, "request_key": True})
            self.session = login.get("session_key")
            if login.get("status_message") != "LOGIN_SUCCESS" or not (self.session or self.cookies):
                raise PermissionError("FortiOS rejected the agent login.")
            status = self.request("GET", "/api/v2/monitor/system/status")
        if status.get("results", {}).get("hostname") != self.name:
            raise ValueError("The connected VM name does not match the training appliance.")

    def object_path(self, table, name):
        if table not in TABLES or not name.startswith("LABCO-") or "/" in name:
            raise ValueError("The object is outside the company profile scope.")
        return "/api/v2/cmdb/" + table + "/" + quote(name, safe="") + "?vdom=root"

    def get(self, table, name):
        result = self.request("GET", self.object_path(table, name), missing_ok=True)
        if result is None:
            return None
        rows = result["results"]
        if isinstance(rows, dict):
            rows = [rows]
        return next((row for row in rows if row.get("name") == name), None)

    def create(self, table, data):
        self.object_path(table, data["name"])
        return self.request("POST", "/api/v2/cmdb/" + table + "?vdom=root", data)

    def delete(self, table, name):
        self.request("DELETE", self.object_path(table, name), missing_ok=True)

    def check_radius(self, password):
        reply = self.request("POST", "/api/v2/monitor/user/radius/test-connect?vdom=root", {
            "mkey": "LABCO-RADIUS", "ordinal": "primary", "auth_type": "pap",
            "user": "labco.radius.student", "password": password,
        })
        result = reply.get("results", {})
        return isinstance(result, dict) and result.get("access_status") == "Access-Accept"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        action = self.rfile.readline(32).strip()
        client = self.server.client
        profile = self.server.profile
        try:
            if action not in {b"status", b"apply", b"remove", b"test"}:
                raise ValueError("Unknown company-profile operation.")
            client.identify()
            if action == b"test":
                radius = client.get("user/radius", "LABCO-RADIUS")
                if not radius or radius.get("server") != profile.radius_ip or profile.status()["state"] != "applied":
                    result = {"ok": False, "message": "Apply the profile with its configured training RADIUS server before testing."}
                else:
                    ok = client.check_radius(self.server.test_password)
                    result = {"ok": ok, "message": "FortiGate accepted the labco.radius.student RADIUS login." if ok else "FortiGate did not accept the RADIUS login."}
            else:
                result = getattr(profile, action.decode())()
            code = 200
        except (OSError, http.client.HTTPException, PermissionError):
            code, result = 503, {"state": "unavailable", "message": "The agent could not connect to the training VM. Check its availability and certificate."}
        except Exception as exc:
            # Even third-party error messages can include CMDB values. Never return
            # or log them. Log only the exception class and allowlisted operation.
            print("Company action failed", action[:10], type(exc).__name__, flush=True)
            code, result = 409, {"state": "partial", "message": "FortiOS did not complete the operation. Check the profile state and its object references."}
        self.wfile.write(json.dumps({"code": code, "result": result}, ensure_ascii=False).encode() + b"\n")


def main():
    os.umask(0o077)
    client = Native()
    radius_secret = (SECRETS / "radius_shared").read_text().strip()
    test_password = (SECRETS / "radius_password").read_text().strip()
    profile = CompanyProfile(
        client, Path("/state") / client.pin.hex(), os.environ["RADIUS_IP"],
        os.environ["RADIUS_CLIENT_IP"], radius_secret, test_password,
        lan_cidr=os.environ["LAB_LAN_CIDR"], dmz_cidr=os.environ["LAB_DMZ_CIDR"],
        lan_node=os.environ["LAB_LAN_NODE"], dmz_node=os.environ["LAB_DMZ_NODE"],
    )
    SOCKET.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(SOCKET), Handler) as service:
        # Both containers share this private volume; only the worksheet's group can invoke it.
        os.chmod(SOCKET, 0o660)
        service.client = client
        service.profile = profile
        service.test_password = test_password
        service.serve_forever()


if __name__ == "__main__":
    main()
