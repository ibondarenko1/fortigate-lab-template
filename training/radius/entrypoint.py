"""Generate a one-user PAP fixture in private runtime memory."""

import ipaddress
import os
from pathlib import Path
import re


RUNTIME = Path("/run/radius")


def secret(name, minimum):
    value = Path("/run/secrets", name).read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{" + str(minimum) + r",128}", value):
        raise SystemExit(f"{name} must contain a private hexadecimal lab value")
    return value


def main():
    client = ipaddress.IPv4Address(os.environ["RADIUS_CLIENT_IP"])
    if not client.is_private or client.is_loopback or client.is_unspecified or client.is_multicast:
        raise SystemExit("RADIUS_CLIENT_IP must identify the private FortiGate DMZ interface")
    shared = secret("radius_shared", 32)
    password = secret("radius_password", 16)
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    clients = f'''client fortigate_lab {{
        ipaddr = {client}
        secret = "{shared}"
        require_message_authenticator = yes
    }}
'''
    if os.environ.get("RADIUS_SELFTEST", "false") == "true":
        clients += f'''client local_selftest {{
        ipaddr = 127.0.0.1
        secret = "{shared}"
        require_message_authenticator = yes
    }}
'''
    config = '''prefix = /usr
localstatedir = /run/radius
logdir = /run/radius
run_dir = /run/radius
libdir = /usr/lib/freeradius
radacctdir = /run/radius
name = radiusd
max_request_time = 10
cleanup_delay = 2
max_requests = 64
hostname_lookups = no
log {
    destination = stdout
    colourise = no
    auth = no
    auth_badpass = no
    auth_goodpass = no
}
security {
    allow_core_dumps = no
    max_attributes = 32
    reject_delay = 0
    status_server = no
}
thread pool {
    start_servers = 2
    max_servers = 4
    min_spare_servers = 1
    max_spare_servers = 2
}
$INCLUDE clients.conf
modules {
    always reject {
        rcode = reject
    }
    files {
        filename = /run/radius/authorize
    }
    pap {
        normalise = yes
    }
}
server lab {
    listen {
        type = auth
        ipaddr = 0.0.0.0
        port = 1812
    }
    authorize {
        if (&User-Name != "labco.radius.student") {
            reject
        }
        if (!&User-Password) {
            reject
        }
        files
        pap
    }
    authenticate {
        Auth-Type PAP {
            pap
        }
    }
    post-auth {
        update reply {
            Message-Authenticator := 0x00000000000000000000000000000000
        }
        Post-Auth-Type REJECT {
            update reply {
                Message-Authenticator := 0x00000000000000000000000000000000
            }
        }
    }
}
'''
    files = {
        "radiusd.conf": config,
        "clients.conf": clients,
        "dictionary": "$INCLUDE /usr/share/freeradius/dictionary\n",
        "authorize": f'labco.radius.student Cleartext-Password := "{password}"\n    Filter-Id := "LABCO-STUDENTS"\n',
    }
    for name, contents in files.items():
        path = RUNTIME / name
        path.write_text(contents, encoding="ascii")
        path.chmod(0o600)
        os.chown(path, 10001, 10001)
    os.chown(RUNTIME, 10001, 10001)
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    os.execv("/usr/sbin/freeradius", ["freeradius", "-f", "-l", "stdout", "-d", str(RUNTIME)])


if __name__ == "__main__":
    main()
