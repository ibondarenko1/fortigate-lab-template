# Local PAP fixture

The fixture runs Debian's FreeRADIUS 3 package with one synthetic account, `labco.radius.student`. An accepted response contains `Filter-Id = LABCO-STUDENTS`. This account has no administrator attributes. The service accepts PAP with Message-Authenticator from the single IPv4 address specified by `RADIUS_CLIENT_IP`.

## Compose integration

Build context is `training/radius`. Attach the service to the lab DMZ only and assign a free address on that segment. UDP 1812 is internal, with no published ports. Configure the FortiGate RADIUS object to source requests from its DMZ interface address, which must equal `RADIUS_CLIENT_IP`.

```yaml
radius:
  build: ./training/radius
  read_only: true
  cap_drop: [ALL]
  cap_add: [CHOWN, SETUID, SETGID]
  security_opt: [no-new-privileges:true]
  tmpfs:
    - /run/radius:mode=0700,size=1m
    - /tmp:mode=1777,size=4m
  environment:
    RADIUS_CLIENT_IP: ${LAB_DMZ_GUEST_IP}
  secrets:
    - source: radius_shared
      target: radius_shared
    - source: radius_password
      target: radius_password
  networks: [dmz]
  pids_limit: 32
```

Supply per-instance randomized hexadecimal values in private host files. The shared secret must contain 32–128 hex characters, and the student password 16–128 hex characters. Mount them at `/run/secrets/radius_shared` and `/run/secrets/radius_password`. Startup reads the files, creates a mode-0600 runtime configuration on tmpfs and drops to UID/GID 10001 before starting FreeRADIUS. Authentication credentials and packets are omitted from normal logs. Configuration and identity files should be regenerated from these mounts after each container restart.

## Native FortiOS test

After loading the company profile, open **User & Authentication → RADIUS Servers** and select `LABCO-RADIUS`. The profile sets the server to the fixture's DMZ address and uses the FortiGate DMZ interface as the source. If configuring the service manually, use PAP, UDP 1812, and the shared secret from `secrets/company/radius_shared` in the active deployment directory.

Select **Test User Credentials** and enter `labco.radius.student` with the password generated in `secrets/company/radius_password` in the active deployment directory. The test should report successful authentication. Repeat with a deliberately incorrect password, then with `unknown.student`. Both attempts should return an authentication failure. A timeout calls for a separate check of connectivity, the client address, the shared secret, and Message-Authenticator.

## Disposable verification

The optional `RADIUS_SELFTEST=true` additionally permits a loopback RADIUS client. Leave it unset for the normal DMZ fixture. The self-test prints only pass/fail and validates response authenticators. This invocation generates fresh throwaway secrets inside tmpfs and connects only through the container's loopback interface.

```sh
docker build -t local/radius-fixture:test training/radius
docker run -d --name radius-fixture-selftest --network none --read-only \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --tmpfs /run/radius:mode=0700 --tmpfs /run/secrets:mode=0700 --tmpfs /tmp \
  -e RADIUS_CLIENT_IP=10.231.32.1 -e RADIUS_SELFTEST=true \
  --entrypoint python3 local/radius-fixture:test \
  /opt/radius/selftest.py --bootstrap-disposable
docker exec radius-fixture-selftest python3 /opt/radius/selftest.py
docker stop radius-fixture-selftest
docker rm radius-fixture-selftest
```

Verified locally on 2026-11-19 with Debian package `freeradius 3.2.1+dfsg-4+deb12u1`. Positive PAP returned Access-Accept, an incorrect password returned Access-Reject, and an unknown username returned Access-Reject. Base image is pinned in the Dockerfile. Debian packages are resolved from signed Bookworm repositories at build time.

[FreeRADIUS PAP documentation](https://www.freeradius.org/radiusd/man/rlm_pap.html)
