#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="$(docker build --quiet "$fixture_dir")"
container="$(docker run --detach --rm --network none --read-only \
  --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --tmpfs /run/radius:mode=0700 --tmpfs /run/secrets:mode=0700 --tmpfs /tmp \
  -e RADIUS_CLIENT_IP=10.231.32.1 -e RADIUS_SELFTEST=true \
  --entrypoint python3 "$image" /opt/radius/selftest.py --bootstrap-disposable)"
trap 'docker stop -t 2 "$container" >/dev/null' EXIT
docker exec "$container" python3 /opt/radius/selftest.py
