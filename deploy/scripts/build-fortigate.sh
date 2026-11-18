#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="$DEPLOY_DIR/.build"
VRNETLAB_COMMIT="a21b24bea0e470f2264d69e7eb2266b39f60738f"
VRNETLAB_URL="https://github.com/srl-labs/vrnetlab.git"
BASE_IMAGE="ghcr.io/srl-labs/vrnetlab-base@sha256:57f36ae1cf44a78a6b2cad35a6276565c56edfd28e8160ae9a772929db28fd6d"

usage() {
  printf 'Usage: %s /path/to/official/FortiGate-VM64-KVM.qcow2\n' "$0" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
FIRMWARE="$(realpath "$1")"
[[ -f "$FIRMWARE" ]] || { printf 'Firmware file not found: %s\n' "$FIRMWARE" >&2; exit 1; }
case "$FIRMWARE" in
  *.qcow2) ;;
  *) printf 'The official KVM image must be a .qcow2 file.\n' >&2; exit 1 ;;
esac

command -v docker >/dev/null || { printf 'docker is required.\n' >&2; exit 1; }
command -v git >/dev/null || { printf 'git is required.\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'python3 is required.\n' >&2; exit 1; }

if [[ -f "$DEPLOY_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$DEPLOY_DIR/.env"
  set +a
fi
: "${FORTIGATE_IMAGE:=local/fortigate-lab:7.6.8}"

mkdir -p "$BUILD_ROOT"
SOURCE_DIR="${VRNETLAB_DIR:-$BUILD_ROOT/vrnetlab}"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git clone --filter=blob:none --no-checkout "$VRNETLAB_URL" "$SOURCE_DIR"
fi
git -C "$SOURCE_DIR" fetch --depth=1 origin "$VRNETLAB_COMMIT"
git -C "$SOURCE_DIR" checkout --detach "$VRNETLAB_COMMIT" >/dev/null

CONTEXT="$BUILD_ROOT/context-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$CONTEXT/common"
cp -a "$SOURCE_DIR/fortinet/common/." "$CONTEXT/common/"
cp -a "$SOURCE_DIR/common/." "$CONTEXT/"
cp "$SOURCE_DIR/fortinet/fortigate/docker/launch.py" "$CONTEXT/launch.py"
cp "$DEPLOY_DIR/fortigate/Dockerfile" "$CONTEXT/Dockerfile"
cp "$DEPLOY_DIR/fortigate/launcher.py" "$CONTEXT/launcher.py"
cp "$DEPLOY_DIR/fortigate/lab-entrypoint.sh" "$CONTEXT/lab-entrypoint.sh"
cp "$FIRMWARE" "$CONTEXT/fortios.qcow2"

docker run --rm --network none -v "$FIRMWARE:/disk.qcow2:ro" --entrypoint qemu-img "$BASE_IMAGE" info --output=json /disk.qcow2 > "$CONTEXT/firmware-qcow2-info.json"
python3 - "$CONTEXT/firmware-qcow2-info.json" <<'PY'
import json
import pathlib
import sys

info = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if info.get("format") != "qcow2":
    raise SystemExit("the supplied image is not qcow2")
if info.get("backing-filename"):
    raise SystemExit("the supplied image must be a standalone qcow2 without a backing file")
if int(info.get("virtual-size", 0)) < 1024 * 1024 * 1024:
    raise SystemExit("the supplied qcow2 virtual disk is unexpectedly small")
PY

docker build --platform linux/amd64 --build-arg IMAGE=fortios.qcow2 --tag "$FORTIGATE_IMAGE" "$CONTEXT"

printf 'Built local image %s from the pinned vrnetlab commit %s.\n' "$FORTIGATE_IMAGE" "$VRNETLAB_COMMIT"
printf 'Build context retained under %s and ignored by Git; do not push this image.\n' "$CONTEXT"
