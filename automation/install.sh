#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
python3 -m venv ../.venv
../.venv/bin/python -m pip install --require-hashes --requirement requirements.txt
ANSIBLE_CONFIG="$PWD/ansible.cfg" ../.venv/bin/ansible-galaxy collection install \
    --requirements-file requirements.yml --collections-path "$PWD/collections"
