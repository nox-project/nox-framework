#!/usr/bin/env bash
set -e

VENV="/opt/nox-cli/.venv"
NOX="/opt/nox-cli/nox.py"

if [[ ! -f "$VENV/bin/python" ]]; then
    echo "[!] NOX Framework venv missing at $VENV — reinstall: sudo dpkg -i nox-cli_*.deb" >&2
    exit 1
fi

export PYTHONPATH="/opt/nox-cli:${PYTHONPATH:-}"
export NOX_PROG_NAME="nox-cli"
exec "$VENV/bin/python" "$NOX" "$@"
