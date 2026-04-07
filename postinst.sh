#!/bin/sh
set -e

INSTALL_DIR="/opt/nox-cli"
VENV="$INSTALL_DIR/.venv"
WRAPPER="$INSTALL_DIR/nox-wrapper.sh"
BIN="/usr/bin/nox-cli"
NOX_VERSION=$(grep '^VERSION=' "$INSTALL_DIR/build_deb.sh" 2>/dev/null | cut -d'"' -f2 || echo "1.0.0")

case "$1" in
    configure)
        echo "[*] NOX Framework: Setting up isolated virtual environment..."

        # 1. Create venv if absent
        if [ ! -f "$VENV/bin/python" ]; then
            python3 -m venv "$VENV"
            echo "[+] Virtual environment created at $VENV"
        else
            echo "[*] Virtual environment already exists — skipping creation."
        fi

        # 2. Upgrade pip inside venv
        "$VENV/bin/pip" install --quiet --upgrade pip

        # 3. Install dependencies strictly inside venv
        "$VENV/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
        echo "[+] Dependencies installed."

        # 4. Build source plugins
        "$VENV/bin/python" "$INSTALL_DIR/build_sources.py" > /dev/null 2>&1 || true
        chmod -R 644 "$INSTALL_DIR/sources/"*.json 2>/dev/null || true
        echo "[+] Source plugins built."

        # 5. Link wrapper to /usr/bin/nox-cli
        chmod +x "$WRAPPER"
        ln -sf "$WRAPPER" "$BIN"
        echo "[+] Executable linked: $BIN"

        echo "[+] NOX v${NOX_VERSION} installed. Run: nox-cli --help"
        ;;

    abort-upgrade|abort-remove|abort-deconfigure)
        ;;

    *)
        echo "postinst called with unknown argument: $1" >&2
        exit 1
        ;;
esac

exit 0
