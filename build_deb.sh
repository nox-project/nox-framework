#!/usr/bin/env bash
set -e

# NOX v1.0.0 — .deb build script (FPM)
# Requires: fpm  →  gem install fpm

VERSION="1.0.0"
PKG_NAME="nox-cli"
ARCH="all"
OUT_DIR="dist"

command -v fpm &>/dev/null || { echo "[!] fpm not found: gem install fpm" >&2; exit 1; }

mkdir -p "$OUT_DIR"
echo "[*] Building ${PKG_NAME}_${VERSION}_${ARCH}.deb ..."

fpm \
    --input-type dir \
    --output-type deb \
    --name "$PKG_NAME" \
    --version "$VERSION" \
    --architecture "$ARCH" \
    --maintainer "nox-project <nox-project@users.noreply.github.com>" \
    --description "NOX — Cyber Threat Intelligence Framework — 120+ async breach sources, pivot engine, HVT detection" \
    --url "https://github.com/nox-project/nox-framework" \
    --license "Apache-2.0" \
    --depends "python3" \
    --depends "python3-venv" \
    --depends "python3-pip" \
    --after-install postinst.sh \
    --package "${OUT_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb" \
    --force \
    nox.py=/opt/nox-cli/nox.py \
    build_sources.py=/opt/nox-cli/build_sources.py \
    requirements.txt=/opt/nox-cli/requirements.txt \
    sources/=/opt/nox-cli/sources/ \
    sources/helpers/=/opt/nox-cli/sources/helpers/ \
    nox-wrapper.sh=/opt/nox-cli/nox-wrapper.sh \
    docs/nox-cli.1=/usr/share/man/man1/nox-cli.1

echo "[+] Built: ${OUT_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb"
