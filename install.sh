#!/usr/bin/env bash
set -euo pipefail

REPO="ironsh/iron-proxy"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)
        echo "Error: unsupported OS: $OS" >&2
        exit 1
        ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)
        echo "Error: unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# Get latest version from GitHub API
echo "Fetching latest release..."
VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version" >&2
    exit 1
fi

# Strip leading 'v' for the archive name
VERSION_NUM="${VERSION#v}"

ARCHIVE="iron-proxy_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading iron-proxy ${VERSION} for ${OS}/${ARCH}..."
curl -fsSL -o "${TMPDIR}/${ARCHIVE}" "$URL"

echo "Extracting..."
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

echo "Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/iron-proxy" "${INSTALL_DIR}/iron-proxy"
else
    sudo mv "${TMPDIR}/iron-proxy" "${INSTALL_DIR}/iron-proxy"
fi

echo "iron-proxy ${VERSION} installed successfully."
iron-proxy --version 2>/dev/null || true
