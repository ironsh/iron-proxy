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

CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

echo "Downloading iron-proxy ${VERSION} for ${OS}/${ARCH}..."
curl -fsSL -o "${TMPDIR}/${ARCHIVE}" "$URL"
curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUMS_URL"

echo "Verifying checksum..."
EXPECTED="$(grep "${ARCHIVE}" "${TMPDIR}/checksums.txt" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
    echo "Error: no checksum found for ${ARCHIVE}" >&2
    exit 1
fi
if command -v sha256sum &>/dev/null; then
    ACTUAL="$(sha256sum "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')"
else
    ACTUAL="$(shasum -a 256 "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Error: checksum mismatch" >&2
    echo "  expected: ${EXPECTED}" >&2
    echo "  actual:   ${ACTUAL}" >&2
    exit 1
fi
echo "Checksum verified."

# Verify GPG signature if gpg is available
if command -v gpg &>/dev/null; then
    echo "Verifying GPG signature..."
    SIGNATURE_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.asc"
    if curl -fsSL -o "${TMPDIR}/checksums.txt.asc" "$SIGNATURE_URL" 2>/dev/null; then
        # Import the iron-proxy public key
        PUBLIC_KEY_URL="https://raw.githubusercontent.com/${REPO}/main/public-key.asc"
        curl -fsSL "$PUBLIC_KEY_URL" | gpg --batch --import 2>/dev/null
        if gpg --batch --verify "${TMPDIR}/checksums.txt.asc" "${TMPDIR}/checksums.txt" 2>/dev/null; then
            echo "GPG signature verified."
        else
            echo "Error: GPG signature verification failed" >&2
            exit 1
        fi
    else
        echo "Warning: no GPG signature found for this release, skipping verification."
    fi
else
    echo "Note: gpg not found, skipping signature verification."
fi

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
