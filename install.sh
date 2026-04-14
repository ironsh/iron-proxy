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
        # Import the embedded iron-proxy release signing key
        gpg --batch --import 2>/dev/null <<'PGPKEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
m6R570al
=BDYk
-----END PGP PUBLIC KEY BLOCK-----
PGPKEY
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
