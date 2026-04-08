#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sign-release.sh <release-tag>

Downloads checksums.txt from the given GitHub release tag, signs it with GPG
(creating checksums.txt.asc), and uploads the signature asset back to the same
release.

Requirements:
  - gh CLI authenticated and configured for this repository
  - gpg configured with a default secret key (or set GPG_KEY_ID)

Environment variables:
  GPG_KEY_ID   Key id/fingerprint to use for signing
               (default: 7969C7E131F29652C601752C64D88022DBC645D1)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  echo "Error: missing release tag."
  usage
  exit 1
fi

TAG="$1"

for cmd in gh gpg mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required command not found: $cmd"
    exit 1
  fi
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

CHECKSUMS_FILE="$WORKDIR/checksums.txt"
SIG_FILE="$WORKDIR/checksums.txt.asc"

echo "Downloading checksums.txt from release '$TAG'..."
gh release download "$TAG" \
  --pattern "checksums.txt" \
  --output "$CHECKSUMS_FILE"

if [[ ! -s "$CHECKSUMS_FILE" ]]; then
  echo "Error: checksums.txt was not downloaded or is empty."
  exit 1
fi

GPG_KEY_ID="${GPG_KEY_ID:-7969C7E131F29652C601752C64D88022DBC645D1}"

echo "Signing checksums.txt with GPG (key: $GPG_KEY_ID)..."
gpg --batch --yes --armor --detach-sign --local-user "$GPG_KEY_ID" --output "$SIG_FILE" "$CHECKSUMS_FILE"

if [[ ! -s "$SIG_FILE" ]]; then
  echo "Error: failed to create signature file."
  exit 1
fi

echo "Uploading signature to release '$TAG'..."
gh release upload "$TAG" "$SIG_FILE" --clobber

echo "Done: uploaded checksums.txt.asc to release '$TAG'."
