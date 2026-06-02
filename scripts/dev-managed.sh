#!/usr/bin/env bash
#
# dev-managed.sh — boot iron-proxy in managed mode against a local iron-control.
#
# Flow:
#   1. Obtain a proxy token (iprx_...): reuse IRON_PROXY_TOKEN if set, otherwise
#      register a new proxy instance with iron-control's admin API
#      (POST /api/v1/proxies, authenticated with the admin key IRON_ADMIN_KEY).
#      The create response returns a one-time token in data.token.
#   2. Boot iron-proxy in managed mode with that token (IRON_PROXY_TOKEN), which
#      syncs its config from POST /api/v1/proxy/sync.
#
# Listen ports are moved to high ports so the proxy does not need root. A local
# CA is generated on first run (default MITM mode requires one) and cached under
# ./dist/dev, which is gitignored.
#
# Usage:
#   ./scripts/dev-managed.sh                 # register a fresh proxy each run
#   IRON_PROXY_TOKEN=iprx_... ./scripts/dev-managed.sh   # reuse an existing token
#
# IRON_ADMIN_KEY defaults to a dev admin key. Override anything via the
# environment, e.g.:
#   IRON_CONTROL_PLANE_URL=http://localhost:4000 IRON_ADMIN_KEY=iak_... ./scripts/dev-managed.sh

set -euo pipefail

cd "$(dirname "$0")/.."

# iron-control admin API key (iak_...). Used to register the proxy instance.
IRON_ADMIN_KEY="${IRON_ADMIN_KEY:-iak_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

# Control plane: local iron-control.
export IRON_CONTROL_PLANE_URL="${IRON_CONTROL_PLANE_URL:-http://localhost:3000}"

# Name for the proxy instance created in iron-control.
PROXY_NAME="${PROXY_NAME:-dev-proxy}"

BIN="./dist/iron-proxy"
CA_DIR="./dist/dev"

# Build the binary (build the package dir, not main.go alone — sibling files
# like generate_ca.go must be included).
echo ">> building iron-proxy"
go build -o "$BIN" ./cmd/iron-proxy

# Generate a local CA on first run for MITM mode.
if [[ ! -f "$CA_DIR/ca.crt" || ! -f "$CA_DIR/ca.key" ]]; then
  echo ">> generating local dev CA in $CA_DIR"
  mkdir -p "$CA_DIR"
  "$BIN" generate-ca -outdir "$CA_DIR" -name "iron-proxy dev CA" -alg ed25519
fi

# Obtain a proxy token. If IRON_PROXY_TOKEN (iprx_...) is already set, reuse it
# and skip registration; otherwise register a new proxy instance via the admin
# API and capture the one-time token from the create response.
if [[ -n "${IRON_PROXY_TOKEN:-}" ]]; then
  echo ">> using supplied IRON_PROXY_TOKEN (skipping registration)"
else
  echo ">> registering proxy '$PROXY_NAME' with $IRON_CONTROL_PLANE_URL"
  create_resp="$(curl -fsS -X POST "$IRON_CONTROL_PLANE_URL/api/v1/proxies" \
    -H "Authorization: Bearer $IRON_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"data\":{\"name\":\"$PROXY_NAME\"}}")" || {
    echo "error: failed to create proxy instance (is iron-control running at $IRON_CONTROL_PLANE_URL? is IRON_ADMIN_KEY valid?)" >&2
    exit 1
  }

  IRON_PROXY_TOKEN="$(printf '%s' "$create_resp" | jq -r '.data.token // empty')"
  if [[ -z "$IRON_PROXY_TOKEN" ]]; then
    echo "error: no proxy token in create response:" >&2
    printf '%s\n' "$create_resp" >&2
    exit 1
  fi

  proxy_id="$(printf '%s' "$create_resp" | jq -r '.data.id // "?"')"
  echo ">> created proxy id=$proxy_id"
fi

# Managed mode is triggered by IRON_PROXY_TOKEN (the iprx_ token).
export IRON_PROXY_TOKEN

# Required by config validation; arbitrary for local dev.
export IRON_DNS_PROXY_IP="${IRON_DNS_PROXY_IP:-127.0.0.1}"

# High ports so we don't need root.
# Avoid 5353 — that's mDNS, already bound by Brave/Spotify/etc on macOS.
export IRON_DNS_LISTEN="${IRON_DNS_LISTEN:-127.0.0.1:15353}"
export IRON_PROXY_HTTP_LISTEN="${IRON_PROXY_HTTP_LISTEN:-127.0.0.1:8080}"
export IRON_PROXY_HTTPS_LISTEN="${IRON_PROXY_HTTPS_LISTEN:-127.0.0.1:8443}"
export IRON_METRICS_LISTEN="${IRON_METRICS_LISTEN:-127.0.0.1:9090}"

# MITM CA.
export IRON_TLS_CA_CERT="${IRON_TLS_CA_CERT:-$CA_DIR/ca.crt}"
export IRON_TLS_CA_KEY="${IRON_TLS_CA_KEY:-$CA_DIR/ca.key}"

export IRON_LOG_LEVEL="${IRON_LOG_LEVEL:-debug}"

echo ">> starting iron-proxy (managed mode -> $IRON_CONTROL_PLANE_URL)"
echo "   http=$IRON_PROXY_HTTP_LISTEN https=$IRON_PROXY_HTTPS_LISTEN dns=$IRON_DNS_LISTEN metrics=$IRON_METRICS_LISTEN"

# No --config: managed mode pulls its pipeline from the control plane; everything
# else comes from the IRON_* env vars above.
exec "$BIN"
