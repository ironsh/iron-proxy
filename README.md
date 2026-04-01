# iron-proxy

[![Docker Pulls](https://img.shields.io/docker/pulls/ironsh/iron-proxy)](https://hub.docker.com/r/ironsh/iron-proxy)

An egress firewall for untrusted workloads. Default-deny HTTP/HTTPS, secret
injection, and full audit logging, in a single binary.

Sandboxed containers can make outbound requests to anywhere. iron-proxy sits
between your workload and the internet as a MITM proxy with a built-in DNS
server, giving you:

- **Default-deny egress control.** Only allowlisted domains and CIDRs get through.
- **Secret injection.** Workloads send proxy tokens; iron-proxy swaps in real
  secrets before the request leaves. The sandbox never sees the real key.
- **Structured audit logging.** Every request logged as JSON with per-transform
  traces, so you know exactly what was allowed, blocked, or rewritten.
- **Protocol support.** WebSocket upgrades and Server-Sent Events are proxied
  natively.

<div align="center">
    <a href="https://screen.studio/share/Gq2zqtrp" target="_blank">
        <img src="./images/intro.gif" width="75%" />
    </a>
</div>

## Installation

Docker images are available on [Docker Hub](https://hub.docker.com/r/ironsh/iron-proxy)
and pre-built binaries for Linux/macOS (amd64/arm64) are on
[GitHub Releases](https://github.com/ironsh/iron-proxy/releases).

Or build from source:

```bash
go build -o iron-proxy ./cmd/iron-proxy
```

## Quick start

```bash
cd examples/docker-compose
docker compose up
```

This starts the proxy and a demo client that runs five requests: allowed,
blocked, and three secret-swap scenarios. Check the proxy logs for audit output:

```bash
docker compose logs proxy
```

Every proxied request produces a structured JSON audit entry:

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "action": "allow",
  "status_code": 200,
  "duration_ms": 142,
  "request_transforms": [
    { "name": "allowlist", "action": "continue" },
    {
      "name": "secrets",
      "action": "continue",
      "annotations": { "swapped": [{ "secret": "OPENAI_API_KEY", "locations": ["header:Authorization"] }] }
    }
  ]
}
```

Rejected requests include a `rejected_by` field and log at WARN level. See
[Audit log format](#audit-log-format) for the full schema.

## Production usage

### 1. Generate a CA

iron-proxy terminates TLS by generating leaf certificates on the fly, signed by
a CA you provide. Client containers must trust this CA.

```bash
mkdir -p certs
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes \
    -key certs/ca.key \
    -sha256 -days 3650 \
    -subj "/CN=iron-proxy CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" \
    -out certs/ca.crt
```

### 2. Create a Docker network

iron-proxy needs a fixed IP so containers can point their DNS at it:

```bash
docker network create --subnet=172.20.0.0/24 iron-proxy
```

### 3. Start iron-proxy

```bash
docker run -d --name iron-proxy \
  --network iron-proxy --ip 172.20.0.2 \
  -v $(pwd)/proxy.yaml:/etc/iron-proxy/proxy.yaml:ro \
  -v $(pwd)/certs/ca.crt:/etc/iron-proxy/ca.crt:ro \
  -v $(pwd)/certs/ca.key:/etc/iron-proxy/ca.key:ro \
  -e OPENAI_API_KEY=sk-real-key \
  ironsh/iron-proxy:latest -config /etc/iron-proxy/proxy.yaml
```

### 4. Route containers through the proxy

The simplest approach is DNS-based routing: point the container's DNS at
iron-proxy and all hostname lookups resolve to the proxy IP, routing traffic
through it automatically:

```bash
docker run --rm \
  --network iron-proxy \
  --dns 172.20.0.2 \
  -v $(pwd)/certs/ca.crt:/certs/ca.crt:ro \
  curlimages/curl --cacert /certs/ca.crt https://httpbin.org/get
```

For stronger enforcement, layer nftables rules to block non-proxy egress, or use
TPROXY for kernel-level interception. See [Routing traffic to the
proxy](#routing-traffic-to-the-proxy) for details on each approach.

## Why iron-proxy?

|                          | iron-proxy                     | Squid                       | mitmproxy                 | Envoy                              |
| ------------------------ | ------------------------------ | --------------------------- | ------------------------- | ---------------------------------- |
| Default-deny egress      | Built-in                       | Requires complex ACL config | Requires custom scripting | Requires RBAC/filter configuration |
| Secret injection         | Built-in                       | No                          | No                        | No                                 |
| Structured audit logging | Built-in, per-transform traces | Basic access logs           | Plugin-based              | Configurable access logs           |
| Setup complexity         | Single binary + YAML           | Extensive config language   | Python scripting          | Complex YAML or control plane      |

iron-proxy is purpose-built for one job: controlling and auditing egress from
untrusted workloads. Squid can do default-deny but requires significant ACL
configuration and has no concept of secret injection. mitmproxy is a great
debugging tool but isn't designed for production enforcement. Envoy is a
general-purpose proxy that can be configured to do parts of this, but it's
far more complexity than the problem requires.

## How it works

iron-proxy runs a DNS server and an HTTP/HTTPS proxy. Point your container's DNS
at iron-proxy and all hostname lookups resolve to the proxy IP, routing traffic
through it automatically. The proxy terminates TLS (generating leaf certs on the
fly from a CA you provide), runs the request through an ordered transform
pipeline, forwards it upstream, and runs the response back through the pipeline.

```
Container → DNS lookup → iron-proxy IP → TLS termination → transforms → upstream
```

Transforms run in order. Built-in transforms:

| Transform   | What it does                                                                                                            |
| ----------- | ----------------------------------------------------------------------------------------------------------------------- |
| `allowlist` | Permits requests to matching domains/CIDRs; rejects everything else (403).                                              |
| `secrets`   | Scans headers, query params, and optionally body for proxy tokens and swaps in real secrets from environment variables. |

## Configuration

iron-proxy takes a single flag: `-config path/to/config.yaml`. Here's the
full shape (see [`iron-proxy.example.yaml`](iron-proxy.example.yaml) for a
copy-pasteable starting point):

```yaml
dns:
  listen: ":53"
  proxy_ip: "10.16.0.1" # IP where iron-proxy is running (required)
  passthrough: # Domains forwarded to OS resolver
    - "*.internal.corp"
    - "metadata.google.internal"
  records: # Static DNS records (highest precedence)
    - name: "internal.example.com"
      type: A
      value: "10.0.0.5"

proxy:
  http_listen: ":80"
  https_listen: ":443"

tls:
  ca_cert: "/etc/iron-proxy/ca.crt" # Required
  ca_key: "/etc/iron-proxy/ca.key" # Required
  cert_cache_size: 1000 # LRU cache for generated leaf certs
  leaf_cert_expiry_hours: 72

transforms:
  - name: allowlist
    config:
      domains:
        - "api.openai.com"
        - "*.anthropic.com"
      cidrs:
        - "10.0.0.0/8"

  - name: secrets
    config:
      source: env
      secrets:
        - var: OPENAI_API_KEY # Env var holding the real secret
          proxy_value: "proxy-token-123" # Token the sandbox sends
          match_headers: ["Authorization"]
          match_body: false
          hosts:
            - name: "api.openai.com"

log:
  level: "info" # debug, info, warn, error
```

### DNS

Everything resolves to `proxy_ip` by default, which is what routes traffic
through the proxy. Exceptions:

- **`passthrough`:** glob patterns forwarded to the OS resolver (e.g.,
  `*.internal.corp`). Traffic to these hosts bypasses the proxy entirely.
- **`records`:** static A or CNAME records. Highest precedence.

### Allowlist

Default-deny. Requests must match at least one domain glob or CIDR to proceed.
Unmatched requests get a `403 Forbidden`.

Domain patterns use glob matching: `*.example.com` matches any subdomain and
`example.com` itself.

### Secrets

The sandbox never holds real credentials. Instead:

1. Set real secrets as environment variables on the iron-proxy container.
2. Give the sandbox a proxy token (e.g., `proxy-openai-abc123`).
3. Configure the `secrets` transform to map proxy tokens to env vars.

iron-proxy scans outbound requests and replaces proxy tokens with the real
values before forwarding upstream. You control where it looks:

- **`match_headers`:** list of header names to scan. Empty list = all headers.
- **`match_body`:** scan the request body (buffered, up to 1 MB).
- **`hosts`:** restrict swapping to specific domains or CIDRs.

Query parameters are always scanned.

### TLS

iron-proxy generates leaf certificates on the fly, signed by the CA you provide.
The client container must trust this CA (add it to the system trust store or pass
it via `--cacert`). Certs are cached in an LRU cache keyed by SNI hostname.

## Routing traffic to the proxy

There are three approaches, with increasing enforcement.

### DNS-based (simple)

Point the container's DNS at iron-proxy. All lookups resolve to the proxy IP,
so HTTP/HTTPS traffic flows through it naturally. This is what the
[Docker Compose example](#docker-compose-example) uses:

```yaml
services:
  client:
    dns:
      - 172.20.0.2 # iron-proxy IP
```

Easy to set up but easy to bypass: the workload can hardcode IPs or use its
own DNS resolver to skip the proxy entirely.

### DNS + nftables egress firewall (enforced)

Layer an nftables firewall on top of DNS routing. DNS still steers traffic to
the proxy, but nftables ensures the workload _can't_ talk to anything else,
even with hardcoded IPs.

The [`examples/nftables`](examples/nftables/) directory has a working setup.
The client container loads firewall rules on startup before running any
application traffic:

**nftables.conf** allows traffic to the proxy, drops everything else:

```
table ip iron {
  chain output {
    type filter hook output priority 0; policy drop;

    # allow loopback
    oif lo accept

    # allow traffic to the proxy itself (DNS + HTTP/HTTPS)
    ip daddr 172.20.0.2 tcp dport { 80, 443 } accept
    ip daddr 172.20.0.2 udp dport 53 accept

    # allow established/related (return traffic)
    ct state established,related accept

    # log and drop everything else
    log prefix "iron-proxy-drop: " drop
  }
}
```

**docker-compose.yml:** the client image is built with nftables
pre-installed. The entrypoint loads the rules, then runs the demo.
`CAP_NET_ADMIN` is required to load the rules:

```yaml
services:
  proxy:
    # ... same as DNS example ...
    networks:
      demo:
        ipv4_address: 172.20.0.2

  client:
    build:
      context: .
      dockerfile: Dockerfile.client # alpine + curl + nftables
    dns:
      - 172.20.0.2
    cap_add:
      - NET_ADMIN
    volumes:
      - ./nftables.conf:/etc/nftables.conf:ro
      - certs:/certs:ro
    networks:
      demo:
        ipv4_address: 172.20.0.4
```

In a production setup you'd load the rules in an entrypoint wrapper and then
`exec` your actual process as a non-root user without `CAP_NET_ADMIN`.

### TPROXY (transparent proxy)

For environments where you can't control the workload's DNS at all, nftables
TPROXY can redirect traffic at the kernel level without any cooperation from
the workload. This intercepts packets in the PREROUTING chain and hands them
directly to iron-proxy:

```
table ip iron {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # redirect HTTP/HTTPS to iron-proxy via TPROXY
    tcp dport 80 tproxy to 172.20.0.2:80 meta mark set 1 accept
    tcp dport 443 tproxy to 172.20.0.2:443 meta mark set 1 accept
  }

  chain output {
    type route hook output priority mangle; policy accept;

    # mark locally-originated packets for policy routing
    tcp dport { 80, 443 } meta mark set 1
  }
}
```

This requires `ip rule` and `ip route` setup to route marked packets to a
local socket, plus iron-proxy must bind with `IP_TRANSPARENT`. This is more
complex to set up but provides the strongest guarantee that traffic can't
bypass the proxy. TPROXY operates below DNS, so it catches hardcoded IPs,
custom resolvers, and anything else the workload might try.

## Docker Compose example

The [`examples/docker-compose`](examples/docker-compose/) directory contains a
working setup. The key pieces:

**docker-compose.yml:** proxy and client on a shared bridge network. Real
secrets are set as env vars on the proxy container only:

```yaml
services:
  proxy:
    build:
      context: ../..
      dockerfile: examples/docker-compose/Dockerfile
    environment:
      - OPENAI_API_KEY=sk-real-openai-key-do-not-share
      - INTERNAL_TOKEN=real-internal-secret-value
    volumes:
      - certs:/certs
    networks:
      demo:
        ipv4_address: 172.20.0.2

  client:
    image: alpine:latest
    dns:
      - 172.20.0.2 # Point DNS at the proxy
    volumes:
      - certs:/certs:ro
    networks:
      demo:
        ipv4_address: 172.20.0.4
```

**proxy.yaml** allowlists `httpbin.org` and `icanhazip.com`, swaps two
secrets:

```yaml
transforms:
  - name: allowlist
    config:
      domains:
        - "httpbin.org"
        - "icanhazip.com"
      cidrs:
        - "172.20.0.0/24"

  - name: secrets
    config:
      source: env
      secrets:
        - var: OPENAI_API_KEY
          proxy_value: "proxy-openai-abc123"
          match_headers: ["Authorization"]
          hosts:
            - name: "httpbin.org"

        - var: INTERNAL_TOKEN
          proxy_value: "proxy-internal-tok"
          match_headers: [] # scan all headers
          hosts:
            - name: "httpbin.org"
```

The client script sends five requests to demonstrate each behavior:

```bash
# 1. Allowed request
curl https://httpbin.org/get

# 2. Blocked request (not in allowlist)
curl https://example.com/

# 3. Secret swap: proxy token replaced with real key in Authorization header
curl -H "Authorization: Bearer proxy-openai-abc123" https://httpbin.org/headers

# 4. Secret swap: proxy token in custom header
curl -H "X-Internal: proxy-internal-tok" https://httpbin.org/headers

# 5. Secret swap: proxy token in query parameter
curl "https://httpbin.org/get?token=proxy-openai-abc123&q=hello"
```

## Audit log format

Every proxied request produces a structured JSON log entry:

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "action": "allow",
  "status_code": 200,
  "duration_ms": 142,
  "request_transforms": [
    {
      "name": "allowlist",
      "action": "continue"
    },
    {
      "name": "secrets",
      "action": "continue",
      "annotations": {
        "swapped": [{ "secret": "OPENAI_API_KEY", "locations": ["header:Authorization"] }]
      }
    }
  ],
  "response_transforms": []
}
```

Rejected requests include a `rejected_by` field and log at WARN level.

## iron.sh

Need Vault/KMS secret backends, a Kubernetes operator, or centralized policy
management? [iron.sh](https://iron.sh) builds on iron-proxy with enterprise
features for teams running this at scale.
