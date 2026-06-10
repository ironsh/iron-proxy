# iron-proxy Helm chart

Deploys [iron-proxy](https://github.com/ironsh/iron-proxy), a DNS-intercepting MITM egress
proxy, to Kubernetes.

## TL;DR

```bash
# Create a CA once and store it in a Secret (MITM mode needs one):
iron-proxy generate-ca -outdir ./ca -name "Acme egress CA"
kubectl create secret generic iron-proxy-ca \
  --from-file=ca.crt=./ca/ca.crt --from-file=ca.key=./ca/ca.key

# From a checkout of the repo:
helm install iron-proxy ./charts/iron-proxy \
  --set ca.existingSecret=iron-proxy-ca
```

The chart runs in standalone mode with a sample allowlist config by default. It is a
starting point: you will almost always want to edit `config` (especially
`config.dns.proxy_ip`), point at your CA Secret, and add your secret-backend credentials.
See below.

## How iron-proxy runs

iron-proxy intercepts DNS, answers queries with a single `proxy_ip`, then terminates and
inspects the HTTP/HTTPS traffic clients send to that IP. The chart wires up these
listeners, configured under `.Values.listeners`:

| Listener | `listeners` key | Default port | Enabled by default |
| --- | --- | --- | --- |
| DNS | `dns` | 53/UDP | yes |
| HTTP | `http` | 80/TCP | yes |
| HTTPS | `https` | 443/TCP | yes |
| Metrics / health (`GET /healthz`) | `metrics` | 9090/TCP | yes |
| Tunnel (CONNECT/SOCKS5) | `tunnel` | 8080/TCP | no |
| Postgres MITM | `postgres` | 5432/TCP | no |
| Management API | `management` | 9092/TCP | no |

Ports 53/80/443 are privileged, so the container is granted the `NET_BIND_SERVICE`
capability and otherwise runs as non-root with a read-only root filesystem.

### Listeners are the single source of truth for ports

`.Values.listeners` is the one place ports are defined. Each enabled listener is exposed on
the Service, exposed as a container port, **and** has its bind address (`:<port>`) fed into
the proxy automatically: merged into the rendered config in standalone mode, or emitted as
the matching `IRON_*_LISTEN` env var in managed mode. So the Service and the proxy can never
disagree about ports. Do not set `dns.listen`, `proxy.http_listen`, etc. under `config` —
those keys are overridden by `listeners`. To move a port, change it in one place:

```yaml
listeners:
  https:
    port: 8443        # Service port, container port, and proxy bind all become 8443
  tunnel:
    enabled: true     # turn on the optional CONNECT/SOCKS5 tunnel
```

## Run modes

### Standalone (default)

The chart renders `.Values.config` into a ConfigMap as `proxy.yaml` and starts the proxy
with `-config /etc/iron-proxy/config/proxy.yaml`. The config keys mirror
[`iron-proxy.example.yaml`](../../iron-proxy.example.yaml) exactly, except for listen
addresses, which come from `.Values.listeners` (see above).

```yaml
mode: standalone
service:
  type: LoadBalancer
config:
  dns:
    proxy_ip: "203.0.113.10"   # MUST equal the IP clients reach this proxy on
  tls:
    mode: "mitm"
    ca_cert: "/etc/iron-proxy/tls/ca.crt"
    ca_key: "/etc/iron-proxy/tls/ca.key"
  transforms:
    - name: allowlist
      config:
        domains: ["api.openai.com"]
    - name: secrets
      config:
        secrets:
          - source: { type: env, var: OPENAI_API_KEY }
            inject: { header: "Authorization", formatter: "Bearer {{ .Value }}" }
            rules:
              - host: "api.openai.com"
env:
  - name: OPENAI_API_KEY
    valueFrom:
      secretKeyRef: { name: my-api-keys, key: openai }
```

> `config.dns.proxy_ip` must be the address clients use to reach the proxy. Pin
> `service.clusterIP` (or a `LoadBalancer` IP) so you know that value ahead of time, and set
> `proxy_ip` to match. To use a ConfigMap you manage yourself instead of `.Values.config`,
> set `configExistingConfigMap`.

### Managed

In managed mode the proxy authenticates to the control plane with a bearer token and pulls
its transforms, secrets, and routes from there. There is no `proxy.yaml`: everything else is
configured through `IRON_*` env vars. The chart renders those for you from the `managed`
block, and listen addresses still come from `.Values.listeners` (as `IRON_*_LISTEN`). The CA
cert/key paths (`IRON_TLS_CA_CERT`/`IRON_TLS_CA_KEY`) are derived from the CA mount
automatically when `ca.mode` is not `none`.

```yaml
mode: managed
managed:
  existingTokenSecret: iron-proxy-token   # Secret with a "token" key
  # tokenSecretKey: token
  # controlPlaneURL: https://api.iron.sh   # override if self-hosting
  proxyIP: "203.0.113.10"                  # REQUIRED -> IRON_DNS_PROXY_IP
  # tlsMode: "sni-only"                     # -> IRON_TLS_MODE (set when ca.mode=none)
  # logLevel: "info"                        # -> IRON_LOG_LEVEL
ca:
  mode: existingSecret
  existingSecret: iron-proxy-ca
```

```bash
kubectl create secret generic iron-proxy-token --from-literal=token="$IRON_PROXY_TOKEN"
```

`managed.proxyIP` is required (the proxy fails validation without `IRON_DNS_PROXY_IP`).
Anything not covered by the `managed` block can still be set through `.Values.env`.

## CA certificate (MITM mode)

MITM mode mints leaf certificates from a CA, so clients must trust that CA. The CA must be
stable: a CA that changes on pod restart breaks every client that trusted the old one. The
mount path is always `/etc/iron-proxy/tls` (matching the default `config.tls.ca_cert`/
`ca_key`). Pick a `ca.mode`:

| `ca.mode` | Behavior | Use when |
| --- | --- | --- |
| `existingSecret` (default) | Mount a Secret you created | Production. Stable, rotatable CA. |
| `inline` | Provide `ca.cert`/`ca.key` PEM; the chart creates the Secret | GitOps where the CA lives in your (encrypted) values. |
| `none` | Mount nothing | `tls.mode: sni-only`, which needs no CA. |

Create a CA for `existingSecret` mode with the bundled subcommand:

```bash
iron-proxy generate-ca -outdir ./ca -name "Acme egress CA"
kubectl create secret generic iron-proxy-ca \
  --from-file=ca.crt=./ca/ca.crt --from-file=ca.key=./ca/ca.key
helm install iron-proxy ./charts/iron-proxy \
  --set ca.mode=existingSecret --set ca.existingSecret=iron-proxy-ca
```

Distribute `ca.crt` to clients as a trusted root.

## Secret-backend credentials

Transforms reference secrets from env vars, files, AWS, or 1Password. Supply the backing
credentials with:

- `env` / `envFrom` — reference your own Secrets (recommended for production).
- `secretEnv` — inline key/value pairs the chart stores in a Secret and injects via
  `envFrom` (convenient for demos).
- `extraVolumes` / `extraVolumeMounts` — for file-based sources, gRPC client certs, or GCP
  keyfiles.
- `serviceAccount.annotations` — for EKS IRSA / GKE Workload Identity used by the
  `workload_identity` AWS/GCP providers.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Replica count. Scaling needs a shared Service IP; see notes. |
| `image.repository` | `ironsh/iron-proxy` | Image repository. |
| `image.tag` | `""` | Image tag; falls back to chart `appVersion`. Pin a release in prod. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Pull secrets for private registries. |
| `mode` | `standalone` | `standalone` or `managed`. |
| `config` | sample | iron-proxy YAML, rendered to a ConfigMap (standalone). |
| `configExistingConfigMap` | `""` | Use an existing ConfigMap (with a `proxy.yaml` key). |
| `managed.token` | `""` | Inline control-plane token (creates a Secret). |
| `managed.existingTokenSecret` | `""` | Existing Secret holding the token. |
| `managed.tokenSecretKey` | `token` | Key within that Secret. |
| `managed.controlPlaneURL` | `""` | Override `IRON_CONTROL_PLANE_URL`. |
| `managed.proxyIP` | `""` | `IRON_DNS_PROXY_IP`. Required in managed mode. |
| `managed.tlsMode` | `""` | `IRON_TLS_MODE` (`mitm`/`sni-only`). |
| `managed.logLevel` | `""` | `IRON_LOG_LEVEL`. |
| `managed.upstreamResolver` | `""` | `IRON_DNS_UPSTREAM_RESOLVER`. |
| `ca.mode` | `existingSecret` | `existingSecret`, `inline`, or `none`. |
| `ca.existingSecret` | `""` | Secret name for `existingSecret` mode. |
| `ca.certKey` / `ca.keyKey` | `ca.crt` / `ca.key` | Keys within that Secret. |
| `ca.cert` / `ca.key` | `""` | PEM material for `inline` mode. |
| `env` | `[]` | Extra environment variables. |
| `envFrom` | `[]` | Pull env from existing Secrets/ConfigMaps. |
| `secretEnv` | `{}` | Inline key/values → chart Secret, injected via `envFrom`. |
| `service.type` | `ClusterIP` | Service type. |
| `service.clusterIP` | `""` | Static cluster IP (set so it can be `proxy_ip`). |
| `service.loadBalancerIP` | `""` | Static LB IP. |
| `service.annotations` | `{}` | Service annotations. |
| `listeners.*` | see values | Per-listener `enabled`/`port`/`protocol`. Single source of truth for ports. |
| `livenessProbe` / `readinessProbe` | `/healthz` on metrics | Probes; fully overridable. |
| `serviceAccount.create` | `true` | Create a ServiceAccount. |
| `serviceAccount.annotations` | `{}` | SA annotations (IRSA / Workload Identity). |
| `podSecurityContext` | non-root | Pod security context. |
| `securityContext` | drop ALL, add `NET_BIND_SERVICE` | Container security context. |
| `terminationGracePeriodSeconds` | `30` | Graceful shutdown window (app uses 10s). |
| `resources` | `{}` | Resource requests/limits. |
| `nodeSelector` / `tolerations` / `affinity` / `topologySpreadConstraints` | `{}`/`[]` | Scheduling. |
| `extraVolumes` / `extraVolumeMounts` | `[]` | Extra volumes for files/certs/keyfiles. |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor. |

## Notes and caveats

- **Single logical endpoint.** Because DNS interception hands every client one `proxy_ip`,
  `replicaCount > 1` only makes sense behind a single shared Service IP that load-balances
  to the replicas, with a config that is identical and stateless across pods.
- **Privileged ports.** If your cluster policy forbids `NET_BIND_SERVICE`, move the DNS/HTTP/
  HTTPS listeners to ports >= 1024 via `listeners.*.port` (which updates the bind, the
  container port, and the Service together).
- **CA trust.** Generate the CA once and keep it in a Secret. Clients trust the CA, so it
  must survive pod restarts and rollouts unchanged.
