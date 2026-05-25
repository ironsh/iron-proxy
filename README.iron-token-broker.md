# iron-token-broker

iron-token-broker is a coordinator process that owns the OAuth refresh-token
state machine for one or more credentials. iron-proxy instances fetch the
current access token from the broker over HTTP, so the refresh family is
never touched concurrently by multiple proxies.

## When to use it

Use iron-token-broker when **all** of the following are true:

- The upstream IdP rotates the refresh token on every use, AND
- The IdP enforces strict reuse detection (presenting an already-rotated
  refresh token invalidates the entire family), AND
- More than one iron-proxy instance shares the credential.

Two examples that hit all three: OpenAI Codex
(`https://auth.openai.com/oauth/token`) and Anthropic Claude Code OAuth.
Modern Okta, Auth0, and Entra ID configurations behave the same way when
refresh-token rotation is enabled.

If only one iron-proxy ever holds the credential, or the IdP doesn't
rotate, the built-in `oauth_token` transform in iron-proxy is simpler and
sufficient. The broker is a separate process specifically because race-free
rotation across multiple proxies needs a single writer.

## Architecture

```
┌─────────────┐  GET /credentials/{id}/access_token  ┌──────────────────────┐
│ iron-proxy  │ ─────────────────────────────────▶   │ iron-token-broker    │
└─────────────┘                                       │  - per-credential    │
                                                       │    refresh loop     │
┌─────────────┐                                       │  - HTTP API + bearer│
│ iron-proxy  │ ─────────────────────────────────▶   │  - Prometheus       │
└─────────────┘                                       └──────────┬──────────┘
                                                                 │
                                                                 ▼
                                                       ┌──────────────────────┐
                                                       │ Store                │
                                                       │  file / 1Password /  │
                                                       │  Connect / SM / SSM  │
                                                       └──────────────────────┘
```

The broker is the only writer to the IdP token endpoint for each
credential. iron-proxy never touches refresh tokens.

## Quick start

1. Bootstrap a credential blob into your chosen store (see "Bootstrap" below).
2. Write an `iron-token-broker.yaml` (see `iron-token-broker.example.yaml`).
3. Start the broker:

   ```
   iron-token-broker --config iron-token-broker.yaml
   ```

4. From iron-proxy, fetch the current access token:

   ```
   curl -H "Authorization: Bearer $IRON_BROKER_TOKEN" \
     http://broker.internal:8181/credentials/openai-codex/access_token
   ```

   Response:

   ```json
   {"access_token":"...","expires_at":"2026-05-24T16:00:00Z"}
   ```

## Bootstrap procedure

The broker does not run the initial OAuth authorization-code flow itself.
A human runs that flow once with the IdP's own tooling, captures the
resulting refresh token, and writes a JSON blob to the store the broker
will read on startup.

The blob shape is the same across every backend:

```json
{
  "access_token": "<optional; broker mints on first refresh if empty>",
  "refresh_token": "<required>",
  "expires_at": "<RFC 3339 timestamp; broker overwrites on first refresh>",
  "last_refresh": "<RFC 3339 timestamp; broker overwrites on first refresh>"
}
```

Only `refresh_token` is required. The broker overwrites the other fields
on every successful refresh.

### OpenAI Codex

The Codex CLI (`@openai/codex`) runs an OAuth authorization-code flow on
first use and saves the resulting tokens to its config file. Capture them
from there:

1. Run `codex login` and complete the browser flow.
2. Locate the Codex tokens file (typically
   `~/.codex/tokens.json` or under `~/Library/Application Support/codex/`).
3. Build the broker blob from the Codex file's `access_token`,
   `refresh_token`, and `expires_at` fields.
4. Write the blob to your configured store.

### Anthropic Claude Code OAuth

Claude Code's OAuth flow is similar. After authenticating once with the
Claude Code CLI, locate its credential file and reshape the contents into
the broker blob format.

### Per-backend write procedure

| Backend           | How to write the bootstrap blob                              |
| ----------------- | ------------------------------------------------------------ |
| `file`            | `printf '%s' "$BLOB" > /var/lib/iron-token-broker/x.json && chmod 600 ...` |
| `1password`       | Edit the item in the 1Password app; paste the JSON into the named field. |
| `1password_connect` | Same: edit via the 1Password app or via `op` CLI; Connect reads it. |
| `aws_sm`          | `aws secretsmanager put-secret-value --secret-id ... --secret-string "$BLOB"` |
| `aws_ssm`         | `aws ssm put-parameter --name ... --type SecureString --value "$BLOB" --overwrite` |

After the bootstrap blob lands, restart the broker. The first refresh
overwrites the access token with a freshly-minted one.

## Configuration

See `iron-token-broker.example.yaml` for the full set of options with
inline explanations. Reference for each store backend:

```yaml
# Local file. Path must be absolute.
store:
  type: file
  path: /var/lib/iron-token-broker/openai-codex.json

# 1Password via SDK (service account token). vault and item segments of
# secret_ref must be UUIDs: the SDK takes raw IDs and looking names up
# would cost a list call per refresh. Copy UUIDs with the 1Password
# app's right-click "Copy Item UUID" / "Copy Vault UUID" actions. Reads
# OP_SERVICE_ACCOUNT_TOKEN from the environment.
store:
  type: 1password
  secret_ref: "op://abcd1234efgh5678ijkl9012mn/1234abcd5678efgh9012ijkl3m/credential_blob"

# 1Password via Connect server. Accepts UUIDs or human titles (Connect
# resolves them server-side). Reads OP_CONNECT_HOST and OP_CONNECT_TOKEN
# from the environment.
store:
  type: 1password_connect
  secret_ref: "op://Engineering/openai-codex/credential_blob"

# AWS Secrets Manager.
store:
  type: aws_sm
  secret_id: iron-broker/openai-codex
  region: us-east-1                     # optional

# AWS SSM Parameter Store. Stored as SecureString.
store:
  type: aws_ssm
  name: /iron-broker/openai-codex
  region: us-east-1                     # optional
```

`client_id` and `client_secret` accept the same shape but with the read-side
sources from iron-proxy's `internal/transform/secrets` package, including
`env` (which the store side cannot use because environment variables are
not writable).

## Deployment patterns

- **One broker per credential id, always.** The store is a dumb
  datastore with no optimistic concurrency. Running two brokers against
  the same store and same IdP credential will invalidate the token
  family within one refresh cycle: the IdP's reuse detection trips on
  the second writer's refresh and revokes the entire chain. Bind one
  broker per credential id and front it with an internal-only network
  policy so only your iron-proxy fleet can reach it. The `broker_credential_dead`
  gauge with reason `invalid_grant` (or similar) is the loudest signal
  if this rule is broken.
- **Restart on failure.** The broker has no HA story. Run it under
  systemd or your container scheduler with `Restart=always`. State lives
  in the store, so a restart is safe at any time.
- **Co-locate metrics scraping.** The broker exposes Prometheus metrics
  on `metrics_listen` (default `:9091`). Scrape it like any other service.

## Failure recovery

If `broker_credential_dead{credential_id="…"}` flips to `1`:

1. Check `reason` label on the gauge or the broker logs. Common causes:
   - `invalid_grant`, `refresh_token_reused`, `token_revoked`, or any
     other OAuth error code the IdP returned — the refresh token was
     rotated by another writer, expired, or the IdP revoked the
     session. Human re-auth required. (The broker treats any non-empty
     OAuth `error` field as terminal: there are no transient OAuth
     codes worth retrying.)
   - `blob_not_bootstrapped` — store has no blob; complete the
     bootstrap procedure above.
   - `blob_load_failed` — store unreachable beyond the broker's retry
     window. Investigate the backend before restarting.

2. Re-run the bootstrap procedure to overwrite the store blob with a
   fresh access_token + refresh_token pair from the upstream's CLI flow.

3. Restart the broker. (v1 has no SIGHUP reload; the operator workflow
   is "fix the store, restart the process.")

## Limitations

- **Single writer per credential id is required.** Running two brokers
  against the same store and same IdP credential will eventually
  invalidate the token family. The README cannot enforce this; the
  operator must.
- **No HA or leader election in v1.** That belongs in the hosted iron.sh
  coordinator, not this reference implementation.
- **No bootstrap subcommand.** Operators populate the store by hand or
  via vendor tooling. A scripted bootstrap is not safer than a manual one
  because it still requires the human OAuth flow.
- **No SIGHUP reload in v1.** Editing the config requires a process
  restart.
- **`env` cannot back the store.** Environment variables are read-only.

## Metrics

All instruments carry a `credential_id` label.

| Metric                                  | Type      | Notes                                                |
| --------------------------------------- | --------- | ---------------------------------------------------- |
| `broker_refresh_attempts_total`         | Counter   | Labels: `result`, `error_code`                       |
| `broker_refresh_duration_seconds`       | Histogram | Labels: `result`                                     |
| `broker_token_age_seconds`              | Gauge     | Seconds since last successful refresh                |
| `broker_token_time_to_expiry_seconds`   | Gauge     | Negative when the cached token is past expiry        |
| `broker_credential_dead`                | Gauge     | Labels: `reason`; alert on `> 0`                     |
| `broker_http_requests_total`            | Counter   | Labels: `endpoint`, `status`                         |
| `broker_http_request_duration_seconds`  | Histogram | Labels: `endpoint`, `status`                         |

Suggested alert: `broker_credential_dead > 0` for any window longer
than the time it takes a human to react.
