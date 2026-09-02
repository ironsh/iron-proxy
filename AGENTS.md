# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

## Layout

Module path is `github.com/ironsh/iron-proxy` even though the repo is now `litmus-team/iron-proxy` — the import path was never renamed. Config schema lives in `internal/config/config.go`; `iron-proxy.example.yaml` and the README's Configuration section are the user-facing docs for it and are expected to move together with a schema change.

## Adding a transform

Transforms live one per package under `internal/transform/<name>/` and implement `transform.Transformer` (see `internal/transform/transform.go`). Copy the shape of a recent one — `internal/transform/gcpauth` is the cleanest example. Three steps are easy to miss:

1. `transform.Register("<yaml_name>", factory)` in the package's `init()`.
2. A blank import in `cmd/iron-proxy/main.go` under "Register built-in transforms" — without it the factory is never registered and the config fails with `unknown transform`.
3. Document the config in both `iron-proxy.example.yaml` and the README.

Keep the factory free of I/O beyond config validation, and split out a `newFromConfig(cfg, ..., dep)` that takes injectable dependencies so tests do not need real backends.

Conventions worth reusing rather than reinventing: `internal/hostmatch` for host/method/path rules (`RuleConfig` + `CompileRules`), `transform.BufferedBody` for any body access, `tctx.Annotate` for audit metadata (never secret values), and `secrets.BuildSource` to load an input from any configured secret backend.

## Reload semantics

There is no SIGHUP handler and no file watcher. Config is re-read by `POST /v1/reload` on the management API, which rebuilds the whole pipeline (`newReloadFunc` in `cmd/iron-proxy/main.go`), and by the control-plane poller in managed mode. A transform that needs to pick up an out-of-band file change has to do it itself — see the `fileStore` in `internal/transform/secretbroker`.

## Build, test, lint

- `go build ./...` and `go test ./...` are the gates; both must be clean.
- `integration_test/` needs `-integration` plus real external services (AWS, GCP, 1Password), so it does not run locally by default.
- Lint config is `.golangci.yml`. `gofmt -l ./...` reports several files that are already unformatted on `main`; check only the files you touched.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
