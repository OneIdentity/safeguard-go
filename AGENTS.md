# AGENTS.md — safeguard-go

Go SDK for the One Identity Safeguard Web API. Module path: `github.com/OneIdentity/safeguard-go`. Root package: `safeguard`. Go floor: 1.21.

The public surface is implemented: authentication and `Connect`, the Invoke/Service API surface, A2A credential workflows, and SignalR event listeners, with `browser` and `devicecode` login add-ons. Keep changes aligned with the established public API design; do not add public API without a maintainer decision.

## Project structure

```text
.                                  # package safeguard (root SDK package)
├── browser/                       # add-on: interactive system-browser (loopback) login
├── devicecode/                    # add-on: OAuth device authorization grant login
├── internal/auth/                 # login state machines (PKCE, password, cert, device, broker)
├── internal/livetest/             # ephemeral live-appliance provisioning for tests
├── samples/                       # one standalone package main per flow
├── testdata/                      # test fixtures (e.g. client certs under CERTS/)
├── pipeline-templates/            # Azure Pipelines reusable jobs/steps
└── .agents/skills/                # deeper agent workflow references
```

The root package holds the entire public surface: `Client`, credential constructors, Invoke/Service, A2A (`A2AContext`), events, typed errors, TLS options, and `Secret`. The single third-party dependency is `github.com/coder/websocket` (events).

## Setup, build, lint, and test

| Purpose | Command |
|---|---|
| Build all packages | `go build ./...` |
| Unit tests | `go test ./...` |
| Race-enabled unit tests | `go test -race ./...` |
| Vet | `go vet ./...` |
| Format check | `gofmt -w` for edits; CI checks `gofmt -l .` is empty |
| Lint | `golangci-lint run` |
| Live/integration tests | `go test ./...` with `SPP_HOST` and related secrets set |

Live-appliance tests live in-package alongside unit tests and **skip** (never fail) when `SPP_HOST` is unset, so `go test ./...` stays hermetic by default. The `internal/livetest` harness provisions and cleans up its own Safeguard resources from bootstrap/admin credentials. The reference appliance has the Resource Owner Grant disabled, so PKCE-headless is the primary automation login. **Live e2e against a running appliance is the standard of proof** — see the `testing-guide` skill.

## Coding conventions

- Keep public I/O APIs context-first: `func (c *Client) Get(ctx context.Context, ...)`.
- Use functional options for optional connection and request behavior (`Option`, `ReqOption`, `CertOption`, `A2AOption`, `PKCEOption`).
- Keep constructors side-effect-free; validate networked and certificate-dependent state at `Connect` time.
- Preserve the `Connect` + credential constructor model: `UsernamePassword`, `Certificate`, `PKCEHeadless`, `Token`, `Anonymous`, plus the browser/devicecode add-ons via the sealed `AuthorizedSession` seam.
- Keep A2A and events in the root package; keep login/broker internals under `internal/auth`.
- Model errors as typed Go errors that work with `errors.Is`/`errors.As` (`APIError` and its 401/403/404 specializations, `TransportError`, sentinel `Err*` values).
- Protect secrets with the `Secret` type. Never log, stringify, serialize, or commit credentials, tokens, certificate private keys, API keys, or retrieved passwords. `APIError.Error()` never includes the raw response body.
- TLS is secure by default. `WithInsecureTLS` is only for bootstrap/dev/test and must stay loud in docs and tests.
- Stay Go 1.21-compatible (no range-over-func iterators). Do not add dependencies casually.

## CI/CD

Azure Pipelines is the CI system. PR validation runs `go build`, the `gofmt -l` gate, `go vet`, `golangci-lint`, and race-enabled unit tests. Merge/tag validation may run live-appliance integration tests with pipeline secrets that are never exposed to fork PRs, logs, or artifacts. See the `build-and-release` skill for pipeline, versioning, and release details.

## Security

- Never commit passwords, tokens, A2A API keys, private keys, generated test certs, or service-connection output.
- Wrap new secret-bearing fields in `Secret` immediately so `fmt`, JSON, and `slog` stay redacted; expose bytes only through `Expose`/`ExposeString` where plaintext is required.
- Prefer `WithCABundle` trust over `WithInsecureTLS`.

## Commit and PR workflow

The maintainer reviews and approves every commit message before commits are created. Do not commit without explicit instruction. Stage specific files, never `-A`. PRs should describe the behavior they add or change and which unit/integration tests prove it.

## On-demand skills

| Skill | When to read | File |
|---|---|---|
| Architecture | Package model, two-axis transport, session epoch, add-on seam | `.agents/skills/architecture/SKILL.md` |
| API Patterns | Connect, credentials, Invoke, options, streaming, errors, Secret | `.agents/skills/api-patterns/SKILL.md` |
| A2A Workflow | Certificate + API-key retrieval, set, broker, retrievable accounts | `.agents/skills/a2a-workflow/SKILL.md` |
| Event Workflow | SignalR-over-WebSocket listeners, reconnect, numeric-name workaround | `.agents/skills/event-workflow/SKILL.md` |
| Testing Guide | Unit, fuzz, race, and live-appliance integration test strategy | `.agents/skills/testing-guide/SKILL.md` |
| Build and Release | Azure Pipelines, linting, semantic-import versioning, tags | `.agents/skills/build-and-release/SKILL.md` |

## Keeping this file current

When a change affects setup, linting, testing, security, versioning, pipeline behavior, or skill routing, update this file and the relevant `.agents/skills/*/SKILL.md` in the same change. Keep this file short — move deeper material into skills.
