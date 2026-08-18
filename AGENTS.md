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
| Live tests (local) | `go test ./...` with `SPP_HOST` and related env vars set |

Live-appliance tests live in-package alongside unit tests and **skip** (never fail) when `SPP_HOST` is unset, so `go test ./...` stays hermetic by default. The `internal/livetest` harness provisions and cleans up its own Safeguard resources from bootstrap/admin credentials. The reference appliance has the Resource Owner Grant disabled, so PKCE-headless is the primary automation login. **Live e2e against a running appliance is the standard of proof** — see the `testing-guide` skill.

**Running the live tests locally is a recommended part of validating a code change**, not just a pre-release step. Whenever a change touches an auth flow, the transport/refresh/token lifecycle, A2A, or events, run the live suite against a lab appliance (for example `SPP_HOST=spp1.dan.laptop SPP_INSECURE=1 go test ./...`) and confirm it is green before considering the change done. Agents working in this repo should proactively recommend — and, when an appliance is reachable, run — the live tests as part of that validation. CI cannot do this (no appliance is reachable from the hosted agents), so this responsibility lives with the developer and the agent, not the pipeline.

## Coding conventions

- Keep public I/O APIs context-first: `func (c *Client) Get(ctx context.Context, ...)`.
- Use functional options for optional connection and request behavior (`Option`, `ReqOption`, `CertOption`, `A2AOption`, `PKCEOption`).
- Keep constructors side-effect-free; validate networked and certificate-dependent state at `Connect` time.
- Preserve the `Connect` + credential constructor model: `UsernamePassword`, `Certificate`, `PKCEHeadless`, `Token`, `Anonymous`, plus the browser/devicecode add-ons via the sealed `AuthorizedSession` seam.
- Keep A2A and events in the root package; keep login/broker internals under `internal/auth`.
- Model errors as typed Go errors that work with `errors.Is`/`errors.As` (`APIError` and its 401/403/404 specializations, `TransportError`, sentinel `Err*` values).
- Protect secrets with the `Secret` type. Never log, stringify, serialize, or commit credentials, tokens, certificate private keys, API keys, or retrieved passwords. `APIError.Error()` never includes the raw response body.
- TLS is secure by default. `WithInsecureTLS` is only for bootstrap/dev/test and must stay loud in docs and tests.
- TLS version is a `uint16` passthrough to `crypto/tls` via `WithMinTLSVersion`/`WithMaxTLSVersion` (future-proof, no enum to age). The default is hybrid per-transport: TLS 1.2 floor everywhere, `serverTrust` open to 1.3, but the `clientCert` transport (certificate login, A2A) is **capped at 1.2** so post-handshake cert-auth keeps working on the 9.0 Standard binding (Go has no TLS 1.3 post-handshake client auth). Setting either option lifts the cap for TLS 1.3 cert-auth against the appliance Cert SNI hostname. See the api-patterns/architecture/a2a-workflow skills.
- Stay Go 1.21-compatible (no range-over-func iterators). Do not add dependencies casually.

## CI/CD

Azure Pipelines is the CI system. PR/CI validation runs `go build`, the `gofmt -l` gate, `go vet`, `golangci-lint`, and race-enabled unit tests. It is fully hermetic: the live-appliance tests skip when `SPP_HOST` is unset, so they never run in CI (no appliance is reachable from the hosted agents). Run the live tests locally against a lab appliance as a pre-release check. See the `build-and-release` skill for pipeline, versioning, and release details.

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
