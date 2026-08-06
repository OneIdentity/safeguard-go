# AGENTS.md — safeguard-go

Go SDK for the One Identity Safeguard Web API. Module path: `github.com/OneIdentity/safeguard-go`. Root package: `safeguard`. Go floor: 1.21.

This repository is currently Phase 0: foundation/contracts only. Keep all implementation work aligned with `plan.md`; do not invent public API outside that plan without a maintainer decision.

## Project structure

```text
.                                  # package safeguard (root SDK package)
├── browser/                       # planned external-browser PKCE add-on package
├── devicecode/                    # planned device-code add-on package
├── internal/auth/                 # planned broker and login flow state machines
├── internal/                      # planned transport, URL, and protocol helpers
├── examples/                      # planned runnable examples
├── cmd/sg/                        # planned sample CLI
├── docs/parity-matrix.md          # GA parity checklist
├── pipeline-templates/            # Azure Pipelines reusable jobs/steps
└── .agents/skills/                # deeper agent workflow references
```

In Phase 0, most planned directories intentionally do not exist yet. The only Go file is `doc.go`, which keeps `go build ./...` valid until implementation begins.

## Setup, build, lint, and test

| Purpose | Command |
|---|---|
| Build all packages | `go build ./...` |
| Unit tests | `go test ./...` |
| Race-enabled unit tests | `go test -race ./...` |
| Vet | `go vet ./...` |
| Format check | `gofmt -w` for edits; CI checks `gofmt -l .` is empty |
| Lint | `golangci-lint run` |
| Integration tests | `go test -tags=integration ./...` with `SPP_HOST` and related secrets set |

Integration tests must use `//go:build integration` and auto-skip when `SPP_HOST` is unset. The future harness provisions and cleans up its own Safeguard resources from bootstrap/admin credentials, including the ROG-disabled workaround described in `plan.md`.

## Coding conventions

- Keep public I/O APIs context-first: `func (c *Client) Get(ctx context.Context, ...)`.
- Use functional options for optional connection and request behavior.
- Keep constructors side-effect-free; validate networked and certificate-dependent state at `Connect` time.
- Preserve the planned `Connect` + credential constructor model: `UsernamePassword`, `Certificate`, `PKCEHeadless`, `Token`, `Anonymous`, plus browser/devicecode add-ons.
- Keep A2A and events in the root package; keep broker internals under `internal/auth`.
- Model errors as typed Go errors that work with `errors.Is` and `errors.As`.
- Protect secrets with the planned `Secret` type. Never log, stringify, serialize, or commit credentials, tokens, certificate private keys, API keys, or retrieved passwords.
- TLS must be secure by default. `WithInsecureTLS` is only for bootstrap/dev/test and must be loud in docs and tests.
- Do not add dependencies casually. The Phase 4 WebSocket dependency is `github.com/coder/websocket`, but it must not be added to `go.mod` until event implementation needs it.

## CI/CD

Azure Pipelines is the CI system. PR validation runs build, `gofmt`, `go vet`, `golangci-lint`, and race-enabled unit tests. Merge/tag validation may run live-appliance integration tests with pipeline secrets that are never exposed to fork PRs, logs, or artifacts.

See `.agents/skills/build-and-release/SKILL.md` for release and versioning notes.

## Commit and PR workflow

The maintainer reviews and approves every commit message before commits are created. Do not commit without explicit instruction. PRs should describe which parity-matrix rows they advance and which unit/integration tests prove the behavior.

## On-demand skills

| Skill | When to read | File |
|---|---|---|
| Architecture | Package model, auth broker boundaries, A2A/events placement | `.agents/skills/architecture/SKILL.md` |
| API Patterns | Connect, Invoke, Service, request options, streaming, pager | `.agents/skills/api-patterns/SKILL.md` |
| A2A Workflow | Certificate-based A2A retrieval, set, broker, cert-user login | `.agents/skills/a2a-workflow/SKILL.md` |
| Event Workflow | SignalR-over-WebSocket listeners, reconnect, event auth | `.agents/skills/event-workflow/SKILL.md` |
| Testing Guide | Unit, fuzz, race, and live-appliance integration test strategy | `.agents/skills/testing-guide/SKILL.md` |
| Build and Release | Azure Pipelines, linting, semantic-import versioning, tags | `.agents/skills/build-and-release/SKILL.md` |

Keep this file short. Move deeper workflow/reference material into skills and update this table when skills change.
