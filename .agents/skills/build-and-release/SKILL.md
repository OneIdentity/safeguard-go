---
name: build-and-release
description: >-
  Use when running or changing CI, linting, module/dependency policy, the
  Azure Pipelines templates, or release/versioning. Covers the exact local and
  pipeline commands, the golangci-lint configuration, semantic-import
  versioning, and integration-test secret handling.
---

# Build and Release

Azure Pipelines is the CI system. The reusable templates live in
`pipeline-templates/`. Go floor is **1.21** (`go.mod`), and the only third-party
dependency is `github.com/coder/websocket` (added for events — do not add
dependencies casually).

## Local commands

| Purpose | Command |
|---|---|
| Build | `go build ./...` |
| Unit tests | `go test ./...` |
| Race tests | `go test -race ./...` (needs cgo/gcc; CI runs it on Linux) |
| Vet | `go vet ./...` |
| Format (fix) | `gofmt -w <files>` |
| Format (check) | `gofmt -l .` must print nothing |
| Lint | `golangci-lint run` |
| Integration | `go test -tags=integration ./...` with `SPP_HOST` etc. set |

**Windows gotcha:** files often land with CRLF; `gofmt -l` flags them. Normalize
to LF before committing (e.g. read the file, replace `\r\n` with `\n`, write it
back).

## Pipeline templates

- **`go-setup-steps.yml`** — checkout + `GoTool@0` pinned to `$(GoVersion)`
  (`1.21.x` in `global-variables.yml`), then prints the Go environment.
- **`go-ci-job.yml`** (PR validation, `ubuntu-latest`) runs, in order:
  `go build ./...` → `gofmt -l .` gate (fails if any file listed) → `go vet
  ./...` → install `golangci-lint` **v1.64.8** and `golangci-lint run` →
  `go test -race ./...`.
- **`go-integration-job.yml`** — runs `go test -race -tags=integration ./...`
  only when `SPP_HOST` is set; otherwise it skips cleanly. Secrets
  (`SPP_HOST`, `SPP_BOOTSTRAP_USER`, `SPP_BOOTSTRAP_PASSWORD`, `SPP_CA_BUNDLE`,
  and future `SPP_A2A_*`) come from protected variable groups / Key Vault.
- **`global-variables.yml`** — `GoVersion=1.21.x`; `isTagBuild` is true when the
  build source branch starts with `refs/tags/`.

Keep the local commands and the pipeline steps in lockstep: if you add a check
locally, add it to `go-ci-job.yml`, and vice versa.

## Lint configuration (`.golangci.yml`)

Enabled linters must all stay clean: **gofmt, govet, staticcheck, errcheck,
ineffassign, unused, revive, gosec, misspell**. Two that bite most often:

- **revive** requires a package/command doc comment. Every `package main` in
  `samples/` opens with a `// Command <name> ...` comment; library files carry a
  package doc.
- **gosec** flags reading a file from a variable path (**G304**). The repo
  convention is a `// #nosec G304 -- <reason>` comment on the line **before**
  `os.ReadFile`. Insecure TLS in test/bootstrap paths uses `// #nosec G402 --
  <reason>`.

Every `.go` file also carries the 13-line Apache 2.0 license header.

## Module and dependency policy

- Keep the module floor at **Go 1.21**. Do not use range-over-func iterators or
  other post-1.21 language features; generic helpers (e.g. `InvokeTyped`,
  pagers) must compile under 1.21.
- Add a dependency only when a feature genuinely needs it. `coder/websocket`
  was added for events; nothing else should join `go.mod` without a maintainer
  decision.

## Versioning and release

- Follows Go **semantic-import versioning**: `v0.x` prereleases while the SDK is
  pre-GA, `v1.0.0` at GA, and a `/v2` module path suffix for a breaking major.
- Releases are **tag-driven** (`isTagBuild` gates release/integration stages).
  After tagging, verify the version is live on `pkg.go.dev` and the module proxy
  before any downstream (e.g. a CSI provider) pins the exact tag.
- Merge/tag validation may run the live-appliance integration tests with
  pipeline secrets; those secrets are **never** exposed to fork PRs, logs, or
  artifacts.

## Commit / PR conventions

The maintainer approves every commit message **before** the commit is created —
do not commit without explicit instruction. Stage specific files (`git add
<paths>`), never `-A`. Messages use a plain imperative subject (no
conventional-commit prefix). A PR should state the behavior it changes and which
unit/integration tests prove it.
