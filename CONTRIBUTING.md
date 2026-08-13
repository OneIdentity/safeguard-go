# Contributing to safeguard-go

Thanks for your interest in improving safeguard-go, the Go SDK for the
One Identity Safeguard for Privileged Passwords Web API.

## Reporting issues

- **Bugs and feature requests:** open a GitHub Issue.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Prerequisites

- [Go 1.21](https://go.dev/dl/) or later.
- (Optional) access to a Safeguard for Privileged Passwords appliance to
  run the live integration tests.

## Building

    go build ./...

## Testing

Unit tests are hermetic and require no appliance:

    go test ./...
    go test -race ./...
    go vet ./...

Live-appliance integration tests live alongside the unit tests and
**skip** automatically when `SPP_HOST` is unset. To run them against a
lab appliance:

    SPP_HOST=spp.example.com SPP_INSECURE=1 go test ./...

`WithInsecureTLS` / `SPP_INSECURE` is for bootstrap, dev, and test only.

## Coding conventions

- Keep public I/O APIs context-first; use functional options for optional
  behavior.
- Format with `gofmt` (CI enforces `gofmt -l .` is empty); lint with
  `golangci-lint run`.
- Stay Go 1.21-compatible and avoid adding dependencies casually.

See [AGENTS.md](AGENTS.md) for the full architecture and conventions.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Keep commits focused with clear messages.
3. Ensure `go build ./...`, `go vet ./...`, `golangci-lint run`, and
   `go test -race ./...` pass.
4. Open a pull request describing the behavior you changed and the tests
   that prove it.
