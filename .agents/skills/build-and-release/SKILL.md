---
name: build-and-release
description: Stub reference for Azure Pipelines validation, release, and Go module versioning policy.
---

# Build and Release

This is a Phase 0 stub to be expanded once the pipeline is wired to project service connections. Azure Pipelines validates build, format, vet, golangci-lint, static analysis, and tests; tag builds publish releases after the SDK reaches release-candidate quality.

- CI checks: `go build ./...`, `gofmt`, `go vet ./...`, `golangci-lint run`, `go test -race ./...`, and later integration tests with protected secrets.
- Linting should keep `gofmt`, `govet`, `staticcheck`, `errcheck`, `ineffassign`, `unused`, `revive`, `gosec`, and `misspell` clean.
- Versioning follows Go semantic-import versioning: `v0.x` prereleases, `v1.0.0` GA, and `/v2` module suffix for breaking major versions.
- Releases are tag-driven; `pkg.go.dev` and the module proxy must be verified before the CSI provider pins the exact SDK `v1.0.0` tag.
