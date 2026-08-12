# Versioning and release policy

`safeguard-go` follows Go semantic-import versioning and tag-driven releases through Azure Pipelines.

## Version sequence

- `v0.x` releases are pre-release candidates while the SDK is private or API-incomplete.
- `v1.0.0` is the first GA release, feature-complete against the documented Safeguard authentication, Invoke, A2A, and event flows.
- Breaking changes after `v1` require a new major module path suffix, for example `github.com/OneIdentity/safeguard-go/v2`.

## Release mechanics

Release builds are driven by Git tags (`vMAJOR.MINOR.PATCH`). Azure Pipelines validates build, format, vet, lint, unit tests, and protected live-appliance integration tests before publishing release artifacts. The exact publishing steps are TODO until the project service connections and release policy are finalized.

## SDK before CSI

The SDK ships before the CSI provider rework. The sequence is:

1. Develop the SDK privately and cut `v0.x` release candidates.
2. Publish SDK `v1.0.0` and verify the Go module proxy and `pkg.go.dev`.
3. Build and ship the CSI provider against the exact immutable SDK `v1.0.0` tag.

The CSI provider must not ship with pseudo-versions or `replace` directives; it pins the exact SDK `v1.0.0` tag.
