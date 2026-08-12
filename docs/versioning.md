# Versioning and release policy

`safeguard-go` follows Go semantic-import versioning and tag-driven releases through Azure Pipelines.

## Version sequence

- `v0.x` releases are pre-release candidates while the public API stabilizes.
- `v1.0.0` is the first GA release, feature-complete against the documented Safeguard authentication, Invoke, A2A, and event flows.
- Breaking changes after `v1` require a new major module path suffix, for example `github.com/OneIdentity/safeguard-go/v2`.

## Release mechanics

Release builds are driven by Git tags (`vMAJOR.MINOR.PATCH`). Azure Pipelines validates build, format, vet, lint, unit tests, and live-appliance integration tests before a release is published.
