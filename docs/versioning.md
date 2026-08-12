# Versioning and release policy

`safeguard-go` follows Go semantic-import versioning and tag-driven releases through Azure Pipelines.

## Version sequence

- `v0.x` releases are pre-release candidates while the public API stabilizes.
- `v1.0.0` is the first GA release, feature-complete against the documented Safeguard authentication, Invoke, A2A, and event flows.
- Breaking changes after `v1` require a new major module path suffix, for example `github.com/OneIdentity/safeguard-go/v2`.

## Release mechanics

Release builds are driven by Git tags (`vMAJOR.MINOR.PATCH`). Azure Pipelines validates build, format, vet, lint, and race-enabled unit tests — the hermetic checks that need no appliance. Live-appliance end-to-end tests are **not** run in CI (no appliance is reachable from the hosted agents); run them locally against a lab appliance as a pre-release check before tagging.
