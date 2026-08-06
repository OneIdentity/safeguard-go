---
name: api-patterns
description: Stub reference for the public Connect, Invoke, Service, request option, response, and pager patterns.
---

# API Patterns

This is a Phase 0 stub to be expanded with examples once the public API lands. It tracks the Go-idiomatic surface from `plan.md`: package-level `Connect`, credential constructors, context-first client methods, functional options, and typed response envelopes.

- Credential constructors: `UsernamePassword`, `Certificate`, `PKCEHeadless`, `Token`, `Anonymous`, plus add-on `browser`/`devicecode` connectors.
- Invoke surface: `Invoke`, HTTP verbs, `InvokeTyped[T]`, `Service`, `ReqOption`, `FullResponse`, and reserved `Authorization` handling.
- Streaming/upload/download must define body ownership, cancellation behavior, and response-body closure rules.
- Pager guidance should use Go 1.21-compatible generics, not range-over-func iterators.
