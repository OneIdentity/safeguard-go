---
name: testing-guide
description: Reference for unit, fuzz, race, and live-appliance integration test strategy.
---

# Testing Guide

The test strategy is: fast unit tests with fake HTTP/TLS/WS servers, fuzzing for the SignalR frame parser, race tests for token/session concurrency, and gated integration tests.

## Live appliance end-to-end is the standard

Live-appliance e2e is the authoritative proof that a feature works. Fake-server unit tests are a required fast supplement for logic, edge cases, and error mapping, but every auth flow and connection-lifecycle behavior must also be proven against a running Safeguard before it is considered done.

- Live tests live in-package alongside unit tests and **skip** (never fail) when `SPP_HOST` is unset, so `go test ./...` stays hermetic by default.
- The reference appliance is `spp1.dan.laptop` (192.168.99.15) with bootstrap `Admin`/`Admin123`. It has **Resource Owner Grant disabled**, so PKCE-headless is the primary automation login; password-login live tests must detect the ROG-disabled response (`grant type is not allowed`) and skip rather than fail.
- Live tests pin the appliance leaf certificate by default and honor `SPP_INSECURE` / `SPP_CA_BUNDLE` for bootstrap trust.

## Unit, fuzz, race

- Unit tests use `httptest.Server`, fake TLS/WebSocket servers, table-driven cases, and `package safeguard_test` for cross-package coverage.
- Fuzz the SignalR frame parser for coalesced records, record separators, oversized frames, and malformed input.
- Run `go test -race ./...` for refresh/logout/401/event concurrency paths.
- Live tests skip when `SPP_HOST` is unset, provision/cleanup resources with bootstrap credentials, and handle ROG-disabled appliances without false failures.

## CI vs. local

CI runs only hermetic checks (build, format, vet, lint, race-enabled unit tests); it never runs the live tests because no appliance is reachable from the hosted agents. Running the live suite is therefore a **local developer responsibility** and a recommended part of validating any change to an auth flow, the transport/refresh/token lifecycle, A2A, or events — run `go test ./...` with `SPP_HOST` set against a lab appliance and confirm it is green before considering the change done.
