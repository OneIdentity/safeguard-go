---
name: testing-guide
description: Stub reference for unit, fuzz, race, and live-appliance integration test strategy.
---

# Testing Guide

This is a Phase 0 stub to be expanded before implementation tests are written. It follows `plan.md`: fast unit tests with fake HTTP/TLS/WS servers, fuzzing for the SignalR frame parser, race tests for token/session concurrency, and gated integration tests.

- Unit tests use `httptest.Server`, fake TLS/WebSocket servers, table-driven cases, and `package safeguard_test` for cross-package coverage.
- Fuzz the SignalR frame parser for coalesced records, record separators, oversized frames, and malformed input.
- Run `go test -race ./...` for refresh/logout/401/event concurrency paths.
- Integration tests use `//go:build integration`, skip when `SPP_HOST` is unset, provision/cleanup resources with bootstrap credentials, and handle ROG-disabled appliances without false failures.
