---
name: architecture
description: Stub reference for package layout, public surface boundaries, and internal authentication architecture.
---

# Architecture

This is a Phase 0 stub to be expanded as implementation begins. It covers the package model from `plan.md`: a lean root `safeguard` package, thin `browser` and `devicecode` add-ons, and an `internal/auth` broker boundary that avoids public broker abstractions.

- Root package holds `Client`, credentials, Invoke/Service, A2A, events, errors, TLS, `Secret`, and pager support.
- `browser` and `devicecode` import root and `internal/auth`; `internal/auth` imports neither root nor add-ons.
- A2A and events stay in root to mirror SafeguardDotNet ergonomics and avoid import cycles.
- Document session epoch, token generation, TLS identity, and authorization axes when those types are implemented.
