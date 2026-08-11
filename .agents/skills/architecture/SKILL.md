---
name: architecture
description: >-
  Use when reasoning about package layout, the public surface boundary, the
  two-axis transport model (TLS identity vs. authorization), session epochs,
  the add-on login seam, or the internal/auth broker boundary. Explains why the
  SDK is shaped the way it is.
---

# Architecture

Module `github.com/OneIdentity/safeguard-go`; root package `safeguard`; Go floor
1.21. The design goal is SafeguardDotNet/PySafeguard parity with idiomatic Go
ergonomics and a lean dependency graph for headless consumers.

## Package layout

```text
.                       # package safeguard: the whole public surface
├── browser/            # add-on: interactive system-browser (loopback) login
├── devicecode/         # add-on: OAuth device authorization grant login
├── internal/auth/      # login state machines (PKCE, password, cert, device, broker)
├── internal/livetest/  # ephemeral live-appliance provisioning for tests
├── samples/            # one standalone package main per flow
└── pipeline-templates/ # Azure Pipelines reusable jobs/steps
```

The **root package holds everything public**: `Client`, the credential
constructors, the Invoke/Service surface, A2A (`A2AContext`), events
(`EventListener`/`PersistentEventListener`), typed errors, TLS options,
`Secret`, and streaming. Keeping A2A and events in root mirrors SafeguardDotNet
ergonomics and avoids import cycles.

### Import direction (one-way)

```text
browser ─┐
         ├─► safeguard (root) ─► internal/auth
devicecode ┘
```

- `browser` and `devicecode` import root **and** `internal/auth`.
- `internal/auth` imports **neither** root nor the add-ons — it is a
  self-contained set of login state machines.
- Root does **not** import the add-ons. This is what lets a headless consumer
  depend on root without compiling in browser-launching / loopback-listener
  machinery.

## The add-on seam: `AuthorizedSession` + `LoginFunc`

`Credential` is a **sealed** interface (its only method is unexported), so
callers — including the add-ons — cannot implement their own credential. The
add-ons plug in through one exported seam:

```go
func AuthorizedSession(login LoginFunc) Credential
type LoginFunc func(ctx context.Context, t LoginTransport) (userToken Secret, err error)
```

An add-on supplies its interactive flow as a `LoginFunc`; `AuthorizedSession`
adopts the resulting user token. `LoginTransport` hands the flow the client's
already-configured server-trust transport plus the appliance coordinates
(`Host()`, `APIVersion()`, `Do(req)`), and its `Do` satisfies the internal
broker's transport interface — so an add-on passes the `LoginTransport` straight
into `internal/auth` helpers without building its own transport. Sessions from
this seam are intentionally **not refreshable** (existing-token model).

## Two-axis transport model

The single most important internal concept. A request has **two independent
axes**, and connection pools are keyed by the TLS identity, **never** by the
authorization mode:

1. **TLS identity** (`tlsIdentity`) — which client transport/pool is used:
   - `serverTrust`: presents no client certificate, verifies the server. Used
     for all standard calls.
   - `clientCert`: presents a client certificate (certificate login, A2A).
2. **Authorization** (`authKind`) — what `Authorization` header rides the
   request:
   - `authNone`: no header (anonymous/notification, RSTS, login).
   - `authUserToken`: a Safeguard user token (Bearer).
   - `authA2A`: an A2A API key (`Authorization: A2A <key>`).

Choosing these independently is what lets **A2A pair a client certificate with
either an API key or a user token**. Because the axes are separate, the
`Authorization` header is owned exclusively by the transport — a caller-supplied
`Authorization` request header is always rejected (`ErrReservedHeader`), never
honored. `Service` selects only the base URL path; it never implies
authorization.

Consequences worth remembering:
- The `clientCert` transport disables the automatic HTTP/2 upgrade and the RSTS
  endpoint rejects client-certificate presentation, so cert material is scoped
  carefully per axis.
- Installing/rotating client certs drops and rebuilds only the `clientCert`
  pools, never the `serverTrust` pool.

## Session epoch

A `Client` is concurrency-safe: token state is immutable and swapped
atomically, and transport pools are internally synchronized. A monotonic
**session epoch** guards the token swap so an in-flight refresh cannot resurrect
a session that was closed or replaced:

- `Close` installs a *terminal* epoch (0 never matches) and zeroes the displaced
  token; `doRefresh` publishes only on the epoch it observed, so a concurrent
  refresh landing after `Close`/`Logout` is discarded.
- There is **no in-place reconnect**. Reconnecting means calling `Connect`
  again for a new client with a new epoch.
- A persistent event listener bound to a user session stops permanently once
  that session is logged out or replaced (a different identity), rather than
  reconnecting under the wrong identity.

## TLS trust model

Secure by default. Trust is configured through connection `Option`s:
`WithCABundle` (add an internal CA), `WithServerCertValidator` (additive, can
only further restrict — parity with .NET's callback), and `WithInsecureTLS`
(bootstrap/dev/test only; disables verification on every transport including the
event WebSocket; cannot combine with a validator). `WithInsecureTLS` is
deliberately loud in docs and tests.

## Secret boundary

`Secret` is the single type for passwords, tokens, API keys, and retrieved
credentials. It redacts across `fmt`, JSON/text marshaling, and `slog`, and adds
copy-on-`Expose`, constant-time `Equal`, and best-effort `Zero`. It is an
anti-accidental-disclosure tool, **not** memory-hardening — document that limit
wherever a `Secret` crosses the public surface. Errors follow suit:
`APIError.Error()` never includes the raw response body (which may carry a
returned credential); `RawBody()` is the explicit, bounded escape hatch.

## Where new work goes

- New credential flow that mints a user token → root credential constructor,
  with the login state machine in `internal/auth` if it is non-trivial.
- New interactive login that needs heavy/optional deps → a new add-on package
  using the `AuthorizedSession`/`LoginFunc` seam.
- New API convenience → root, on `Client`, context-first with `ReqOption`s.
- Do not introduce public broker abstractions or a second public package for
  A2A/events — they stay in root by design.
