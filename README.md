# safeguard-go

One Identity Safeguard SDK for Go.

`safeguard-go` is the planned standalone Go SDK for One Identity Safeguard for Privileged Passwords (SPP). It mirrors the SafeguardDotNet and PySafeguard SDKs with a Go-idiomatic API surface for authentication, Invoke-style API calls, Application-to-Application (A2A) workflows, and events.

## Status

This repository is in **Phase 0: foundation/contracts only**. The module is pre-1.0 and private during development; no functional SDK implementation is present yet. Public APIs shown below are the target API from `plan.md` and may change before the first `v1.0.0` release candidate.

## Features

Planned GA parity includes:

- Authentication flows: Resource Owner Grant username/password, certificate login, PKCE headless with MFA/secondary support, external browser login, device code login, existing user token, anonymous access, and provider name-to-ID lookup.
- Invoke and Service surface: `Connect`, HTTP verb helpers, generic `Invoke`, `InvokeTyped[T]`, query parameters, headers, API-version override, host override, `FullResponse`, streaming, upload, download, and JSON/CSV/binary/empty responses.
- Application-to-Application (A2A): password retrieval, private-key retrieval, API-key secret retrieval, credential set operations, access-request brokering, retrievable-account discovery with certificate user login, and credential-change events.
- Events: owned SignalR-over-WebSocket implementation with one-shot and persistent listeners, reconnect/backoff, subscription restoration, and A2A client-certificate event authentication.
- TLS secure by default: system trust by default, custom CA bundles, additive server-certificate validator callback, and a loud insecure override for bootstrap/test appliances.
- Typed errors: API, authentication, authorization, not-found, transport, and sentinel errors designed for `errors.Is`/`errors.As`.
- Secret hygiene: secret values are wrapped, redacted from strings/logs/errors, copied on construction/exposure, and best-effort zeroed on close.

## Installation

After the SDK is published:

```bash
go get github.com/OneIdentity/safeguard-go
```

## Target API example

> **Note**  
> This is aspirational Phase 1+ API shape from `plan.md`; Phase 0 contains only package documentation.

```go
package main

import (
    "context"
    "log"

    "github.com/OneIdentity/safeguard-go"
)

func main() {
    ctx := context.Background()

    cred := safeguard.UsernamePassword(
        "local",
        "Admin",
        safeguard.NewSecretString("correct horse battery staple"),
    )

    client, err := safeguard.Connect(ctx, "safeguard.sample.corp", cred)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Get(ctx, safeguard.Core, "Me")
    if err != nil {
        log.Fatal(err)
    }
    _ = resp // FullResponse from the target API.

    log.Println("GET Me completed")
}
```

Recent Safeguard appliances commonly disable Resource Owner Grant (ROG). New applications should prefer PKCE, browser, device-code, certificate, or token-based flows as appropriate.

## API version

The SDK targets Safeguard API **v4** by default for Safeguard 7.0 and later. A v3 override will be available for legacy compatibility; the SDK will not auto-detect the API version.

## Support

One Identity open source projects are supported through GitHub issues and the One Identity Community. During private development, use the repository's internal review process described in `AGENTS.md`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
