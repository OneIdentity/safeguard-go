# safeguard-go

One Identity Safeguard SDK for Go.

`safeguard-go` is the standalone Go SDK for One Identity Safeguard for Privileged Passwords (SPP). It mirrors the SafeguardDotNet and PySafeguard SDKs with a Go-idiomatic API surface for authentication, Invoke-style API calls, Application-to-Application (A2A) workflows, and events.

The module is pre-1.0; the public API may change before the first `v1.0.0` release. See [docs/versioning.md](docs/versioning.md) for the versioning and release policy.

## Features

- **Authentication** — Resource Owner Grant username/password, certificate login over mutual TLS, PKCE headless (with MFA/secondary-factor support), existing user token, and anonymous access. Interactive external-browser and device-code logins ship as optional add-on packages so headless consumers keep a lean dependency graph.
- **Invoke and Service surface** — `Connect`, `Get`/`Post`/`Put`/`Delete` helpers, generic `Invoke`, typed `InvokeTyped[T]`, query parameters, headers, per-request API-version and host overrides, `Response`, and `Stream`/`Upload`/`Download` for large payloads.
- **Application-to-Application (A2A)** — password, SSH private-key, and API-key secret retrieval; password and private-key set (write-back); access-request brokering; retrievable-account discovery; and credential-change events.
- **Events** — an owned SignalR-over-WebSocket implementation with one-shot and persistent (auto-reconnecting) listeners for both user sessions and A2A credential-change streams.
- **TLS secure by default** — system trust by default, custom CA bundles, an additive server-certificate validator callback, and a loud insecure override for bootstrap/test appliances.
- **Typed errors** — API, authentication (401), authorization (403), not-found (404), transport, and sentinel errors designed for `errors.Is`/`errors.As`.
- **Secret hygiene** — the `Secret` type wraps sensitive values, redacts them from strings/logs/errors/JSON, copies on construction and exposure, and best-effort zeroes on close.

The only third-party dependency is [`github.com/coder/websocket`](https://github.com/coder/websocket) (used by the event listeners). The `browser` and `devicecode` add-ons are separate packages, so importing the root package alone stays dependency-light.

## Installation

```bash
go get github.com/OneIdentity/safeguard-go
```

The SDK requires Go 1.21 or later.

## Quick start

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
    log.Printf("GET Me -> %d\n%s\n", resp.StatusCode, resp.Body)
}
```

Recent Safeguard appliances commonly disable Resource Owner Grant (ROG). New applications should prefer PKCE, browser, device-code, certificate, or token-based flows as appropriate. `PKCEHeadless` is the recommended flow for automation because it does not depend on ROG.

To decode a JSON response into a Go value, use the generic helper:

```go
type me struct {
    UserName    string `json:"UserName"`
    DisplayName string `json:"DisplayName"`
}

info, err := safeguard.InvokeTyped[me](ctx, client, safeguard.MethodGet, safeguard.Core, "Me", nil)
if err != nil {
    log.Fatal(err)
}
log.Printf("signed in as %s (%s)", info.UserName, info.DisplayName)
```

## Samples

The [`samples`](samples) directory has a small, standalone program for each flow — every authentication method, the A2A retrieval/set/broker workflows, and the event listeners. Each sample takes its inputs as flags; run one with, for example:

```bash
go run ./samples/pkce -appliance safeguard.example.com -username Admin -insecure
```

See [samples/README.md](samples/README.md) for the full list and the shared flags.

## API version

The SDK targets Safeguard API **v4** by default for Safeguard 7.0 and later. Override it per client with `WithAPIVersion` or per request with `WithAPIVersionOverride` (for example `"v3"` for legacy compatibility); the SDK does not auto-detect the API version.

## Support

One Identity open source projects are supported through GitHub issues and the [One Identity Community](https://www.oneidentity.com/community/). Open an issue in this repository to report a bug or request a feature.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
