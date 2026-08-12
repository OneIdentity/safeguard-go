# safeguard-go samples

Small, standalone programs that each demonstrate one Safeguard flow with the
`safeguard-go` SDK. They mirror the per-flow examples shipped by PySafeguard and
SafeguardDotNet. Every sample is its own `package main`, so run one with:

```bash
go run ./samples/pkce -appliance safeguard.example.com -username Admin -password "..." -insecure
```

## Configuration

Every sample takes its inputs as flags. The common ones are:

| Flag | Meaning |
|---|---|
| `-appliance` | Appliance host name or IP (required) |
| `-ca` | Path to the appliance's trusted CA bundle (PEM). Omit to use the system trust store. |
| `-insecure` | Skip TLS verification. **Dev/test only** — never use against production. |

Flow-specific flags (run any sample with `-h` for its full set) include
`-username`/`-password`, `-provider`, `-cert`/`-key`/`-cert-password`, `-token`,
`-apikey`, and `-broker-apikey`.

Against a self-signed lab appliance you can trust its CA with `-ca`, or bypass
verification entirely with `-insecure` while you get set up.

> **Secrets:** these samples take credentials as flags to stay simple and
> runnable. That is fine for a demo, but flags are visible in your shell history
> and process list — a real application should source secrets from wherever suits
> its deployment (environment, a secrets manager, a config file) rather than the
> command line.

## Samples

| Directory | Flow |
|---|---|
| `password` | Resource Owner Grant (username/password) login |
| `pkce` | PKCE headless login (recommended for automation) |
| `certificate` | Client-certificate login over mutual TLS |
| `token` | Reuse an existing Safeguard user token |
| `anonymous` | Anonymous session against the Notification service |
| `browser` | Interactive external-browser login (`browser` add-on) |
| `devicecode` | Device authorization grant (`devicecode` add-on) |
| `invoke` | Generic request with any method against any service |
| `invoke-typed` | Typed request that decodes JSON into a Go struct |
| `download` | Stream a response body straight to a file |
| `a2a-password` | A2A password retrieval |
| `a2a-privatekey` | A2A SSH private-key retrieval |
| `a2a-apikey` | A2A API-key retrieval |
| `a2a-discover` | List the accounts a certificate can retrieve |
| `a2a-set-password` | A2A password write-back |
| `a2a-broker` | Broker an access request on behalf of another user |
| `events` | One-shot SignalR event listener |
| `events-persistent` | Reconnecting SignalR event listener |
| `a2a-events` | A2A credential-change event listener |

## A note on retrieved credentials

The A2A samples print retrieved credentials to stdout so you can see the flow
work. Do not do that in real applications: keep values in `safeguard.Secret`,
which redacts itself from logs, strings, and errors, and expose the bytes only
where you must.
