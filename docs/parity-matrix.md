# safeguard-go parity matrix

This living checklist tracks GA parity with SafeguardDotNet and PySafeguard. Every `safeguard-go` capability must be implemented, unit-tested, and integration-tested where it touches a live appliance before `v1.0.0`.

## Auth flows

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| Resource Owner Grant username/password | Yes | Yes | ☐ Not started | TBD |
| Certificate authentication | Yes | Yes | ☐ Not started | TBD |
| PKCE headless authentication | Add-on package | Yes | ☐ Not started | TBD |
| PKCE MFA/secondary handling | Add-on package | Planned/partial | ☐ Not started | TBD |
| External browser login | Add-on package | Planned | ☐ Not started | TBD |
| Device code login | Add-on package | Planned | ☐ Not started | TBD |
| Existing user token | Yes | Yes | ☐ Not started | TBD |
| Anonymous access | Yes | Yes | ☐ Not started | TBD |
| Provider name-to-ID lookup | Yes | Yes | ☐ Not started | TBD |

## Connection lifecycle

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| `Connect` | Yes | Yes | ☐ Not started | TBD |
| `Logout` with re-connectable lifecycle | Yes | Yes | ☐ Not started | TBD |
| `Close` terminal lifecycle | Yes | Yes | ☐ Not started | TBD |
| Connect via existing token | Yes | Yes | ☐ Not started | TBD |
| Token lifetime remaining | Yes | Yes | ☐ Not started | TBD |
| Proactive auto-refresh with threshold and jitter | Yes | Yes | ☐ Not started | TBD |
| Explicit refresh | Yes | Yes | ☐ Not started | TBD |
| Per-request host override | Yes | Yes | ☐ Not started | TBD |

## Invoke and Service

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| `Service` values including Management | Yes | Yes | ☐ Not started | TBD |
| HTTP verb helpers | Yes | Yes | ☐ Not started | TBD |
| Generic `Invoke` | Yes | Yes | ☐ Not started | TBD |
| `InvokeTyped[T]` | N/A (typed language patterns differ) | N/A (typed language patterns differ) | ☐ Not started | TBD |
| Query parameters | Yes | Yes | ☐ Not started | TBD |
| Request headers | Yes | Yes | ☐ Not started | TBD |
| API-version override | Yes | Yes | ☐ Not started | TBD |
| Host override | Yes | Yes | ☐ Not started | TBD |
| Context timeouts | Yes | Yes | ☐ Not started | TBD |
| `FullResponse` envelope | Yes | Yes | ☐ Not started | TBD |
| Streaming responses | Yes | Yes | ☐ Not started | TBD |
| Upload | Yes | Yes | ☐ Not started | TBD |
| Download | Yes | Yes | ☐ Not started | TBD |
| JSON bodies | Yes | Yes | ☐ Not started | TBD |
| CSV bodies | Yes | Yes | ☐ Not started | TBD |
| Binary bodies | Yes | Yes | ☐ Not started | TBD |
| Empty bodies | Yes | Yes | ☐ Not started | TBD |
| Management service | Yes | Yes | ☐ Not started | TBD |

## A2A

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| Retrieve password | Yes | Yes | ☐ Not started | TBD |
| Retrieve private key with `SshKeyFormat` | Yes | Yes | ☐ Not started | TBD |
| Retrieve API-key secret | Yes | Yes | ☐ Not started | TBD |
| Set password | Yes | Yes | ☐ Not started | TBD |
| Set private key | Yes | Yes | ☐ Not started | TBD |
| Broker access request | Yes | Yes | ☐ Not started | TBD |
| Get retrievable accounts with certificate user login | Yes | Yes | ☐ Not started | TBD |
| A2A credential-change events | Yes | Yes | ☐ Not started | TBD |

## Events

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| Owned SignalR-over-WebSocket implementation | SignalR client dependency | SignalR client dependency | ☐ Not started | TBD |
| One-shot event listeners | Yes | Yes | ☐ Not started | TBD |
| Persistent event listeners | Yes | Yes | ☐ Not started | TBD |
| Reconnect, renewal, and backoff | Yes | Yes | ☐ Not started | TBD |
| Subscription restoration | Yes | Yes | ☐ Not started | TBD |
| Numeric event-name workaround | Yes | Yes | ☐ Not started | TBD |
| A2A event auth via client certificate | Yes | Yes | ☐ Not started | TBD |

## Cross-cutting

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| Typed errors | Yes | Yes | ☐ Not started | TBD |
| `Secret` hygiene and redaction | SecureString | HiddenString | ☐ Not started | TBD |
| TLS default verification | Yes | Yes | ☐ Not started | TBD |
| Custom CA bundle | Yes | Yes | ☐ Not started | TBD |
| Additive server-certificate validator callback | Yes | Partial | ☐ Not started | TBD |
| Insecure TLS disable override | Yes | Yes | ☐ Not started | TBD |
| Idempotency-aware retry | Yes | Yes | ☐ Not started | TBD |
| `Retry-After` handling | Yes | Yes | ☐ Not started | TBD |
| Granular dial/TLS/response-header timeouts | Yes | Yes | ☐ Not started | TBD |
| Optional `slog` logger | Serilog | Python logging | ☐ Not started | TBD |
