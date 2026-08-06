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
| Anonymous access | Yes | Yes | ✔ Done | `TestLiveNotificationStatus`, `TestLiveApplianceSystemTime` (live anonymous calls) |
| Provider name-to-ID lookup | Yes | Yes | ☐ Not started | TBD |

## Connection lifecycle

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| `Connect` | Yes | Yes | ☐ Not started | TBD |
| `Logout` with re-connectable lifecycle | Yes | Yes | ☐ Not started | TBD |
| `Close` terminal lifecycle | Yes | Yes | ✔ Done | `TestCloseZeroesTokenAndPreventsUse` |
| Connect via existing token | Yes | Yes | ☐ Not started | TBD |
| Token lifetime remaining | Yes | Yes | ◐ Partial (cached expiry; appliance lifetime endpoint in Phase 2) | `TestTokenLifetimeRemaining` |
| Proactive auto-refresh with threshold and jitter | Yes | Yes | ☐ Not started | TBD |
| Explicit refresh | Yes | Yes | ☐ Not started | TBD |
| Per-request host override | Yes | Yes | ✔ Done | `TestLiveHostOverride` |

## Invoke and Service

| Capability | SafeguardDotNet | PySafeguard | safeguard-go status | Test that proves it |
|---|---|---|---|---|
| `Service` values including Management | Yes | Yes | ✔ Done | `TestServiceBaseURL` (routing incl. RSTS no-version) |
| HTTP verb helpers | Yes | Yes | ✔ Done | `TestVerbHelpersHitMethodAndPath` |
| Generic `Invoke` | Yes | Yes | ✔ Done | `TestLiveNotificationStatus`, `TestInvokeErrorMapping` |
| `InvokeTyped[T]` | N/A (typed language patterns differ) | N/A (typed language patterns differ) | ✔ Done | `TestInvokeTypedDecodesJSON`, `TestLiveNotificationStatus` |
| Query parameters | Yes | Yes | ✔ Done | `TestInvokeQueryAndAPIVersionOverride` |
| Request headers | Yes | Yes | ✔ Done | `TestBuildHTTPRequest`, `TestInvokeContentType` |
| API-version override | Yes | Yes | ✔ Done | `TestInvokeQueryAndAPIVersionOverride` |
| Host override | Yes | Yes | ✔ Done | `TestLiveHostOverride` |
| Context timeouts | Yes | Yes | ✔ Done | live tests run under `context.WithTimeout` |
| `FullResponse` envelope | Yes | Yes | ✔ Done | `TestLiveNotificationStatus`, `TestVerbHelpersHitMethodAndPath` |
| Streaming responses | Yes | Yes | ✔ Done | `TestStream*` (stream_test.go) |
| Upload | Yes | Yes | ◐ Mechanics (local httptest); live proof with auth in Phase 2 | `TestUploadPostsOctetStream` |
| Download | Yes | Yes | ✔ Done | `TestLiveDownloadStatus`, `TestDownload*` |
| JSON bodies | Yes | Yes | ✔ Done | `TestEncodeBody`, `TestLiveLoginResponseTypedError` |
| CSV bodies | Yes | Yes | ◐ Mechanics (Accept/Content-Type override); live report proof in Phase 2 | `TestInvokeContentType` |
| Binary bodies | Yes | Yes | ✔ Done | `TestEncodeBody` (bytes/reader) |
| Empty bodies | Yes | Yes | ✔ Done | `TestEncodeBody` (nil/empty) |
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
| Typed errors | Yes | Yes | ✔ Done | `TestNewAPIErrorStatusSpecializations`, `TestLiveCoreVersionNotFound`, `TestLiveLoginResponseTypedError` |
| `Secret` hygiene and redaction | SecureString | HiddenString | ✔ Done | `TestSecretRedaction`, `TestSecretCopiesInputAndExposeReturnsCopy` |
| TLS default verification | Yes | Yes | ✔ Done | `TestLiveTLSModes/default_system_trust_fails` |
| Custom CA bundle | Yes | Yes | ✔ Done | `TestLiveTLSModes/ca_bundle`, `TestBuildTLSConfigCABundle` |
| Additive server-certificate validator callback | Yes | Partial | ✔ Done | `TestLiveTLSModes/validator_rejects`, `TestLiveTLSModes/validator_accepts` |
| Insecure TLS disable override | Yes | Yes | ✔ Done | `TestLiveTLSModes/insecure`, `TestBuildTLSConfigInsecure` |
| Idempotency-aware retry | Yes | Yes | ☐ Not started | TBD |
| `Retry-After` handling | Yes | Yes | ☐ Not started | TBD |
| Granular dial/TLS/response-header timeouts | Yes | Yes | ✔ Done | `TestTimeoutsOrDefaultAndWithHTTPTimeouts` |
| Optional `slog` logger | Serilog | Python logging | ✔ Done | `TestSecretRedaction` (slog redaction), `WithLogger` |
