---
name: api-patterns
description: >-
  Use when connecting a Client, making Safeguard API calls via the Invoke
  surface, choosing a credential, working with request options, streaming,
  error handling, token lifecycle, TLS trust, or the Secret type. Covers the
  Go-idiomatic public surface with real signatures and gotchas.
---

# API Patterns

The root package is `safeguard` (`github.com/OneIdentity/safeguard-go`). The
default API version is `v4` (`DefaultAPIVersion`). Everything I/O-bound is
context-first, optional behavior is a functional option, and secrets are
`Secret` values.

## Connect

`Connect` is the only way to obtain an authenticated `*Client`. There is no
in-place reconnect: to re-authenticate, call `Connect` again for a fresh
session.

```go
func Connect(ctx context.Context, host string, cred Credential, opts ...Option) (*Client, error)
```

```go
pw := safeguard.NewSecretString(os.Getenv("SPP_PASSWORD"))
defer pw.Zero()

client, err := safeguard.Connect(ctx, "spp.example.com",
    safeguard.PKCEHeadless("local", "admin", pw),
    safeguard.WithCABundle(caPEM),
)
if err != nil { /* ... */ }
defer client.Close() // terminal: releases transports, zeroes the token
```

Connection options are applied **before** authentication, so certificate
parsing and the login exchange run under the caller's TLS policy.

## Credentials

`Credential` is a **sealed** interface — callers cannot implement their own;
use one of the constructors. Refreshability differs by flow (see Token
lifecycle).

| Constructor | Signature | Refreshable |
|---|---|---|
| `UsernamePassword` | `(provider, username string, password Secret)` | yes |
| `Certificate` | `(certPEM []byte, password Secret, opts ...CertOption)` | yes |
| `PKCEHeadless` | `(provider, username string, password Secret, opts ...PKCEOption)` | no |
| `Token` | `(userToken Secret)` | no |
| `Anonymous` | `()` | n/a |
| `AuthorizedSession` | `(login LoginFunc)` | no — add-on seam |

- **`provider`** empty selects the default local provider; a non-default
  provider may be its display name, RSTS provider id, or a unique substring of
  that id (resolved the same way SafeguardDotNet/safeguard-ps resolve it).
- **`PKCEHeadless` is the recommended automation flow** — it does not depend on
  the Resource Owner Grant, which appliances commonly disable. Supply
  `WithSecondaryFactor(fn)` for MFA.
- **`Certificate`** accepts **PEM only**; PKCS#12 (`.pfx`/`.p12`) is rejected
  with a clear error — convert first (`openssl pkcs12 -in cert.pfx -nodes -out
  cert.pem`). Key options: `WithPrivateKeyPEM([]byte)`,
  `WithCertificateProvider(string)`.
- **`Anonymous`** carries no user token — sufficient for `Notification` and
  other anonymous endpoints.
- **Browser / device-code** logins are not called here; use the
  `browser`/`devicecode` add-on `Connect` functions (see below).

## Invoke surface

The client exposes convenience verbs plus a general `Invoke`, all returning a
`Response`:

```go
func (c *Client) Get(ctx, s Service, relURL string, opts ...ReqOption) (Response, error)
func (c *Client) Post(ctx, s Service, relURL string, body any, opts ...ReqOption) (Response, error)
func (c *Client) Put(ctx, s Service, relURL string, body any, opts ...ReqOption) (Response, error)
func (c *Client) Delete(ctx, s Service, relURL string, opts ...ReqOption) (Response, error)
func (c *Client) Invoke(ctx, m HTTPMethod, s Service, relURL string, body any, opts ...ReqOption) (Response, error)
```

**Body encoding by type** (Invoke/Post/Put): `nil` → empty; `string` and
`json.RawMessage` → `application/json`; `[]byte` and `io.Reader` →
`application/octet-stream`; any other value is JSON-marshaled. Override with
`WithHeader("Content-Type", ...)`. The response body is always read and closed.

### Typed decode

```go
func InvokeTyped[T any](ctx, c *Client, m HTTPMethod, s Service, relURL string, body any, opts ...ReqOption) (T, error)
```

Decodes a successful body into `T`. An empty body yields the zero value with no
error. Requires Go 1.21-compatible generics (no range-over-func iterators).

```go
type Me struct{ Id int; Name string }
me, err := safeguard.InvokeTyped[Me](ctx, client, safeguard.MethodGet, safeguard.Core, "Me", nil)
```

### Response

```go
type Response struct {
    StatusCode int
    Headers    http.Header
    Body       []byte // nil for streaming calls
    RequestID  string // appliance correlation id, if present
}
func (r Response) IsSuccess() bool // 2xx
func (r Response) String() string  // body as string
```

## Services

`Service` only selects the base URL path; it never implies authorization.

| Const | Path | Notes |
|---|---|---|
| `Core` | `service/core` | primary SPP API |
| `Appliance` | `service/appliance` | appliance management |
| `Notification` | `service/notification` | anonymous, no token |
| `A2A` | `service/a2a` | A2A credential retrieval |
| `Event` | `service/event` | SignalR events |
| `RSTS` | `RSTS` | token service, no version segment |
| `Management` | — | appliance management service |

## Request options (`ReqOption`)

| Option | Effect |
|---|---|
| `WithQueryParam(k, v)` / `WithQueryParams(map)` | add query parameters |
| `WithHeader(k, v)` | add a header; **`Authorization` is rejected** with `ErrReservedHeader` |
| `WithAccept(mediaType)` | override Accept (e.g. `"text/csv"` for reports) |
| `WithHost(host)` | per-request host override (same TLS config) |
| `WithAPIVersionOverride(v)` | API version for this request only |
| `WithRequestTimeout(d)` | derives a context deadline for this (non-stream) call |

Authorization is controlled exclusively by the transport axis and can never be
set as a request header — that is the point of `ErrReservedHeader`.

## Connection options (`Option`)

`WithCABundle([]byte)`, `WithInsecureTLS()`, `WithServerCertValidator(v)`,
`WithAPIVersion(v)`, `WithHTTPTimeouts(Timeouts{Dial, TLSHandshake,
ResponseHeader})`, `WithLogger(*slog.Logger)`.

- **`WithCABundle`** is the secure way to trust a self-signed/privately-issued
  appliance cert.
- **`WithInsecureTLS`** disables chain and hostname verification on every
  transport, including the event WebSocket. Bootstrapping/dev/test only — it is
  loud and dangerous, and cannot combine with `WithServerCertValidator`.
- **`WithServerCertValidator`** is *additive* — it runs after normal
  verification and can only further restrict trust (parity with .NET's
  `RemoteCertificateValidationCallback`).
- No global request timeout exists by design (it would break streams/events);
  use context and `WithRequestTimeout`.

## Streaming, upload, download

```go
func (c *Client) Stream(ctx, m, s, relURL, body, opts...) (io.ReadCloser, Response, error)
func (c *Client) Upload(ctx, s, relURL string, r io.Reader, opts...) (Response, error)
func (c *Client) Download(ctx, s, relURL string, w io.Writer, opts...) (Response, error)
```

- **`Stream`** returns a body the caller **must Close**; it is not buffered and
  never retried, so a consumed stream cannot be replayed. It does not apply
  `WithRequestTimeout` — control cancellation through `ctx`.
- **`Upload`** sends `r` as `application/octet-stream` without buffering.
- **`Download`** streams the payload to `w`; `Response.Body` is nil on
  success, or holds the bounded error payload on a non-2xx status. Default
  Accept is `application/octet-stream`; override with `WithAccept`.

## Errors

Non-2xx responses return a typed error **alongside** a populated
`Response`.

```go
type APIError struct { StatusCode int; Code int; Message string; RequestID string }
func (e *APIError) Error() string   // deliberately omits the raw body
func (e *APIError) RawBody() []byte  // bounded copy; may contain secrets, never auto-logged
```

Specializations (embed `*APIError`, reachable via `errors.As`):
`AuthenticationError` (401), `AuthorizationError` (403), `NotFoundError` (404).
Pre-response failures are `*TransportError{Op, Err}` (`errors.Is/As` reaches the
cause).

```go
resp, err := client.Get(ctx, safeguard.Core, "Users/99999")
var nf *safeguard.NotFoundError
if errors.As(err, &nf) { /* not found */ }
var apiErr *safeguard.APIError
if errors.As(err, &apiErr) { log.Printf("api %d code=%d", apiErr.StatusCode, apiErr.Code) }
```

Sentinels (`errors.Is`): `ErrNotAuthenticated`, `ErrNotRefreshable`,
`ErrReservedHeader`, `ErrClosed`, `ErrAlreadyStarted`,
`ErrSecondaryFactorRequired`, `ErrSecondaryFactorFailed`.

**`APIError.Error()` never includes the raw response body** because it may carry
returned credentials. Use `RawBody()` for an explicit, bounded diagnostic copy.

## Token lifecycle

```go
func (c *Client) RefreshToken(ctx) error
func (c *Client) TokenLifetimeRemaining(ctx) (time.Duration, error)
func (c *Client) Logout(ctx) error
```

- **`RefreshToken`** re-runs the full login exchange (single-flight: concurrent
  callers share one refresh). It reports `ErrNotAuthenticated` for an anonymous
  session and `ErrNotRefreshable` for a bare token or an OAuth
  authorization-code flow (PKCE/browser/device-code). Tokens are long-lived;
  don't over-engineer refresh.
- **`TokenLifetimeRemaining`** returns a cached expiry without a network call
  when known; otherwise it consults Core `LoginMessage` once and reads the
  `X-TokenLifetimeRemaining` header. Returns `ErrNotAuthenticated` for an
  anonymous session.
- **`Logout`** makes a best-effort appliance `Token/Logout`, then clears the
  local session and invalidates its epoch so an in-flight refresh cannot
  resurrect it. Idempotent; a no-op for anonymous.
- **`Close`** is terminal — releases transports and zeroes the token; safe to
  `defer` and idempotent.

## Secret

`Secret` makes reading sensitive bytes a deliberate act. It **prevents
accidental disclosure**; it is **not** memory-hardening.

```go
s := safeguard.NewSecretString("password")   // copies input
b := safeguard.NewSecret(byteSlice)           // copies input
raw := s.Expose()        // []byte copy — caller may zero it
str := s.ExposeString()  // string copy — cannot be zeroed
s.Zero()                 // best-effort wipe; defer s.Zero()
s.Equal(other)           // constant-time compare
```

Redaction is automatic for `fmt` (`String`/`GoString`/`Format` → `[REDACTED]`),
JSON/text marshaling, and `slog` (`LogValue`). What it does **not** provide:
no encryption at rest in memory, no reclaim of already-exposed values, and
`Zero` is best-effort (the runtime may copy the backing array). Document this
so callers set correct expectations.

## Add-on logins (interactive)

Optional packages keep the interactive machinery out of headless builds:

```go
// browser: opens the system browser, runs a loopback listener on 127.0.0.1
client, err := browser.Connect(ctx, host,
    browser.WithConnectionOptions(safeguard.WithCABundle(caPEM)),
    browser.WithLoginHint("admin"),   // optional
    browser.WithPort(0),              // 0 = OS-chosen ephemeral port
    browser.WithBrowserOpener(fn),    // optional, for tests/remote
)

// devicecode: OAuth device authorization grant; prompt shows the user code
client, err := devicecode.Connect(ctx, host, func(ctx context.Context, p devicecode.Prompt) error {
    fmt.Printf("Visit %s and enter %s\n", p.VerificationURI, p.UserCode)
    return nil
}, devicecode.WithConnectionOptions(...), devicecode.WithPollInterval(d))
```

Both produce **non-refreshable** sessions (existing-token model). Errors:
`browser.ErrNoAuthorizationCode`; `devicecode.ErrDenied`, `devicecode.ErrExpired`,
`devicecode.ErrNoPrompt`.

## Runnable examples

`samples/` holds one standalone `package main` per flow (`pkce`, `certificate`,
`token`, `anonymous`, `browser`, `devicecode`, the `a2a-*` set, and the event
listeners). Each takes `-appliance`, `-ca`/`-insecure`, and flow-specific flags.
They are the fastest way to see a correct end-to-end call.
