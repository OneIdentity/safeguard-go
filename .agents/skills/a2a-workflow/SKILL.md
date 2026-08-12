---
name: a2a-workflow
description: >-
  Use when retrieving or setting credentials over the Safeguard
  Application-to-Application (A2A) service, brokering access requests on behalf
  of another user, enumerating retrievable accounts, or listening for A2A
  credential-change events. Covers A2AContext construction, the certificate +
  API-key authorization model, and its gotchas.
---

# A2A Workflow

A2A retrieves and updates credentials for registered accounts without a user
login. `A2AContext` is **not a token session**: it authenticates with a client
certificate over mutual TLS on every call, and each retrieval is authorized by a
per-account **API key** passed as an argument. The certificate proves the
calling application's identity; the API key selects which registered account the
call targets. This is the two-axis model (`clientCert` TLS identity + `authA2A`
authorization) in practice.

## Construction

```go
func NewA2AContext(host string, certPEM []byte, password Secret, opts ...A2AOption) (*A2AContext, error)
```

- `certPEM` is concatenated PEM (leaf + chain + optionally the key). Supply the
  key separately with `WithA2APrivateKeyPEM([]byte)` when it is in its own PEM.
- `password` decrypts an encrypted PEM key (empty `Secret` if unencrypted).
- **PEM only** — PKCS#12 is rejected; convert first with `openssl pkcs12 -in
  cert.pfx -nodes -out cert.pem`.
- `WithA2AConnectionOptions(...safeguard.Option)` forwards the same connection
  options as `Connect` (`WithCABundle`, `WithInsecureTLS`, `WithAPIVersion`,
  timeouts, logger).
- The certificate is parsed and validated **in memory** here — a bad
  cert/password fails immediately. No network call happens until the first
  retrieval. The context is safe for concurrent use; release it with `Close`.

```go
a2a, err := safeguard.NewA2AContext("spp.example.com", certPEM, safeguard.Secret{},
    safeguard.WithA2APrivateKeyPEM(keyPEM),
    safeguard.WithA2AConnectionOptions(safeguard.WithCABundle(caPEM)),
)
if err != nil { /* ... */ }
defer a2a.Close()
```

## Retrieval

```go
func (a *A2AContext) RetrievePassword(ctx, apiKey Secret) (Secret, error)
func (a *A2AContext) RetrievePrivateKey(ctx, apiKey Secret, format KeyFormat) (Secret, error)
func (a *A2AContext) RetrieveAPIKey(ctx, apiKey Secret) ([]APIKey, error)
```

- Every credential is returned inside a `Secret`. `RetrievePassword` returns an
  empty `Secret` when the account has no stored password.
- `KeyFormat` selects the encoding; an empty value means `KeyFormatOpenSSH`.
  Values: `KeyFormatOpenSSH` (`"OpenSsh"`), `KeyFormatSSH2` (`"Ssh2"`),
  `KeyFormatPuTTY` (`"Putty"`) — PascalCase to match the wire.
- `APIKey` carries `ID, Name, Description, ClientID, ClientSecret Secret,
  ClientSecretID`; the appliance returns one entry per configured API key. Only
  `ClientSecret` is wrapped as a `Secret`; the rest is non-sensitive metadata.

```go
pw, err := a2a.RetrievePassword(ctx, safeguard.NewSecretString(apiKey))
// use pw.Expose(); defer pw.Zero()
```

## Write-back (set)

```go
func (a *A2AContext) SetPassword(ctx, apiKey Secret, newPassword Secret) error
func (a *A2AContext) SetPrivateKey(ctx, apiKey Secret, privateKeyPEM Secret, passphrase Secret, format KeyFormat) error
```

The account's A2A registration must have **bidirectional (write-back) access
enabled**, or the appliance rejects the call. `SetPrivateKey` takes the key in
PEM (`privateKeyPEM`), its `format` (empty → OpenSSH), and a `passphrase`
(empty `Secret` for an unencrypted key).

## Broker an access request

```go
func (a *A2AContext) BrokerAccessRequest(ctx, brokerAPIKey Secret, req BrokeredAccessRequest) (*AccessRequest, error)
```

Creates an access request **on behalf of another user**, authorized by
`brokerAPIKey` — the API key of the registration's *access request broker*,
which is **distinct from an account's retrieval API key**. Requirements: the
registration must list the context's certificate user among its broker users,
**and** an access policy must grant the target user access to the target, or the
call is rejected.

`BrokeredAccessRequest` (zero-valued fields are omitted):

- `AccessRequestType` (required): `AccessRequestPassword`, `AccessRequestSSHKey`,
  `AccessRequestSSH`, `AccessRequestRemoteDesktop`,
  `AccessRequestRemoteDesktopApplication`, `AccessRequestTelnet`,
  `AccessRequestAPIKey`, `AccessRequestFile`.
- Target user: `ForUserID` (takes precedence) or `ForUser` (+ optional
  `ForProvider`).
- Target asset: `AssetID` (takes precedence) or `AssetName`.
- Target account: `AccountID` (takes precedence) or `AccountName` (+ optional
  `AccountDomainName`); omit the account to request the asset itself.
- Optional: `IsEmergency`, `ReasonCodeID`/`ReasonCode`, `ReasonComment`,
  `TicketNumber`, `RequestedFor`, `RequestedDuration{Days,Hours,Minutes}`.

The returned `AccessRequest` exposes `ID`, `State` (e.g. `"RequestAvailable"`
for an auto-approved request, `"PendingApproval"` otherwise),
`AccessRequestType`, `AccountID/Name`, `AssetID/Name`, and `Raw` (the full
appliance JSON for anything not modeled).

```go
req, err := a2a.BrokerAccessRequest(ctx, safeguard.NewSecretString(brokerKey),
    safeguard.BrokeredAccessRequest{
        AccessRequestType: safeguard.AccessRequestPassword,
        ForUser: "alice", AssetName: "db-01", AccountName: "svc",
    })
```

## Enumerate retrievable accounts — different auth axis

```go
func (a *A2AContext) GetRetrievableAccounts(ctx, filter string) ([]A2ARetrievableAccount, error)
```

**Gotcha:** unlike the Retrieve methods, this is authorized by the **client
certificate alone — no per-account API key** — because it enumerates *all*
registrations bound to the certificate user. Pass `""` for no filter, or an
OData filter applied to each registration's accounts.

Each `A2ARetrievableAccount` carries the per-account `APIKey` (a `Secret`), so
you can discover an account here and pass its `APIKey` straight to a Retrieve
method. Because an entry does **not** record which credential type it was
registered for, an account registered for multiple types appears once per type
with a distinct `APIKey`; a caller that needs the mapping must track it itself.

## A2A events

```go
func (a *A2AContext) NewEventListener(apiKey Secret) *EventListener
func (a *A2AContext) NewPersistentEventListener(apiKey Secret) *PersistentEventListener
```

Deliver credential events for the account the `apiKey` retrieves. A2A event auth
uses the **client certificate** for TLS plus the API key on the correct
authorization axis. An A2A API key does not expire, so the persistent listener
simply reconnects after a dropped connection until `Stop` — there is no session
identity to invalidate it (contrast the user-session persistent listener). See
the event-workflow skill for handler registration and lifecycle.

## Authorization model summary

| Operation | TLS identity | Authorization |
|---|---|---|
| `Retrieve*` / `Set*` | client certificate | per-account API key (`A2A <key>`) |
| `BrokerAccessRequest` | client certificate | broker API key (`A2A <key>`) |
| `GetRetrievableAccounts` | client certificate | **certificate only** (no API key) |
| A2A events | client certificate | per-account API key |

## Live coverage

`a2a_live_test.go` proves retrieve, set, broker, bogus-key rejection, and
`GetRetrievableAccounts` end-to-end against a real appliance; `internal/livetest`
provisions the certificate user, asset/account, stored credentials, API keys,
and registrations ephemerally and cleans them up. `samples/a2a-*` are runnable
one-file demos of each operation.
