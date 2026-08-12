---
name: event-workflow
description: >-
  Use when listening for Safeguard events: registering handlers, one-shot vs.
  persistent listeners, listener lifecycle (Start/Stop/Done/Err), the numeric
  event-name workaround, reconnect/backoff, and the SignalR-over-WebSocket
  internals the SDK owns. Applies to both user-session and A2A event listeners.
---

# Event Workflow

The SDK owns a minimal SignalR-over-WebSocket client (built on
`github.com/coder/websocket`, the module's only third-party dependency) so
consumers never handle SignalR framing themselves. Listeners come in two shapes
from two sources.

## Public API

```go
// user session (client's own events)
func (c *Client) NewEventListener() *EventListener
func (c *Client) NewPersistentEventListener() *PersistentEventListener

// A2A (events for the account an API key retrieves)
func (a *A2AContext) NewEventListener(apiKey Secret) *EventListener
func (a *A2AContext) NewPersistentEventListener(apiKey Secret) *PersistentEventListener

// both listener types share these methods:
func RegisterEventHandler(name string, h EventHandlerFunc)
func Start(ctx context.Context) error
func Stop()
func Done() <-chan struct{}
func Err() error

type EventHandlerFunc func(name string, data json.RawMessage)
```

### Usage

```go
listener := client.NewEventListener()
listener.RegisterEventHandler("AssetAccountPasswordUpdated", func(name string, data json.RawMessage) {
    fmt.Printf("event %s: %s\n", name, data)
})
if err := listener.Start(ctx); err != nil { /* connect failed */ }
defer listener.Stop()
<-listener.Done()               // blocks until stopped
if err := listener.Err(); err != nil && ctx.Err() == nil { /* stopped on error */ }
```

- **Register handlers before `Start`.** Registering the same name more than once
  adds handlers; matching is **case-insensitive**.
- **`Start`** performs negotiate + handshake **synchronously** (returns an error
  if the connection can't be established), then services the stream on a
  background goroutine. `ctx` bounds the whole listener lifetime, not just the
  connect. Calling `Start` twice returns `ErrAlreadyStarted` — create a new
  listener rather than restarting a stopped one.
- **`Done`** closes when the listener stops (Stop, cancelled ctx, or connection
  error); it returns `nil` before `Start`. **`Err`** returns the cause (nil if
  clean or still running). **`Stop`** waits for the goroutine to finish and is
  safe to call repeatedly and before `Start` returns.

## Handler execution model

Handlers run on a **dispatcher goroutine off the read loop**. Two consequences:

- A **panic in a handler is recovered** and does not stop the listener.
- A **slow handler applies backpressure** to later events (the dispatcher is not
  unbounded). Handlers should not block indefinitely; hand off to a channel or
  worker if processing is heavy.

## One-shot vs. persistent

- `EventListener` (one-shot): a single connection. It **stops when the
  connection ends** — no reconnect.
- `PersistentEventListener`: reconnects automatically with **exponential backoff
  and jitter** (`reconnectBackoff`), preserving registered handlers and
  restoring subscriptions across reconnects. `Start` returns immediately and the
  connect/reconnect loop runs in the background until `Stop`, ctx cancel, or a
  terminal condition.
  - **User session:** stops **permanently** once the owning session is logged
    out or replaced by a different identity (it must not reconnect under the
    wrong identity — this ties to the session epoch).
  - **A2A:** an API key does not expire, so it simply reconnects until `Stop`.

## The numeric event-name workaround (do not remove)

Safeguard sometimes delivers an event whose SignalR "target" is a numeric
string rather than the event name. The listener always reads the **real event
name from the payload's `Data.EventName`** (`eventNameFromData`, which also
handles a `Data` that arrives as an array). The `name` passed to your
`EventHandlerFunc` is this resolved name. Preserve this behavior — handler matching
depends on it.

## SignalR-over-WebSocket internals (owned by the SDK)

Relevant when touching `events_signalr.go`:

- **Record separator:** every SignalR message is terminated by `0x1e`
  (`recordSeparator`, U+001E). A single WebSocket frame may carry several
  coalesced records — `splitRecords` splits on the separator; empty trailing
  parts are ignored.
- **Negotiate:** `POST https://<host>/service/<servicePath>/signalr/negotiate?negotiateVersion=1`
  returns the connection token. Failures are wrapped as `*TransportError`
  (`event-negotiate*` ops) with sanitized causes.
- **Upgrade + handshake:** open the `wss` connection with the negotiated token,
  then send the JSON protocol handshake; the reply is a single record — `{}` on
  success or `{"error":"..."}` on rejection.
- **User-token auth:** a user-session listener passes its bearer token in the
  `access_token` query parameter (the standard ASP.NET Core SignalR convention,
  since a WebSocket handshake can't set an `Authorization` header). This is as
  secure as the header because the connection is always `wss`; the token can
  still land in appliance request logs, which is the appliance's concern, not the
  SDK's. See
  <https://learn.microsoft.com/aspnet/core/signalr/security#access-token-logging>.
- **Transport axis:** the listener negotiates and upgrades on the correct
  `tlsIdentity` with the current token snapshot — `serverTrust` + user token for
  a `Client` listener; `clientCert` + A2A API key for an `A2AContext` listener.
  The WebSocket client shares the connection's TLS config (and, for A2A, its
  certificates) and has no overall timeout, since an event stream is long-lived.
- **Frame types:** `handleMessage` dispatches invocation records (deliver
  events), ping/keep-alive, and close/completion messages; a clean server close
  is detected by `isCleanClose` and is not reported as an error.
- **Keep-alive:** the session runs a `keepAlive` writer; writes are serialized so
  handshake and keep-alive never interleave on the connection.

## Testing

The SignalR frame parser is a prime **fuzz** target — feed coalesced records,
stray/leading/trailing separators, oversized frames, and malformed JSON.
Listener concurrency (start/stop/reconnect, dispatch vs. session teardown) is
covered by **race** tests. Live coverage exercises real negotiate/handshake and
event delivery against the appliance; `samples/events`, `samples/events-persistent`,
and `samples/a2a-events` are runnable listeners.
