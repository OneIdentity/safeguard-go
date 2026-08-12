// Copyright 2026 One Identity LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safeguard

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// EventHandlerFunc receives an event it was registered for: name is the resolved
// event name (with the numeric-name workaround applied) and data is the raw JSON
// payload for the caller to decode. Handlers run on a dispatcher goroutine off
// the read loop; a panic in a handler is recovered and does not stop the
// listener. A handler should not block indefinitely, as a slow handler applies
// backpressure to later events.
type EventHandlerFunc func(name string, data json.RawMessage)

// decodedEvent is one event decoded off the wire, carried from the read loop to
// the dispatcher.
type decodedEvent struct {
	name string
	data json.RawMessage
}

// eventRegistry maps event names to handlers. Lookups are case-insensitive to
// match the reference SDKs. It is shared unchanged across reconnects so a
// persistent listener keeps its handlers without re-registration.
type eventRegistry struct {
	mu       sync.RWMutex
	handlers map[string][]EventHandlerFunc
	logger   *slog.Logger
}

func newEventRegistry(logger *slog.Logger) *eventRegistry {
	return &eventRegistry{handlers: map[string][]EventHandlerFunc{}, logger: logger}
}

// register adds a handler for the named event.
func (r *eventRegistry) register(name string, h EventHandlerFunc) {
	if h == nil {
		return
	}
	key := strings.ToLower(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[key] = append(r.handlers[key], h)
}

// dispatch invokes every handler registered for ev's name, recovering panics so
// one misbehaving handler neither stops the listener nor blocks its peers.
func (r *eventRegistry) dispatch(ev decodedEvent) {
	r.mu.RLock()
	handlers := r.handlers[strings.ToLower(ev.name)]
	r.mu.RUnlock()
	for _, h := range handlers {
		r.invoke(h, ev)
	}
}

func (r *eventRegistry) invoke(h EventHandlerFunc, ev decodedEvent) {
	defer func() {
		if p := recover(); p != nil && r.logger != nil {
			r.logger.Error("safeguard: event handler panicked", "event", ev.name, "panic", p)
		}
	}()
	h(ev.name, ev.data)
}

// EventListener is a single-connection Safeguard event listener. It negotiates a
// SignalR-over-WebSocket connection, dispatches events to registered handlers,
// and stops when the connection ends. Register handlers before calling Start.
// EventListener is safe for concurrent handler registration before Start; use
// PersistentEventListener when automatic reconnect is required.
type EventListener struct {
	conn *eventConn
	reg  *eventRegistry

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
}

func newEventListener(conn *eventConn) *EventListener {
	return &EventListener{conn: conn, reg: newEventRegistry(conn.logger)}
}

// RegisterEventHandler registers h to receive events named name. Registering the
// same name more than once adds an additional handler. Matching is
// case-insensitive.
func (l *EventListener) RegisterEventHandler(name string, h EventHandlerFunc) {
	l.reg.register(name, h)
}

// Start connects the listener and begins dispatching events. It performs the
// negotiate and handshake synchronously, returning an error if the connection
// cannot be established, then services the stream on a background goroutine. The
// listener stops when the connection ends; Done reports that, and Err reports the
// cause. ctx bounds the whole listener lifetime, not just the connect.
func (l *EventListener) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return ErrAlreadyStarted
	}
	// Claim the started flag before the (synchronous) connect so a concurrent
	// Start cannot also proceed. On a connect failure we release the claim below
	// so the caller may retry.
	l.started = true
	l.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	sess, err := l.conn.connect(runCtx)
	if err != nil {
		cancel()
		l.mu.Lock()
		l.started = false
		l.mu.Unlock()
		return err
	}

	l.mu.Lock()
	l.cancel = cancel
	l.done = make(chan struct{})
	l.mu.Unlock()

	go func() {
		serveErr := sess.serve(runCtx, l.reg)
		l.mu.Lock()
		l.err = serveErr
		l.mu.Unlock()
		cancel()
		close(l.done)
	}()
	return nil
}

// Stop ends the listener and waits for its background goroutine to finish. It is
// safe to call more than once and before Start returns.
func (l *EventListener) Stop() {
	l.mu.Lock()
	cancel := l.cancel
	done := l.done
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Done returns a channel closed when the listener has stopped, whether from Stop,
// a cancelled context, or a connection error. It returns nil before Start.
func (l *EventListener) Done() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.done
}

// Err returns the error that stopped the listener, or nil if it stopped cleanly
// or is still running.
func (l *EventListener) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// PersistentEventListener is a Safeguard event listener that reconnects
// automatically with exponential backoff and jitter, preserving its registered
// handlers across reconnects. For a user session it stops permanently once the
// owning session is logged out or replaced, rather than reconnecting under a
// different identity.
type PersistentEventListener struct {
	conn *eventConn
	reg  *eventRegistry

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
}

func newPersistentEventListener(conn *eventConn) *PersistentEventListener {
	return &PersistentEventListener{conn: conn, reg: newEventRegistry(conn.logger)}
}

// RegisterEventHandler registers h to receive events named name. Handlers survive
// reconnects. Matching is case-insensitive.
func (l *PersistentEventListener) RegisterEventHandler(name string, h EventHandlerFunc) {
	l.reg.register(name, h)
}

// Start begins the listener's connect-and-reconnect loop on a background
// goroutine and returns immediately. The loop retries failed connects with
// backoff and reconnects after a dropped connection, until Stop is called, ctx is
// cancelled, or the owning session ends. Done reports a terminal stop and Err
// reports its cause.
func (l *PersistentEventListener) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return ErrAlreadyStarted
	}
	runCtx, cancel := context.WithCancel(ctx)
	l.started = true
	l.cancel = cancel
	l.done = make(chan struct{})
	l.mu.Unlock()

	go l.run(runCtx)
	return nil
}

// run drives the reconnect loop until a terminal condition is reached.
func (l *PersistentEventListener) run(ctx context.Context) {
	defer close(l.done)
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404 -- jitter only, not security sensitive.
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}
		sess, err := l.conn.connect(ctx)
		if err != nil {
			// A gone or changed session is terminal: do not reconnect under a
			// different identity.
			if isTerminalSessionErr(err) {
				l.setErr(err)
				return
			}
			if ctx.Err() != nil {
				return
			}
			l.sleep(ctx, reconnectBackoff(attempt, rng))
			attempt++
			continue
		}
		// The connection was established, so escalating connect backoff resets.
		attempt = 0
		serveErr := sess.serve(ctx, l.reg)
		if ctx.Err() != nil {
			return
		}
		if serveErr != nil && isTerminalSessionErr(serveErr) {
			l.setErr(serveErr)
			return
		}
		// Reconnect after any end of session (error or clean server close) with a
		// short floor delay so an immediately-closing server cannot spin the loop.
		l.sleep(ctx, reconnectBackoff(attempt, rng))
		attempt++
	}
}

// sleep waits d or until ctx is cancelled.
func (l *PersistentEventListener) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (l *PersistentEventListener) setErr(err error) {
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
}

// Stop ends the listener and waits for its loop to finish. It is idempotent.
func (l *PersistentEventListener) Stop() {
	l.mu.Lock()
	cancel := l.cancel
	done := l.done
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Done returns a channel closed when the listener has permanently stopped. It
// returns nil before Start.
func (l *PersistentEventListener) Done() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.done
}

// Err returns the terminal error that stopped the listener, if any.
func (l *PersistentEventListener) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// isTerminalSessionErr reports whether err means the owning session is gone or
// changed, so a persistent listener must stop instead of reconnecting.
func isTerminalSessionErr(err error) bool {
	return errors.Is(err, ErrNotAuthenticated) ||
		errors.Is(err, errEpochChanged) ||
		errors.Is(err, ErrClosed)
}

// userEventConn builds the event connection for the client's user session.
func (c *Client) userEventConn() *eventConn {
	startEpoch := uint64(0)
	if ts := c.token.Load(); ts != nil {
		startEpoch = ts.epoch
	}
	return &eventConn{
		host:        c.host,
		apiVersion:  c.apiVersion,
		transports:  c.transports,
		logger:      c.logger,
		servicePath: string(Event),
		tlsID:       serverTrust,
		auth: func() (authorization, error) {
			if c.isClosed() {
				return authorization{}, ErrClosed
			}
			ts := c.token.Load()
			if ts == nil || ts.anonymous || ts.token.IsZero() {
				return authorization{}, ErrNotAuthenticated
			}
			if ts.epoch != startEpoch {
				return authorization{}, errEpochChanged
			}
			return userTokenAuth(ts.token), nil
		},
	}
}

// NewEventListener returns a single-connection listener for this client's user
// events. Register handlers, then call Start. The listener stops if the
// connection ends; use NewPersistentEventListener for automatic reconnect.
func (c *Client) NewEventListener() *EventListener {
	return newEventListener(c.userEventConn())
}

// NewPersistentEventListener returns a reconnecting listener for this client's
// user events. It stops permanently if the client logs out or re-authenticates
// as a different identity.
func (c *Client) NewPersistentEventListener() *PersistentEventListener {
	return newPersistentEventListener(c.userEventConn())
}

// a2aEventConn builds the event connection for an A2A credential-event source
// authorized by apiKey over the context's client certificate.
func (a *A2AContext) a2aEventConn(apiKey Secret) *eventConn {
	return &eventConn{
		host:        a.host,
		apiVersion:  a.apiVersion,
		transports:  a.transports,
		logger:      a.logger,
		servicePath: string(A2A),
		tlsID:       clientCert,
		auth: func() (authorization, error) {
			if a.closed.Load() {
				return authorization{}, ErrClosed
			}
			return a2aAuth(apiKey), nil
		},
	}
}

// NewEventListener returns a single-connection listener for A2A credential events
// authorized by apiKey. Events are delivered for the account the API key
// retrieves. Register handlers, then call Start.
func (a *A2AContext) NewEventListener(apiKey Secret) *EventListener {
	return newEventListener(a.a2aEventConn(apiKey))
}

// NewPersistentEventListener returns a reconnecting listener for A2A credential
// events authorized by apiKey. An A2A API key does not expire, so the listener
// simply reconnects after a dropped connection until Stop.
func (a *A2AContext) NewPersistentEventListener(apiKey Secret) *PersistentEventListener {
	return newPersistentEventListener(a.a2aEventConn(apiKey))
}
