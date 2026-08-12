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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// recordSeparator (U+001E) terminates every SignalR message on the wire. A single
// WebSocket message may carry several records back to back.
const recordSeparator = 0x1e

// signalrHandshake is the JSON protocol handshake the client sends immediately
// after the WebSocket opens; the appliance rejects any version other than 1.
const signalrHandshake = `{"protocol":"json","version":1}`

// hubMethodEvent is the hub method the appliance invokes to push an event. Some
// appliance versions also use hubMethodEventAlias.
const (
	hubMethodEvent      = "NotifyEventAsync"
	hubMethodEventAlias = "ReceiveMessage"
)

// SignalR message type discriminators used by the appliance.
const (
	signalrInvocation = 1
	signalrPing       = 6
	signalrClose      = 7
)

// eventKeepAlive is how often the listener sends a client ping so the appliance
// does not time the connection out while a slow handler is running.
const eventKeepAlive = 15 * time.Second

// eventReadLimit caps a single inbound WebSocket message to guard against a
// hostile or malfunctioning peer. Safeguard event payloads are far smaller.
const eventReadLimit = 1 << 20

// eventDispatchBuffer bounds how many decoded events may await a handler before
// the read loop applies backpressure.
const eventDispatchBuffer = 256

// errEpochChanged reports that the session that owns an event listener was
// replaced (for example by Logout and re-login as a different identity), so the
// listener must stop rather than reconnect under a different identity.
var errEpochChanged = errors.New("safeguard: session changed; event listener stopped")

// eventConn holds everything an event listener needs to (re)establish a SignalR
// connection to one appliance event source. It is shared, unchanged, across every
// reconnect; the per-attempt authorization is produced by auth so a user
// listener always negotiates with the current token snapshot.
type eventConn struct {
	host       string
	apiVersion string
	transports *transportSet
	logger     *slog.Logger

	// servicePath is the event service segment: "event" for user events or "a2a"
	// for A2A credential events.
	servicePath string
	// tlsID selects the TLS identity the negotiate and upgrade ride on:
	// serverTrust for user events, clientCert for A2A events.
	tlsID tlsIdentity
	// auth returns the authorization for the current attempt, or an error when
	// the owning session is gone (anonymous, logged out, or a different epoch).
	auth func() (authorization, error)
}

// eventSession is one live SignalR connection.
type eventSession struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

// negotiateResponse is the subset of the SignalR negotiate reply the listener
// uses. The connectionToken is threaded onto the WebSocket URL as the id query.
type negotiateResponse struct {
	ConnectionToken string `json:"connectionToken"`
	Error           string `json:"error"`
}

// hostAuthority strips any scheme and trailing slash from the configured host,
// yielding a bare authority such as "appliance.example.com".
func (ec *eventConn) hostAuthority() string {
	h := ec.host
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	return strings.Trim(h, "/")
}

// negotiateURL is the HTTPS negotiate endpoint for the event source.
func (ec *eventConn) negotiateURL() string {
	return fmt.Sprintf("https://%s/service/%s/signalr/negotiate?negotiateVersion=1", ec.hostAuthority(), ec.servicePath)
}

// websocketURL is the wss upgrade endpoint carrying the negotiated connection
// token and, for user events, the access token as a query parameter.
//
// Passing the bearer token in the access_token query parameter is the standard
// ASP.NET Core SignalR convention (the appliance's event hub is SignalR): the
// WebSocket handshake cannot carry an Authorization header, so the token is sent
// in the query string instead. This is as secure as the header provided the
// connection uses TLS (wss), which it always does here. Per Microsoft's guidance
// the token may still appear in server-side request logs, so the appliance is
// responsible for scrubbing it there.
// See https://learn.microsoft.com/aspnet/core/signalr/security#access-token-logging
func (ec *eventConn) websocketURL(connToken string, auth authorization) string {
	q := url.Values{"id": {connToken}}
	if auth.kind == authUserToken && !auth.token.IsZero() {
		q.Set("access_token", auth.token.ExposeString())
	}
	return fmt.Sprintf("wss://%s/service/%s/signalr?%s", ec.hostAuthority(), ec.servicePath, q.Encode())
}

// connect performs the negotiate, WebSocket upgrade, and SignalR handshake,
// returning a live session ready to read. It fails fast on a missing session, a
// negotiate error, or a rejected handshake.
func (ec *eventConn) connect(ctx context.Context) (*eventSession, error) {
	auth, err := ec.auth()
	if err != nil {
		return nil, err
	}

	connToken, err := ec.negotiate(ctx, auth)
	if err != nil {
		return nil, err
	}

	wsClient, err := ec.transports.websocketClient(ec.tlsID)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	if auth.kind == authA2A {
		if v := auth.headerValue(); v != "" {
			header.Set("Authorization", v)
		}
	}
	conn, _, err := websocket.Dial(ctx, ec.websocketURL(connToken, auth), &websocket.DialOptions{
		HTTPClient: wsClient,
		HTTPHeader: header,
	})
	if err != nil {
		return nil, &TransportError{Op: "event-dial", Err: sanitizeError(err)}
	}
	conn.SetReadLimit(eventReadLimit)
	sess := &eventSession{conn: conn}

	if err := sess.handshake(ctx); err != nil {
		_ = conn.Close(websocket.StatusInternalError, "handshake failed")
		return nil, err
	}
	return sess, nil
}

// negotiate POSTs to the negotiate endpoint and returns the connection token.
func (ec *eventConn) negotiate(ctx context.Context, auth authorization) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ec.negotiateURL(), nil)
	if err != nil {
		return "", &TransportError{Op: "event-negotiate", Err: sanitizeError(err)}
	}
	req.Header.Set("Accept", "application/json")
	if v := auth.headerValue(); v != "" {
		req.Header.Set("Authorization", v)
	}
	resp, err := ec.transports.do(ec.tlsID, req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, eventReadLimit))
	if err != nil {
		return "", &TransportError{Op: "event-negotiate-read", Err: sanitizeError(err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", newAPIError(resp.StatusCode, body, resp.Header)
	}
	var nr negotiateResponse
	if err := json.Unmarshal(body, &nr); err != nil {
		return "", &TransportError{Op: "event-negotiate-decode", Err: err}
	}
	if nr.Error != "" {
		return "", fmt.Errorf("safeguard: event negotiate rejected: %s", nr.Error)
	}
	if nr.ConnectionToken == "" {
		return "", errors.New("safeguard: event negotiate returned no connection token")
	}
	return nr.ConnectionToken, nil
}

// handshake sends the JSON protocol handshake and validates the reply.
func (s *eventSession) handshake(ctx context.Context) error {
	if err := s.write(ctx, signalrHandshake); err != nil {
		return err
	}
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return &TransportError{Op: "event-handshake-read", Err: sanitizeError(err)}
	}
	// The handshake reply is a single record: {} on success or {"error":"..."}.
	records := splitRecords(data)
	if len(records) == 0 {
		return errors.New("safeguard: empty event handshake response")
	}
	var hs struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(records[0], &hs); err != nil {
		return &TransportError{Op: "event-handshake-decode", Err: err}
	}
	if hs.Error != "" {
		return fmt.Errorf("safeguard: event handshake rejected: %s", hs.Error)
	}
	return nil
}

// write sends payload as a single SignalR record (text message terminated by the
// record separator). Writes are serialized so the keep-alive pinger and the
// handshake never interleave on the connection.
func (s *eventSession) write(ctx context.Context, payload string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	msg := append([]byte(payload), recordSeparator)
	if err := s.conn.Write(ctx, websocket.MessageText, msg); err != nil {
		return &TransportError{Op: "event-write", Err: sanitizeError(err)}
	}
	return nil
}

// serve runs the read and keep-alive loops until the connection ends or ctx is
// cancelled, dispatching decoded events to reg. It returns nil when ctx is
// cancelled or the server closes cleanly, and the underlying error otherwise.
func (s *eventSession) serve(ctx context.Context, reg *eventRegistry) error {
	defer func() { _ = s.conn.Close(websocket.StatusNormalClosure, "") }()

	dispatch := make(chan decodedEvent, eventDispatchBuffer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range dispatch {
			reg.dispatch(ev)
		}
	}()
	defer wg.Wait()
	defer close(dispatch)

	// Keep-alive pings run independently of dispatch so a slow handler cannot
	// stall them and trip the appliance's client timeout.
	pingCtx, stopPing := context.WithCancel(ctx)
	defer stopPing()
	go s.keepAlive(pingCtx)

	for {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isCleanClose(err) {
				return nil
			}
			return &TransportError{Op: "event-read", Err: sanitizeError(err)}
		}
		closed, derr := s.handleMessage(ctx, data, dispatch)
		if derr != nil {
			return derr
		}
		if closed {
			return nil
		}
	}
}

// keepAlive sends a client ping on a fixed interval until ctx is cancelled.
func (s *eventSession) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(eventKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.write(ctx, `{"type":6}`); err != nil {
				return
			}
		}
	}
}

// handleMessage splits a WebSocket message into records, dispatching each event
// invocation and reporting whether the server asked to close. Malformed records
// are skipped rather than tearing the connection down.
func (s *eventSession) handleMessage(ctx context.Context, data []byte, dispatch chan<- decodedEvent) (closed bool, err error) {
	for _, rec := range splitRecords(data) {
		var msg struct {
			Type      int               `json:"type"`
			Target    string            `json:"target"`
			Arguments []json.RawMessage `json:"arguments"`
		}
		if e := json.Unmarshal(rec, &msg); e != nil {
			continue
		}
		switch msg.Type {
		case signalrClose:
			return true, nil
		case signalrPing:
			continue
		case signalrInvocation:
			if msg.Target != hubMethodEvent && msg.Target != hubMethodEventAlias {
				continue
			}
			if len(msg.Arguments) == 0 {
				continue
			}
			ev, ok := decodeEvent(msg.Arguments[0])
			if !ok {
				continue
			}
			// Respect cancellation so a stalled handler with a full buffer cannot
			// block shutdown.
			select {
			case dispatch <- ev:
			case <-ctx.Done():
				return true, nil
			}
		}
	}
	return false, nil
}

// decodeEvent parses one event invocation argument into a decodedEvent, applying
// the numeric-event-name workaround: when the appliance reports Name as a numeric
// string it carries the real name in Data.EventName.
func decodeEvent(arg json.RawMessage) (decodedEvent, bool) {
	var raw struct {
		Name string          `json:"Name"`
		Data json.RawMessage `json:"Data"`
	}
	if err := json.Unmarshal(arg, &raw); err != nil {
		return decodedEvent{}, false
	}
	name := raw.Name
	if _, err := strconv.Atoi(strings.TrimSpace(name)); err == nil && len(raw.Data) > 0 {
		if inner := eventNameFromData(raw.Data); inner != "" {
			name = inner
		}
	}
	return decodedEvent{name: name, data: raw.Data}, true
}

// eventNameFromData extracts EventName from an event Data payload, which may be a
// JSON object or a JSON string containing an object.
func eventNameFromData(data json.RawMessage) string {
	var obj struct {
		EventName string `json:"EventName"`
	}
	if err := json.Unmarshal(data, &obj); err == nil && obj.EventName != "" {
		return obj.EventName
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil && s != "" {
		if err := json.Unmarshal([]byte(s), &obj); err == nil {
			return obj.EventName
		}
	}
	return ""
}

// splitRecords splits a WebSocket message on the record separator, dropping empty
// and whitespace-only fragments (including a trailing empty fragment).
func splitRecords(data []byte) [][]byte {
	parts := bytes.Split(data, []byte{recordSeparator})
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}

// isCleanClose reports whether err represents a normal or going-away WebSocket
// close, which the listener treats as an ordinary end of stream.
func isCleanClose(err error) bool {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	return errors.Is(err, io.EOF)
}

// reconnectBackoff computes the delay before the next reconnect attempt using
// exponential growth capped at one minute with +/-25% jitter, matching the
// reference SDKs so operational behavior is predictable.
func reconnectBackoff(attempt int, rng *rand.Rand) time.Duration {
	const (
		initial = 1.0
		maxSecs = 60.0
		jitter  = 0.25
	)
	base := initial * math.Pow(2, float64(attempt))
	if base > maxSecs {
		base = maxSecs
	}
	mult := 1.0 - jitter + 2*jitter*rng.Float64()
	return time.Duration(base * mult * float64(time.Second))
}
