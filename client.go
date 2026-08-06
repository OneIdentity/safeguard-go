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
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
)

// Client is a concurrency-safe Safeguard API client. It is safe for use by
// multiple goroutines: token state is immutable and swapped atomically, and the
// transport pools are internally synchronized.
//
// In Phase 1 there is no public Connect; a client is built through the internal
// seam (and, from Phase 2, through the credential constructors). A freshly built
// client starts in an anonymous session, which is sufficient for the Notification
// service and other anonymous endpoints.
type Client struct {
	host       string
	apiVersion string
	transports *transportSet
	logger     *slog.Logger

	token  atomic.Pointer[tokenState]
	closed atomic.Bool
}

// newClient builds a client shell for host with the given connection options.
// The client starts anonymous. This is the internal construction seam used by
// tests and, from Phase 2, by the credential constructors and Connect.
func newClient(host string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errEmptyHost
	}
	cfg := defaultClientConfig()
	if err := cfg.apply(opts...); err != nil {
		return nil, err
	}
	tlsConfig, err := cfg.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	c := &Client{
		host:       host,
		apiVersion: cfg.apiVersion,
		transports: newTransportSet(tlsConfig, cfg.timeouts),
		logger:     cfg.logger,
	}
	c.token.Store(&tokenState{epoch: 1, anonymous: true})
	return c, nil
}

// setUserToken installs a user token for the client, bumping the generation
// within the current epoch. It is the internal seam that the concurrency tests
// and (Phase 2) the login flows use to publish an exchanged token.
func (c *Client) setUserToken(token Secret, expiry time.Time, refreshable bool) {
	for {
		prev := c.token.Load()
		next := &tokenState{
			epoch:       1,
			token:       token,
			expiry:      expiry,
			refreshable: refreshable,
		}
		if prev != nil {
			next.epoch = prev.epoch
			next.generation = prev.generation + 1
		}
		if c.token.CompareAndSwap(prev, next) {
			return
		}
	}
}

// Host returns the appliance host the client is bound to.
func (c *Client) Host() string { return c.host }

// APIVersion returns the default API version the client uses.
func (c *Client) APIVersion() string { return c.apiVersion }

// isClosed reports whether the client has been closed.
func (c *Client) isClosed() bool { return c.closed.Load() }

// Logout ends this client's session. Phase 1 clears the local session state; a
// reconnect means creating a new client (Phase 2 adds appliance-side revocation
// and stops persistent listeners). Logout is idempotent.
func (c *Client) Logout(_ context.Context) error {
	if c.isClosed() {
		return ErrClosed
	}
	if prev := c.token.Load(); prev != nil {
		s := prev.token
		(&s).Zero()
	}
	c.token.Store(&tokenState{epoch: 0, anonymous: true})
	return nil
}

// Close is terminal: it releases the transport pools and zeroes the in-memory
// token. After Close the client cannot be used. Close is idempotent.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if ts := c.token.Load(); ts != nil {
		s := ts.token
		(&s).Zero()
	}
	c.transports.Close()
	return nil
}
