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
)

// Client is a concurrency-safe Safeguard API client. It is safe for use by
// multiple goroutines: token state is immutable and swapped atomically, and the
// transport pools are internally synchronized.
//
// A freshly built client starts in an anonymous session, which is sufficient for
// the Notification service and other anonymous endpoints; Connect establishes an
// authenticated session from a credential.
type Client struct {
	host       string
	apiVersion string
	transports *transportSet
	logger     *slog.Logger

	// credential is the strategy that established this client's session. It is
	// retained so a refreshable credential can mint a fresh token.
	credential Credential

	// refresh serializes token refreshes so concurrent callers that observe the
	// same stale token trigger exactly one re-authentication.
	refresh refreshCoordinator

	token  atomic.Pointer[tokenState]
	closed atomic.Bool
}

// newClient builds a client shell for host with the given connection options.
// The client starts anonymous. This is the internal construction seam used by the
// credential constructors and Connect.
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
// within the current epoch. It is the internal seam that the login flows use to
// publish an exchanged token.
func (c *Client) setUserToken(token Secret, refreshable bool) {
	c.installSession(&session{token: token, refreshable: refreshable})
}

// installSession publishes s as the client's current session, bumping the
// generation within the current epoch via CAS so concurrent installs and reads
// stay race-free. It is the single seam through which Connect and the token
// seam publish authentication state.
func (c *Client) installSession(s *session) {
	for {
		prev := c.token.Load()
		next := &tokenState{
			epoch:       1,
			token:       s.token,
			anonymous:   s.anonymous,
			refreshable: s.refreshable,
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

// Logout ends this client's session. It makes a best-effort appliance-side
// Token/Logout call to revoke the user token, then clears the local session and
// invalidates its epoch so an in-flight refresh cannot resurrect it. A failure of
// the appliance call is ignored: the local session is cleared regardless. Logout
// is idempotent and is a no-op for an anonymous session.
func (c *Client) Logout(ctx context.Context) error {
	if c.isClosed() {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if prev := c.token.Load(); prev != nil && !prev.anonymous && !prev.token.IsZero() {
		c.applianceLogout(ctx, prev.token)
	}
	// Swap in a terminal epoch and zero whatever token it displaces. Using Swap
	// (rather than Load then Store) means a token installed by a refresh that
	// raced this logout is still zeroed, and doRefresh's CAS on the observed
	// (epoch, generation) can never resurrect the session because epoch 0 never
	// matches.
	if prev := c.token.Swap(&tokenState{epoch: 0, anonymous: true}); prev != nil {
		s := prev.token
		(&s).Zero()
	}
	return nil
}

// applianceLogout performs the best-effort Core Token/Logout call that revokes a
// user token appliance-side. It builds the request with the supplied token
// directly (the client's session may be cleared concurrently) and ignores every
// outcome; it never replays or refreshes.
func (c *Client) applianceLogout(ctx context.Context, token Secret) {
	base, err := Core.baseURL(c.host, c.apiVersion)
	if err != nil {
		return
	}
	req, err := buildHTTPRequest(ctx, MethodPost, base+"Token/Logout", nil, userTokenAuth(token), "", nil)
	if err != nil {
		return
	}
	resp, err := c.transports.do(serverTrust, req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// Close is terminal: it releases the transport pools and zeroes the in-memory
// token. Close installs a terminal epoch so an in-flight refresh cannot
// resurrect the session (doRefresh publishes only on the observed epoch, and
// epoch 0 never matches) and zeroes whatever token that swap displaces. After
// Close the client cannot be used. Close is idempotent.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if prev := c.token.Swap(&tokenState{epoch: 0, anonymous: true}); prev != nil {
		s := prev.token
		(&s).Zero()
	}
	c.transports.Close()
	return nil
}
