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
	"strconv"
	"strings"
	"time"
)

// tokenState is the immutable, atomically swapped authentication state of a
// client. It pairs the session epoch with a monotonic generation so refreshes
// and 401 replays can be reasoned about without races. The user token is held as
// a Secret and never persisted or logged.
type tokenState struct {
	// epoch is the immutable session identifier minted at Connect. A new login
	// mints a new epoch; requests and refreshes capture their epoch and never
	// cross epoch boundaries.
	epoch uint64
	// generation is a monotonic counter bumped on every token swap within an epoch.
	generation uint64
	// token is the Safeguard user token, or a zero Secret for anonymous sessions.
	token Secret
	// anonymous marks a session that carries no user token.
	anonymous bool
	// refreshable indicates the credential can mint a fresh token. A bare user
	// token supplied via Token is not refreshable.
	refreshable bool
}

// TokenLifetimeRemaining reports the remaining lifetime of the current user
// token. The appliance is consulted once via the Core LoginMessage endpoint,
// whose X-TokenLifetimeRemaining header carries the remaining minutes. It returns
// ErrNotAuthenticated for an anonymous or absent session, and zero with no error
// when the lifetime cannot be determined.
func (c *Client) TokenLifetimeRemaining(ctx context.Context) (time.Duration, error) {
	if c.isClosed() {
		return 0, ErrClosed
	}
	ts := c.token.Load()
	if ts == nil || ts.anonymous || ts.token.IsZero() {
		return 0, ErrNotAuthenticated
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.queryTokenLifetime(ctx)
}

// tokenLifetimeHeader is the response header, in minutes, that Safeguard uses to
// report a user token's remaining lifetime on an authenticated response.
const tokenLifetimeHeader = "X-TokenLifetimeRemaining"

// queryTokenLifetime consults the appliance for the current token's remaining
// lifetime by reading the X-TokenLifetimeRemaining header off an authenticated
// Core LoginMessage request. A missing or unparseable header yields zero with no
// error.
func (c *Client) queryTokenLifetime(ctx context.Context) (time.Duration, error) {
	full, err := c.Get(ctx, Core, "LoginMessage")
	if err != nil {
		return 0, err
	}
	raw := strings.TrimSpace(full.Headers.Get(tokenLifetimeHeader))
	if raw == "" {
		return 0, nil
	}
	minutes, err := strconv.Atoi(raw)
	if err != nil || minutes < 0 {
		return 0, nil
	}
	return time.Duration(minutes) * time.Minute, nil
}

// RefreshToken exchanges the current credential for a fresh user token by
// re-running the full login exchange (single flight: concurrent callers share one
// refresh). It reports ErrNotAuthenticated for an anonymous or absent session and
// ErrNotRefreshable when the credential cannot mint a replacement token (a bare
// user token, or an OAuth authorization-code flow such as PKCE, browser, or
// device code).
func (c *Client) RefreshToken(ctx context.Context) error {
	if c.isClosed() {
		return ErrClosed
	}
	ts := c.token.Load()
	if ts == nil || ts.anonymous || ts.token.IsZero() {
		return ErrNotAuthenticated
	}
	if !ts.refreshable {
		return ErrNotRefreshable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.refreshOnce(ctx, ts.epoch, ts.generation)
}

// currentAuthorization returns the authorization axis value for a standard
// request based on the client's current token state.
func (c *Client) currentAuthorization() authorization {
	ts := c.token.Load()
	if ts == nil || ts.anonymous || ts.token.IsZero() {
		return noAuth()
	}
	return userTokenAuth(ts.token)
}
