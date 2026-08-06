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
	"time"
)

// tokenState is the immutable, atomically swapped authentication state of a
// client. It pairs the session epoch with a monotonic generation so refreshes
// and 401 replays can be reasoned about without races (full single-flight refresh
// and epoch-scoped replay land in Phase 2). The user token is held as a Secret
// and never persisted or logged.
type tokenState struct {
	// epoch is the immutable session identifier minted at Connect. A new login
	// mints a new epoch; requests and refreshes capture their epoch and never
	// cross epoch boundaries.
	epoch uint64
	// generation is a monotonic counter bumped on every token swap within an epoch.
	generation uint64
	// token is the Safeguard user token, or a zero Secret for anonymous sessions.
	token Secret
	// expiry is the cached token expiry used for proactive refresh; zero means
	// unknown.
	expiry time.Time
	// anonymous marks a session that carries no user token.
	anonymous bool
	// refreshable indicates the credential can mint a fresh token. A bare user
	// token supplied via Token is not refreshable.
	refreshable bool
}

// TokenLifetimeRemaining reports the remaining lifetime of the current user
// token from cached expiry. It does not call the appliance per request. It
// returns ErrNotAuthenticated for an anonymous or absent session, and zero with
// no error when the expiry is unknown.
//
// Phase 2 augments this to consult the appliance lifetime endpoint when needed.
func (c *Client) TokenLifetimeRemaining(_ context.Context) (time.Duration, error) {
	if c.isClosed() {
		return 0, ErrClosed
	}
	ts := c.token.Load()
	if ts == nil || ts.anonymous || ts.token.IsZero() {
		return 0, ErrNotAuthenticated
	}
	if ts.expiry.IsZero() {
		return 0, nil
	}
	if d := time.Until(ts.expiry); d > 0 {
		return d, nil
	}
	return 0, nil
}

// RefreshToken exchanges the current credential for a fresh user token.
//
// Phase 1 provides only the shell: it validates session state and reports
// ErrNotRefreshable, because minting a token requires the authentication flows
// implemented in Phase 2. Phase 2 replaces this body with the single-flight,
// epoch-scoped refresh described in the plan.
func (c *Client) RefreshToken(_ context.Context) error {
	if c.isClosed() {
		return ErrClosed
	}
	ts := c.token.Load()
	if ts == nil || ts.anonymous {
		return ErrNotAuthenticated
	}
	return ErrNotRefreshable
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
