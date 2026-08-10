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
	"net/http"
)

// LoginTransport is the appliance connection handed to an interactive add-on
// login flow (the browser and devicecode packages). It carries the client's
// server-trust HTTP transport, which already honors the connection's TLS policy
// and timeouts, together with the appliance coordinates a flow needs to build
// RSTS and Core URLs. Its Do method satisfies the internal broker's transport
// interface, so an add-on can pass a LoginTransport straight into the internal
// auth helpers without building its own transport.
type LoginTransport interface {
	// Do issues an HTTP request on the client's server-trust transport.
	Do(req *http.Request) (*http.Response, error)
	// Host is the appliance host the client is bound to.
	Host() string
	// APIVersion is the default Core API version segment, for example "v4".
	APIVersion() string
}

// LoginFunc runs an interactive OAuth login against the appliance using t and
// returns the resulting Safeguard user token. It is implemented by the browser
// and devicecode add-on packages and handed to AuthorizedSession; end users call
// those packages' Connect functions rather than writing a LoginFunc themselves.
// The returned Secret is owned by the SDK after a nil error; the login must not
// retain or zero it.
type LoginFunc func(ctx context.Context, t LoginTransport) (userToken Secret, err error)

// AuthorizedSession returns a credential that completes an interactive OAuth
// login by running login and adopting the Safeguard user token it produces. It
// is the seam the optional browser and devicecode add-on packages use to hand a
// finished authorization back to Connect: because Credential is sealed, an add-on
// cannot implement its own credential, so it supplies its interactive flow as a
// LoginFunc and lets this credential install the result.
//
// The resulting session is intentionally not refreshable, matching SafeguardDotNet
// and PySafeguard, which treat browser and device-code logins as existing-token
// connections that cannot silently re-authenticate: RefreshToken reports
// ErrNotRefreshable and a 401 is surfaced rather than retried. To obtain a new
// token, run the interactive flow again. For a bare, caller-supplied user token
// with no interactive step, use Token instead.
func AuthorizedSession(login LoginFunc) Credential {
	return &authorizedSessionCredential{login: login}
}

// authorizedSessionCredential adopts the user token produced by an interactive
// add-on login flow.
type authorizedSessionCredential struct {
	login LoginFunc
}

func (a *authorizedSessionCredential) establish(ctx context.Context, c *Client) (*session, error) {
	if a.login == nil {
		return nil, errNilLoginFunc
	}
	httpClient, err := c.transports.client(serverTrust)
	if err != nil {
		return nil, err
	}
	token, err := a.login(ctx, loginTransport{doer: httpClient, host: c.host, apiVersion: c.apiVersion})
	if err != nil {
		return nil, translateAuthError(err)
	}
	if token.IsZero() {
		return nil, errEmptyToken
	}
	return &session{token: token, refreshable: false}, nil
}

// loginTransport is the concrete LoginTransport handed to a LoginFunc. It adapts
// the client's server-trust *http.Client and appliance coordinates onto the
// interface the add-on packages consume.
type loginTransport struct {
	doer       *http.Client
	host       string
	apiVersion string
}

func (t loginTransport) Do(req *http.Request) (*http.Response, error) { return t.doer.Do(req) }
func (t loginTransport) Host() string                                 { return t.host }
func (t loginTransport) APIVersion() string                           { return t.apiVersion }
