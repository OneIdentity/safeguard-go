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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"sync"
	"time"
)

// tlsIdentity is the TLS-identity axis of a request. Connection pools are keyed
// by this value, never by the authorization mode, because headers are
// request-scoped while the TLS identity is a property of the transport.
type tlsIdentity int

const (
	// serverTrust presents no client certificate and verifies the server per the
	// configured TLS validation mode. It is used for all standard calls.
	serverTrust tlsIdentity = iota
	// clientCert presents a client certificate (certificate login, A2A). The
	// certificate material is configured in Phase 2/3.
	clientCert
)

// authKind is the authorization axis of a request.
type authKind int

const (
	// authNone sends no Authorization header (anonymous/notification, RSTS, login).
	authNone authKind = iota
	// authUserToken sends a Safeguard user token as a Bearer credential.
	authUserToken
	// authA2A sends an A2A API key credential.
	authA2A
)

// authorization is the request-scoped authorization axis value. It is chosen
// independently of the TLS identity, which is what lets A2A pair a client
// certificate with either an API key or a user token.
type authorization struct {
	kind   authKind
	token  Secret
	apiKey Secret
}

// noAuth returns an anonymous authorization.
func noAuth() authorization { return authorization{kind: authNone} }

// userTokenAuth returns an authorization carrying a Safeguard user token.
func userTokenAuth(token Secret) authorization {
	return authorization{kind: authUserToken, token: token}
}

// a2aAuth returns an authorization carrying an A2A API key.
func a2aAuth(apiKey Secret) authorization {
	return authorization{kind: authA2A, apiKey: apiKey}
}

// headerValue returns the Authorization header value for this authorization, or
// the empty string for anonymous requests.
func (a authorization) headerValue() string {
	switch a.kind {
	case authUserToken:
		if a.token.IsZero() {
			return ""
		}
		return "Bearer " + a.token.ExposeString()
	case authA2A:
		if a.apiKey.IsZero() {
			return ""
		}
		return "A2A " + a.apiKey.ExposeString()
	default:
		return ""
	}
}

// transportSet holds one *http.Client per TLS identity, all built from the same
// shared TLS configuration and timeouts. Pools are isolated by TLS identity;
// authorization headers are applied per request and never influence pooling.
type transportSet struct {
	mu          sync.Mutex
	tlsConfig   *tls.Config
	timeouts    Timeouts
	clientCerts []tls.Certificate
	clients     map[tlsIdentity]*http.Client
	closed      bool
}

// newTransportSet returns a transportSet using tlsConfig and timeouts.
func newTransportSet(tlsConfig *tls.Config, timeouts Timeouts) *transportSet {
	return &transportSet{
		tlsConfig: tlsConfig,
		timeouts:  timeouts.orDefault(),
		clients:   make(map[tlsIdentity]*http.Client),
	}
}

// client returns the *http.Client for id, building it lazily. Clients never
// follow redirects: a 3xx is surfaced, not chased, so a client-certificate
// transport can never present its certificate to a redirected host.
func (ts *transportSet) client(id tlsIdentity) (*http.Client, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.closed {
		return nil, ErrClosed
	}
	if c, ok := ts.clients[id]; ok {
		return c, nil
	}

	tc := ts.tlsConfig.Clone()
	if id == clientCert {
		if len(ts.clientCerts) == 0 {
			return nil, errNoClientCert
		}
		tc.Certificates = ts.clientCerts
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   ts.timeouts.TLSHandshake,
		ResponseHeaderTimeout: ts.timeouts.ResponseHeader,
		DialContext: (&net.Dialer{
			Timeout:   ts.timeouts.Dial,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	c := &http.Client{
		Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ts.clients[id] = c
	return c, nil
}

// do sends req on the transport for id and returns the response, wrapping
// network/TLS failures in a TransportError with credentials redacted.
func (ts *transportSet) do(id tlsIdentity, req *http.Request) (*http.Response, error) {
	c, err := ts.client(id)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, &TransportError{Op: "request", Err: sanitizeError(err)}
	}
	return resp, nil
}

// Close closes idle connections on every pool and marks the set closed. In-place
// certificate replacement (Phase 2/3) rebuilds affected transports rather than
// relying on CloseIdleConnections alone.
func (ts *transportSet) Close() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.closed = true
	for _, c := range ts.clients {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	ts.clients = make(map[tlsIdentity]*http.Client)
}

// buildHTTPRequest constructs an *http.Request applying additional headers, the
// Accept header, and the authorization axis. A caller-supplied Authorization
// header is never honored here; the transport axis owns it exclusively.
func buildHTTPRequest(ctx context.Context, method HTTPMethod, urlStr string, body io.Reader, auth authorization, accept string, headers http.Header) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, string(method), urlStr, body)
	if err != nil {
		return nil, &TransportError{Op: "build-request", Err: sanitizeError(err)}
	}
	for k, vs := range headers {
		if textproto.CanonicalMIMEHeaderKey(k) == "Authorization" {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	if av := auth.headerValue(); av != "" {
		req.Header.Set("Authorization", av)
	}
	return req, nil
}

// sanitizeError removes potentially sensitive material (query strings that could
// carry credentials) from transport errors before they are surfaced or logged.
func sanitizeError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			u.RawQuery = ""
			u.User = nil
			ue.URL = u.String()
		}
	}
	return err
}
