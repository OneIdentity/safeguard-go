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

// Package auth is the internal Safeguard authentication broker. It runs the
// two-step RSTS-then-LoginResponse login for every credential strategy and
// returns a Safeguard user token.
//
// This package imports neither the root safeguard package nor the browser and
// devicecode add-on packages, so there is no import cycle: the root package and
// the add-ons call in with a host, an API version, and ready-built HTTP
// transports (as Doer values), and receive a user token out. It knows the RSTS
// and Core wire protocol; it knows nothing about the public Client, Secret, or
// Option types.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Doer performs HTTP requests. The root package satisfies it with an *http.Client
// bound to a particular TLS identity (server-trust for password and PKCE flows,
// a client-certificate transport for certificate login), so the broker never
// builds transports or decides TLS policy itself.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config carries everything a login flow needs from the caller. Doer is the
// server-trust transport used by password, PKCE, and token-exchange calls;
// CertDoer is the client-certificate transport used by certificate login and is
// required only for LoginCertificate.
type Config struct {
	// Host is the appliance host. It may include a scheme; https is assumed when
	// absent. A trailing slash is ignored.
	Host string
	// APIVersion is the Core API version segment, for example "v4".
	APIVersion string
	// Doer is the server-trust HTTP transport. It must not be nil.
	Doer Doer
	// CertDoer is the client-certificate HTTP transport, required only for
	// certificate login.
	CertDoer Doer
}

// schemeHost splits a possibly scheme-prefixed host into its scheme (including
// the "://") and bare host, defaulting to https. It mirrors the root package's
// Service.baseURL normalization so URLs are built identically.
func (c Config) schemeHost() (string, string) {
	scheme := "https://"
	h := c.Host
	if i := strings.Index(h, "://"); i >= 0 {
		scheme = h[:i+3]
		h = h[i+3:]
	}
	return scheme, strings.Trim(h, "/")
}

// rstsURL builds an absolute RSTS URL. RSTS has no version segment.
func (c Config) rstsURL(path string) string {
	scheme, host := c.schemeHost()
	return fmt.Sprintf("%s%s/RSTS/%s", scheme, host, strings.TrimLeft(path, "/"))
}

// coreURL builds an absolute Core service URL including the API version segment.
func (c Config) coreURL(path string) string {
	scheme, host := c.schemeHost()
	v := strings.Trim(c.APIVersion, "/")
	if v == "" {
		v = "v4"
	}
	return fmt.Sprintf("%s%s/service/core/%s/%s", scheme, host, v, strings.TrimLeft(path, "/"))
}

// ensureCtx guards against a nil context so the broker never panics deep in a flow.
func ensureCtx(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
