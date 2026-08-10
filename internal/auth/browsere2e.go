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

package auth

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// AcquireBrowserLoopbackURL drives the RSTS form controller for a browser
// authorize URL and returns the loopback redirect URL, complete with the oauth
// authorization code, that a real system browser would be navigated to after the
// user signs in. It exists so the browser add-on can be exercised end-to-end
// against a live appliance without a human at a browser: a live test supplies a
// browser opener that calls this and then delivers the returned URL to the
// add-on's loopback listener. Production browser login opens a real system
// browser and never calls this.
//
// authorizeURL is the URL BrowserAuthorizeURL produced (it carries the PKCE
// challenge and loopback port). provider selects the RSTS directory (empty
// defaults to the local provider); username and password are the primary
// credentials; secondary, when non-nil, satisfies a multi-factor challenge.
func AcquireBrowserLoopbackURL(ctx context.Context, cfg Config, httpClient HTTPClient, authorizeURL, provider, username string, password []byte, secondary SecondaryFactorProvider) (string, error) {
	ctx = ensureCtx(ctx)
	if httpClient == nil {
		return "", errNilHTTPClient
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		return "", &RequestError{Op: "browser authorize url", Err: fmt.Errorf("parse authorize url: %w", err)}
	}
	q := parsed.Query()
	challenge := q.Get("code_challenge")
	port, err := strconv.Atoi(q.Get("port"))
	if err != nil {
		return "", &RequestError{Op: "browser authorize url", Err: fmt.Errorf("parse port: %w", err)}
	}

	csrf, err := randomBase64URL(csrfTokenBytes)
	if err != nil {
		return "", err
	}
	form := &pkceForm{
		cfg:         cfg,
		client:      httpClient,
		challenge:   challenge,
		redirectURI: browserRedirectURI,
		port:        port,
		cookies:     map[string]string{csrfCookieName: string(csrf)},
	}

	directory := resolveProviderID(ctx, cfg, httpClient, provider, "local")
	fields := url.Values{}
	fields.Set("directoryComboBox", directory)
	fields.Set("usernameTextbox", username)
	fields.Set("passwordTextbox", string(password))
	fields.Set("csrfTokenTextbox", string(csrf))

	code, err := form.acquireCode(ctx, fields, secondary)
	if err != nil {
		return "", err
	}

	loopback := url.URL{
		Scheme:   "http",
		Host:     "127.0.0.1:" + strconv.Itoa(port),
		Path:     "/",
		RawQuery: url.Values{"oauth": {code}}.Encode(),
	}
	return loopback.String(), nil
}
