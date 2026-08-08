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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxTokenResponse bounds a successful token/exchange response body so a
// malformed or hostile response cannot exhaust memory. Real responses are a few
// kilobytes (a JWT and a little JSON); one mebibyte is generous.
const maxTokenResponse = 1 << 20

// rstsGrantPath is the RSTS OAuth2 token endpoint, relative to /RSTS. It has no
// API version segment.
const rstsGrantPath = "oauth2/token"

// loginResponsePath is the Core endpoint that exchanges an RSTS access token for
// a Safeguard user token, relative to the versioned Core base.
const loginResponsePath = "Token/LoginResponse"

// providersPath is the anonymous Core endpoint listing authentication providers,
// relative to the versioned Core base.
const providersPath = "AuthenticationProviders"

// passwordGrant is the RSTS Resource Owner Grant body.
type passwordGrant struct {
	GrantType string `json:"grant_type"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}

// clientCredentialsGrant is the RSTS client-credentials body used by certificate
// login; the certificate itself is presented by the mutual-TLS transport.
type clientCredentialsGrant struct {
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
}

// LoginPassword performs a Resource Owner Grant login and returns the Safeguard
// user token. An empty provider defaults to the local scope; a non-empty
// provider is resolved to its RSTS scope.
func LoginPassword(ctx context.Context, cfg Config, provider, username string, password []byte) ([]byte, error) {
	ctx = ensureCtx(ctx)
	scope, err := resolveScope(ctx, cfg, cfg.HTTPClient, provider, "local")
	if err != nil {
		return nil, err
	}
	rstsToken, err := postRSTSGrant(ctx, cfg, cfg.HTTPClient, passwordGrant{
		GrantType: "password",
		Username:  username,
		Password:  string(password),
		Scope:     scope,
	})
	if err != nil {
		return nil, err
	}
	defer zero(rstsToken)
	return exchangeRSTSToken(ctx, cfg, cfg.HTTPClient, rstsToken)
}

// LoginCertificate performs a certificate (client-credentials) login over the
// client-certificate transport and returns the Safeguard user token. An empty
// provider defaults to the certificate scope.
func LoginCertificate(ctx context.Context, cfg Config, provider string) ([]byte, error) {
	ctx = ensureCtx(ctx)
	httpClient := cfg.CertHTTPClient
	scope, err := resolveScope(ctx, cfg, httpClient, provider, "certificate")
	if err != nil {
		return nil, err
	}
	rstsToken, err := postRSTSGrant(ctx, cfg, httpClient, clientCredentialsGrant{
		GrantType: "client_credentials",
		Scope:     scope,
	})
	if err != nil {
		return nil, err
	}
	defer zero(rstsToken)
	return exchangeRSTSToken(ctx, cfg, httpClient, rstsToken)
}

// ExchangeRSTSToken exchanges an already-obtained RSTS access token for a
// Safeguard user token over the server-trust transport. It is used by the
// interactive add-on flows (browser, device code) after they obtain an RSTS
// token through OAuth.
func ExchangeRSTSToken(ctx context.Context, cfg Config, rstsToken []byte) ([]byte, error) {
	return exchangeRSTSToken(ensureCtx(ctx), cfg, cfg.HTTPClient, rstsToken)
}

// postRSTSGrant posts an RSTS grant body and returns the access_token bytes.
func postRSTSGrant(ctx context.Context, cfg Config, httpClient HTTPClient, grant any) ([]byte, error) {
	status, body, err := postJSON(ctx, httpClient, cfg.rstsURL(rstsGrantPath), grant)
	if err != nil {
		return nil, &RequestError{Op: "rsts grant", Err: err}
	}
	if status < 200 || status >= 300 {
		return nil, &RequestError{Op: "rsts grant", StatusCode: status, body: bound(body)}
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return nil, &RequestError{Op: "rsts grant", StatusCode: status, Err: ErrMissingToken, body: bound(body)}
	}
	return []byte(parsed.AccessToken), nil
}

// exchangeRSTSToken performs the Core Token/LoginResponse exchange over httpClient and
// returns the Safeguard user token.
func exchangeRSTSToken(ctx context.Context, cfg Config, httpClient HTTPClient, rstsToken []byte) ([]byte, error) {
	payload := struct {
		StsAccessToken string `json:"StsAccessToken"`
	}{StsAccessToken: string(rstsToken)}

	status, body, err := postJSON(ctx, httpClient, cfg.coreURL(loginResponsePath), payload)
	if err != nil {
		return nil, &RequestError{Op: "login response", Err: err}
	}
	if status < 200 || status >= 300 {
		return nil, &RequestError{Op: "login response", StatusCode: status, body: bound(body)}
	}
	var parsed struct {
		Status    string `json:"Status"`
		UserToken string `json:"UserToken"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &RequestError{Op: "login response", StatusCode: status, Err: ErrMissingToken, body: bound(body)}
	}
	if !strings.EqualFold(parsed.Status, "Success") {
		return nil, &RequestError{Op: "login response", StatusCode: status, Err: ErrLoginResponseFailed, body: bound(body)}
	}
	if parsed.UserToken == "" {
		return nil, &RequestError{Op: "login response", StatusCode: status, Err: ErrMissingToken, body: bound(body)}
	}
	return []byte(parsed.UserToken), nil
}

// postJSON marshals payload as JSON, POSTs it to url through httpClient, and returns
// the status code and the bounded response body. Authentication calls never
// carry an Authorization header: RSTS grants are unauthenticated and certificate
// login authenticates through the mutual-TLS transport.
func postJSON(ctx context.Context, httpClient HTTPClient, url string, payload any) (int, []byte, error) {
	if httpClient == nil {
		return 0, nil, errNilHTTPClient
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// bound returns a copy of b truncated to maxErrorBody for storage in a
// RequestError.
func bound(b []byte) []byte {
	if len(b) > maxErrorBody {
		b = b[:maxErrorBody]
	}
	return append([]byte(nil), b...)
}

// zero best-effort wipes a byte slice holding sensitive material.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
