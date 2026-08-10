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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// PKCE non-interactive ("headless") login reproduces the multi-step RSTS form
// controller that SafeguardDotNet and PySafeguard drive without a browser: the
// client generates its own PKCE verifier/challenge and CSRF token, walks the
// numbered LoginController steps to obtain an OAuth authorization code, exchanges
// that code for an RSTS access token, and finally exchanges the RSTS token for a
// Safeguard user token. It is the preferred flow for test automation because it
// does not require the Resource Owner Grant (which appliances often disable).

const (
	// pkceRedirectURI is the redirect URI registered for the headless installed
	// application flow. It is a URN, not a real callback: the authorization code
	// is returned in the RelyingPartyUrl of the final form step rather than by a
	// browser redirect.
	pkceRedirectURI = "urn:InstalledApplication"

	// loginControllerPath is the RSTS form controller, relative to /RSTS.
	loginControllerPath = "UserLogin/LoginController"

	// The RSTS form controller is a numbered state machine. The steps are always
	// driven in the order init, primary, (secondary-init, secondary-auth if MFA
	// is required), generate-claims; the numeric values are the appliance's, not
	// a sequence.
	pkceStepInit           = "1"
	pkceStepPrimaryAuth    = "3"
	pkceStepSecondaryInit  = "7"
	pkceStepSecondaryAuth  = "5"
	pkceStepGenerateClaims = "6"

	// csrfCookieName is the cookie the appliance compares against the
	// csrfTokenTextbox form field to defeat cross-site request forgery.
	csrfCookieName = "CsrfToken"

	// codeVerifierBytes and csrfTokenBytes are the random-material sizes used by
	// the reference SDKs before base64url encoding.
	codeVerifierBytes = 60
	csrfTokenBytes    = 32

	// mfaFailedStatus is the non-standard HTTP status the RSTS form controller
	// returns when a secondary authentication code is rejected.
	mfaFailedStatus = 203
)

// SecondaryFactorProvider supplies a multi-factor one-time code given the
// appliance's human-readable prompt. It is invoked only when the primary login
// step reports that a secondary provider is required. Returning an error aborts
// the login. The returned bytes are zeroed by the caller after use.
type SecondaryFactorProvider func(ctx context.Context, prompt string) ([]byte, error)

// authorizationCodeGrant is the RSTS oauth2/token body that exchanges a PKCE
// authorization code for an access token. No client_id is sent; the reference
// SDKs omit it and the appliance supplies the built-in application identity.
type authorizationCodeGrant struct {
	GrantType    string `json:"grant_type"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// LoginPKCE performs the PKCE non-interactive (headless) login and returns the
// Safeguard user token. provider selects the RSTS directory (empty defaults to
// the local provider); username and password are the primary credentials.
// secondary, when non-nil, is consulted if the appliance requires multi-factor
// authentication; when the appliance requires it and secondary is nil, the login
// fails with ErrSecondaryFactorRequired.
func LoginPKCE(ctx context.Context, cfg Config, provider, username string, password []byte, secondary SecondaryFactorProvider) ([]byte, error) {
	ctx = ensureCtx(ctx)
	if cfg.HTTPClient == nil {
		return nil, errNilHTTPClient
	}

	verifier, err := randomBase64URL(codeVerifierBytes)
	if err != nil {
		return nil, err
	}
	defer zero(verifier)
	csrf, err := randomBase64URL(csrfTokenBytes)
	if err != nil {
		return nil, err
	}

	directory := resolveProviderID(ctx, cfg, cfg.HTTPClient, provider, "local")

	form := &pkceForm{
		cfg:         cfg,
		client:      cfg.HTTPClient,
		challenge:   codeChallenge(verifier),
		redirectURI: pkceRedirectURI,
		cookies:     map[string]string{csrfCookieName: string(csrf)},
	}

	baseFields := url.Values{}
	baseFields.Set("directoryComboBox", directory)
	baseFields.Set("usernameTextbox", username)
	baseFields.Set("passwordTextbox", string(password))
	baseFields.Set("csrfTokenTextbox", string(csrf))

	code, err := form.acquireCode(ctx, baseFields, secondary)
	if err != nil {
		return nil, err
	}

	rstsToken, err := postRSTSGrant(ctx, cfg, cfg.HTTPClient, authorizationCodeGrant{
		GrantType:    "authorization_code",
		RedirectURI:  pkceRedirectURI,
		Code:         code,
		CodeVerifier: string(verifier),
	})
	if err != nil {
		return nil, err
	}
	defer zero(rstsToken)

	return exchangeRSTSToken(ctx, cfg, cfg.HTTPClient, rstsToken)
}

// acquireCode walks the RSTS form controller (init, primary, optional secondary,
// generate-claims) and returns the OAuth authorization code from the final
// RelyingPartyUrl. It is shared by the headless PKCE login and the browser
// add-on's end-to-end tests, which drive the same controller with the
// TCP-listener redirect.
func (p *pkceForm) acquireCode(ctx context.Context, baseFields url.Values, secondary SecondaryFactorProvider) (string, error) {
	if _, err := p.step(ctx, pkceStepInit, baseFields, "pkce init"); err != nil {
		return "", err
	}

	primary, err := p.step(ctx, pkceStepPrimaryAuth, baseFields, "pkce primary authentication")
	if err != nil {
		return "", err
	}

	if providerID := jsonField(primary, "SecondaryProviderID"); providerID != "" {
		if err := p.runSecondary(ctx, baseFields, secondary); err != nil {
			return "", err
		}
	}

	claims, err := p.step(ctx, pkceStepGenerateClaims, baseFields, "pkce generate claims")
	if err != nil {
		return "", err
	}
	relyingParty := jsonField(claims, "RelyingPartyUrl")
	if relyingParty == "" {
		return "", &RequestError{Op: "pkce generate claims", Err: ErrMissingToken, body: bound(claims)}
	}
	code, err := extractAuthorizationCode(relyingParty)
	if err != nil {
		return "", &RequestError{Op: "pkce generate claims", Err: err, body: bound(claims)}
	}
	return code, nil
}

// runSecondary drives the multi-factor steps: it initializes the secondary
// provider (step 7), obtains the one-time code from secondary, and submits it
// (step 5). A nil secondary means the caller cannot satisfy the challenge.
func (p *pkceForm) runSecondary(ctx context.Context, base url.Values, secondary SecondaryFactorProvider) error {
	if secondary == nil {
		return &RequestError{Op: "pkce primary authentication", Err: ErrSecondaryFactorRequired}
	}

	init, err := p.step(ctx, pkceStepSecondaryInit, base, "pkce secondary initialization")
	if err != nil {
		return err
	}
	state := jsonField(init, "State")
	prompt := jsonField(init, "Message")

	code, err := secondary(ctx, prompt)
	if err != nil {
		return &RequestError{Op: "pkce secondary authentication", Err: err}
	}

	fields := cloneValues(base)
	fields.Set("secondaryLoginTextbox", string(code))
	fields.Set("secondaryAuthenticationStateTextbox", state)
	zero(code)

	status, body, err := p.post(ctx, pkceStepSecondaryAuth, fields)
	if err != nil {
		return &RequestError{Op: "pkce secondary authentication", Err: err}
	}
	if status == mfaFailedStatus {
		return &RequestError{
			Op:         "pkce secondary authentication",
			StatusCode: status,
			Err:        fmt.Errorf("%w: %s", ErrSecondaryFactorFailed, jsonField(body, "Message")),
			body:       bound(body),
		}
	}
	if status < 200 || status >= 300 {
		return &RequestError{Op: "pkce secondary authentication", StatusCode: status, body: bound(body)}
	}
	return nil
}

// pkceForm carries the per-login state for the RSTS form controller: the PKCE
// challenge echoed in every step's query string and the cookies (seeded with the
// CSRF token) threaded across steps. The injected HTTP transport has no cookie
// jar, so the flow tracks cookies itself.
type pkceForm struct {
	cfg         Config
	client      HTTPClient
	challenge   string
	redirectURI string
	port        int
	cookies     map[string]string
}

// step posts one LoginController step and requires a 2xx response, returning the
// response body. op names the step for error reporting.
func (p *pkceForm) step(ctx context.Context, step string, fields url.Values, op string) ([]byte, error) {
	status, body, err := p.post(ctx, step, fields)
	if err != nil {
		return nil, &RequestError{Op: op, Err: err}
	}
	if status < 200 || status >= 300 {
		return nil, &RequestError{Op: op, StatusCode: status, body: bound(body)}
	}
	return body, nil
}

// post issues a single form-encoded LoginController POST for the given step,
// threading cookies in and harvesting any Set-Cookie values out. It returns the
// raw status and body so callers can handle non-2xx statuses (such as the MFA
// 203) themselves.
func (p *pkceForm) post(ctx context.Context, step string, fields url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.stepURL(step), strings.NewReader(fields.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cookie := p.cookieHeader(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	p.harvestCookies(resp)
	return resp.StatusCode, body, nil
}

// stepURL builds the LoginController URL for a step, carrying the fixed PKCE
// query parameters and the step number.
func (p *pkceForm) stepURL(step string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("code_challenge_method", "S256")
	q.Set("code_challenge", p.challenge)
	q.Set("redirect_uri", p.redirectURI)
	if p.port != 0 {
		q.Set("port", strconv.Itoa(p.port))
	}
	q.Set("loginRequestStep", step)
	return p.cfg.rstsURL(loginControllerPath) + "?" + q.Encode()
}

// cookieHeader renders the tracked cookies as a Cookie header value. Names are
// sorted so the header is deterministic (which keeps tests stable); the server
// does not depend on cookie order.
func (p *pkceForm) cookieHeader() string {
	if len(p.cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(p.cookies))
	for name, value := range p.cookies {
		parts = append(parts, name+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// harvestCookies records Set-Cookie values from a response so later steps resend
// them, mirroring the reference SDKs' cookie container. Cookie deletions (empty
// values) are ignored.
func (p *pkceForm) harvestCookies(resp *http.Response) {
	for _, c := range resp.Cookies() {
		if c.Value == "" {
			continue
		}
		p.cookies[c.Name] = c.Value
	}
}

// extractAuthorizationCode pulls the authorization code from the code query
// parameter of the RelyingPartyUrl returned by the generate-claims step.
func extractAuthorizationCode(relyingPartyURL string) (string, error) {
	u, err := url.Parse(relyingPartyURL)
	if err != nil {
		return "", fmt.Errorf("parse relying party url: %w", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", ErrMissingToken
	}
	return code, nil
}

// randomBase64URL returns n cryptographically random bytes encoded as base64url
// without padding, matching the reference SDKs' verifier and CSRF encoding. The
// random bytes are zeroed before returning the encoded form.
func randomBase64URL(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, &RequestError{Op: "pkce setup", Err: err}
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	zero(b)
	return []byte(encoded), nil
}

// codeChallenge derives the S256 PKCE challenge from a verifier: the base64url
// (no padding) encoding of the SHA-256 digest of the verifier's ASCII bytes.
func codeChallenge(verifier []byte) string {
	sum := sha256.Sum256(verifier)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jsonField returns the string value of a top-level field in a JSON object body,
// or the empty string when the body is not an object, the field is absent, or
// the field is not a string (for example a JSON null).
func jsonField(body []byte, key string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// cloneValues returns an independent copy of v so per-step additions (the MFA
// fields) do not mutate the shared base form.
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for key, values := range v {
		cp := make([]string, len(values))
		copy(cp, values)
		out[key] = cp
	}
	return out
}
