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
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

// Interactive OAuth flows drive the appliance's RSTS OAuth2 endpoints the way a
// human at a browser would. Unlike the headless PKCE flow (pkce.go), which walks
// the RSTS form controller itself, these flows delegate the human step to an
// add-on package: the browser package opens a system browser and captures the
// redirect, and the devicecode package prints a user code and polls. This file
// owns only the wire protocol (URL construction, token exchange, and device-code
// polling); it launches no browser and prints nothing, so the headless consumers
// of this package never compile that machinery in.

const (
	// browserRedirectURI is the redirect URI the external-browser flow registers.
	// It is a URN rather than a real callback: the actual loopback TCP port is
	// carried in the port query parameter, and the authorization code is returned
	// to that listener. It differs from pkceRedirectURI, which names the headless
	// installed-application flow.
	browserRedirectURI = "urn:InstalledApplicationTcpListener"

	// browserLoginPath is the RSTS authorize endpoint for the browser flow,
	// relative to /RSTS.
	browserLoginPath = "Login"

	// deviceLoginPath is the RSTS device-authorization endpoint, relative to
	// /RSTS. It has no trailing slash and no API version segment.
	deviceLoginPath = "oauth2/DeviceLogin"

	// deviceCodeGrantType is the OAuth device-authorization grant identifier used
	// when polling the token endpoint.
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// deviceScope is the RSTS scope requested for a device-code login. It pins the
	// primary local provider, matching SafeguardDotNet and PySafeguard.
	deviceScope = "rsts:sts:primaryproviderid:local"

	// deviceDefaultExpiresIn is the polling lifetime assumed when the device
	// authorization response omits expires_in.
	deviceDefaultExpiresIn = 300 * time.Second

	// deviceDefaultInterval is the polling interval assumed when none is supplied;
	// the RSTS device response does not carry one.
	deviceDefaultInterval = 5 * time.Second

	// deviceSlowDownIncrement is added to the polling interval each time the
	// appliance answers a poll with slow_down.
	deviceSlowDownIncrement = 5 * time.Second
)

// PKCEPair is a PKCE code verifier and its derived S256 challenge for a single
// interactive login. The verifier is short-lived: the browser package holds it
// only between building the authorize URL and redeeming the authorization code.
type PKCEPair struct {
	// Verifier is the base64url (no padding) code verifier sent in the token
	// exchange. It must never be placed in the authorize URL.
	Verifier string
	// Challenge is the base64url (no padding) S256 challenge placed in the
	// authorize URL.
	Challenge string
}

// NewPKCEPair generates a fresh PKCE verifier and its S256 challenge using the
// same random-material size as the headless flow.
func NewPKCEPair() (PKCEPair, error) {
	verifier, err := randomBase64URL(codeVerifierBytes)
	if err != nil {
		return PKCEPair{}, err
	}
	defer zero(verifier)
	return PKCEPair{Verifier: string(verifier), Challenge: codeChallenge(verifier)}, nil
}

// BrowserAuthorizeURL builds the RSTS authorize URL the browser flow opens. port
// is the loopback TCP port the add-on is listening on for the redirect; username,
// when non-empty, is passed as login_hint to pre-fill the appliance login form.
// No client_id, scope, or state is sent, matching the reference SDKs.
func BrowserAuthorizeURL(cfg Config, challenge string, port int, username string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("code_challenge_method", "S256")
	q.Set("code_challenge", challenge)
	q.Set("redirect_uri", browserRedirectURI)
	q.Set("port", strconv.Itoa(port))
	if username != "" {
		q.Set("login_hint", username)
	}
	return cfg.rstsURL(browserLoginPath) + "?" + q.Encode()
}

// RedeemBrowserCode exchanges an authorization code captured by the browser flow
// for a Safeguard user token: it redeems the code for an RSTS access token over
// httpClient and then performs the Core LoginResponse exchange. verifier is the
// PKCE verifier whose challenge was placed in the authorize URL.
func RedeemBrowserCode(ctx context.Context, cfg Config, httpClient HTTPClient, code, verifier string) ([]byte, error) {
	ctx = ensureCtx(ctx)
	if httpClient == nil {
		return nil, errNilHTTPClient
	}
	rstsToken, err := postRSTSGrant(ctx, cfg, httpClient, authorizationCodeGrant{
		GrantType:    "authorization_code",
		RedirectURI:  browserRedirectURI,
		Code:         code,
		CodeVerifier: verifier,
	})
	if err != nil {
		return nil, err
	}
	defer zero(rstsToken)
	return exchangeRSTSToken(ctx, cfg, httpClient, rstsToken)
}

// deviceAuthRequest is the RSTS device-authorization body. client_id must be the
// empty string: RSTS normalizes it to its built-in application identity, and a
// non-empty value breaks the pre-filled verification URI.
type deviceAuthRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// deviceTokenRequest is the RSTS token-endpoint body polled during a device-code
// login. client_id is empty for the same reason as deviceAuthRequest.
type deviceTokenRequest struct {
	GrantType  string `json:"grant_type"`
	DeviceCode string `json:"device_code"`
	ClientID   string `json:"client_id"`
}

// DeviceCodeChallenge is the result of starting a device-code login: the codes
// and URIs shown to the user, the opaque device code used for polling, and the
// interval and lifetime that bound the poll loop.
type DeviceCodeChallenge struct {
	// DeviceCode is the opaque code presented back to the token endpoint while
	// polling. It is not shown to the user.
	DeviceCode string
	// UserCode is the short code the user enters at the verification URI.
	UserCode string
	// VerificationURI is where the user goes to enter the user code.
	VerificationURI string
	// VerificationURIComplete is the verification URI with the user code embedded,
	// suitable for a QR code or direct link.
	VerificationURIComplete string
	// Interval is how long to wait between polls.
	Interval time.Duration
	// ExpiresIn is how long the user code remains valid.
	ExpiresIn time.Duration
}

// StartDeviceCode begins a device-code login by requesting a device
// authorization from RSTS. The returned challenge carries the codes to display
// and the timing that bounds PollDeviceCode.
func StartDeviceCode(ctx context.Context, cfg Config, httpClient HTTPClient) (DeviceCodeChallenge, error) {
	ctx = ensureCtx(ctx)
	if httpClient == nil {
		return DeviceCodeChallenge{}, errNilHTTPClient
	}
	status, body, err := postJSON(ctx, httpClient, cfg.rstsURL(deviceLoginPath), deviceAuthRequest{
		ClientID: "",
		Scope:    deviceScope,
	})
	if err != nil {
		return DeviceCodeChallenge{}, &RequestError{Op: "device authorization", Err: err}
	}
	if status < 200 || status >= 300 {
		return DeviceCodeChallenge{}, &RequestError{Op: "device authorization", StatusCode: status, body: bound(body)}
	}
	var parsed struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.DeviceCode == "" {
		return DeviceCodeChallenge{}, &RequestError{Op: "device authorization", StatusCode: status, Err: ErrMissingToken, body: bound(body)}
	}

	expires := deviceDefaultExpiresIn
	if parsed.ExpiresIn > 0 {
		expires = time.Duration(parsed.ExpiresIn) * time.Second
	}
	interval := deviceDefaultInterval
	if parsed.Interval > 0 {
		interval = time.Duration(parsed.Interval) * time.Second
	}
	return DeviceCodeChallenge{
		DeviceCode:              parsed.DeviceCode,
		UserCode:                parsed.UserCode,
		VerificationURI:         parsed.VerificationURI,
		VerificationURIComplete: parsed.VerificationURIComplete,
		Interval:                interval,
		ExpiresIn:               expires,
	}, nil
}

// PollDeviceCode polls the RSTS token endpoint until the user completes the
// device-code login, then exchanges the resulting RSTS token for a Safeguard user
// token. It waits interval between polls (honoring a slow_down response by
// backing off) and gives up after expiresIn, returning ErrDeviceCodeExpired on
// timeout or expired_token and ErrDeviceCodeDenied when the user declines. The
// context bounds the whole wait and each poll.
func PollDeviceCode(ctx context.Context, cfg Config, httpClient HTTPClient, deviceCode string, interval, expiresIn time.Duration) ([]byte, error) {
	ctx = ensureCtx(ctx)
	if httpClient == nil {
		return nil, errNilHTTPClient
	}
	if interval <= 0 {
		interval = deviceDefaultInterval
	}
	if expiresIn <= 0 {
		expiresIn = deviceDefaultExpiresIn
	}
	deadline := time.Now().Add(expiresIn)

	for time.Now().Before(deadline) {
		if err := wait(ctx, interval); err != nil {
			return nil, err
		}
		status, body, err := postJSON(ctx, httpClient, cfg.rstsURL(rstsGrantPath), deviceTokenRequest{
			GrantType:  deviceCodeGrantType,
			DeviceCode: deviceCode,
			ClientID:   "",
		})
		if err != nil {
			return nil, &RequestError{Op: "device token poll", Err: err}
		}
		if status >= 200 && status < 300 {
			rstsToken, perr := accessTokenFromBody(body, status)
			if perr != nil {
				return nil, perr
			}
			defer zero(rstsToken)
			return exchangeRSTSToken(ctx, cfg, httpClient, rstsToken)
		}
		switch jsonField(body, "error") {
		case "authorization_pending":
			// The user has not yet finished; keep polling.
		case "slow_down":
			interval += deviceSlowDownIncrement
		case "access_denied":
			return nil, &RequestError{Op: "device token poll", StatusCode: status, Err: ErrDeviceCodeDenied, body: bound(body)}
		case "expired_token":
			return nil, &RequestError{Op: "device token poll", StatusCode: status, Err: ErrDeviceCodeExpired, body: bound(body)}
		default:
			return nil, &RequestError{Op: "device token poll", StatusCode: status, body: bound(body)}
		}
	}
	return nil, &RequestError{Op: "device token poll", Err: ErrDeviceCodeExpired}
}

// accessTokenFromBody extracts the access_token from a successful RSTS token
// response body.
func accessTokenFromBody(body []byte, status int) ([]byte, error) {
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return nil, &RequestError{Op: "device token poll", StatusCode: status, Err: ErrMissingToken, body: bound(body)}
	}
	return []byte(parsed.AccessToken), nil
}

// wait sleeps for d or returns the context's error if it is canceled first.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
