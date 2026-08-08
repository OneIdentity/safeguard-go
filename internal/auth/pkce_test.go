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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakePKCE mimics the RSTS form LoginController plus the oauth2/token and Core
// LoginResponse endpoints exercised by the PKCE headless flow.
type fakePKCE struct {
	t *testing.T

	requireMFA  bool // primary step reports a secondary provider
	mfaCode     string
	authCode    string
	userToken   string
	rejectMFA   bool   // secondary step answers 203
	dropCSRF    bool   // do not echo the CSRF cookie back on init
	claimsExtra string // override RelyingPartyUrl query, e.g. drop the code

	providers []provider // served from AuthenticationProviders when non-nil

	// captured for assertions
	steps            []string
	primaryCSRFField string
	primaryCSRFCooky string
	challenge        string
	directoryField   string
	secondaryCode    string
	secondaryState   string
	grantCode        string
	grantVerifier    string
}

func (f *fakePKCE) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/RSTS/UserLogin/LoginController"):
			f.serveController(w, r)
		case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
			f.serveGrant(w, r)
		case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
			f.serveLogin(w, r)
		case strings.HasSuffix(r.URL.Path, "/AuthenticationProviders"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.providers)
		default:
			f.t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (f *fakePKCE) serveController(w http.ResponseWriter, r *http.Request) {
	step := r.URL.Query().Get("loginRequestStep")
	f.steps = append(f.steps, step)
	f.challenge = r.URL.Query().Get("code_challenge")
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		f.t.Errorf("step %s Content-Type = %q, want form encoded", step, ct)
	}
	if err := r.ParseForm(); err != nil {
		f.t.Fatalf("parse form: %v", err)
	}
	if v := r.PostForm.Get("directoryComboBox"); v != "" {
		f.directoryField = v
	}

	w.Header().Set("Content-Type", "application/json")
	switch step {
	case pkceStepInit:
		f.primaryCSRFField = r.PostForm.Get("csrfTokenTextbox")
		if c, err := r.Cookie(csrfCookieName); err == nil {
			f.primaryCSRFCooky = c.Value
		}
		if !f.dropCSRF {
			http.SetCookie(w, &http.Cookie{Name: "RSTS-Session", Value: "sess-1", Path: "/RSTS"})
		}
		_, _ = io.WriteString(w, `{"Message":"init"}`)
	case pkceStepPrimaryAuth:
		if f.requireMFA {
			_, _ = io.WriteString(w, `{"SecondaryProviderID":"radius-1"}`)
			return
		}
		_, _ = io.WriteString(w, `{"SecondaryProviderID":""}`)
	case pkceStepSecondaryInit:
		_, _ = io.WriteString(w, `{"State":"mfa-state-xyz","Message":"Enter your one-time code"}`)
	case pkceStepSecondaryAuth:
		f.secondaryCode = r.PostForm.Get("secondaryLoginTextbox")
		f.secondaryState = r.PostForm.Get("secondaryAuthenticationStateTextbox")
		if f.rejectMFA {
			w.WriteHeader(mfaFailedStatus)
			_, _ = io.WriteString(w, `{"Message":"Invalid one-time code"}`)
			return
		}
		_, _ = io.WriteString(w, `{"Message":"ok"}`)
	case pkceStepGenerateClaims:
		query := "code=" + f.authCode
		if f.claimsExtra != "" {
			query = f.claimsExtra
		}
		relying := pkceRedirectURI + "?" + query
		_ = json.NewEncoder(w).Encode(map[string]string{"RelyingPartyUrl": relying})
	default:
		f.t.Errorf("unexpected login step %q", step)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *fakePKCE) serveGrant(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var grant map[string]any
	if err := json.Unmarshal(body, &grant); err != nil {
		f.t.Errorf("grant body not JSON: %v", err)
	}
	if grant["grant_type"] != "authorization_code" {
		f.t.Errorf("grant_type = %v, want authorization_code", grant["grant_type"])
	}
	if r.Header.Get("Cookie") != "" {
		f.t.Errorf("oauth2/token exchange must not carry cookies")
	}
	f.grantCode, _ = grant["code"].(string)
	f.grantVerifier, _ = grant["code_verifier"].(string)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "rsts-access-token"})
}

func (f *fakePKCE) serveLogin(w http.ResponseWriter, _ *http.Request) {
	token := f.userToken
	if token == "" {
		token = "user-token"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"Status": "Success", "UserToken": token})
}

func newFakePKCEConfig(t *testing.T, f *fakePKCE) (Config, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(f.handler())
	client := srv.Client()
	cfg := Config{
		Host:           strings.TrimPrefix(srv.URL, "https://"),
		APIVersion:     "v4",
		HTTPClient:     client,
		CertHTTPClient: client,
	}
	return cfg, srv.Close
}

func TestLoginPKCEHappyPath(t *testing.T) {
	f := &fakePKCE{t: t, authCode: "auth-code-123", userToken: "pkce-user-token"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	token, err := LoginPKCE(context.Background(), cfg, "", "admin", []byte("Admin123"), nil)
	if err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}
	if string(token) != "pkce-user-token" {
		t.Fatalf("token = %q, want pkce-user-token", token)
	}
	wantSteps := []string{pkceStepInit, pkceStepPrimaryAuth, pkceStepGenerateClaims}
	if strings.Join(f.steps, ",") != strings.Join(wantSteps, ",") {
		t.Errorf("steps = %v, want %v", f.steps, wantSteps)
	}
	if f.grantCode != "auth-code-123" {
		t.Errorf("grant code = %q, want auth-code-123", f.grantCode)
	}
	if f.grantVerifier == "" {
		t.Error("code_verifier not forwarded to token exchange")
	}
	if got := base64.RawURLEncoding.EncodeToString(hashString(f.grantVerifier)); got != f.challenge {
		t.Errorf("challenge %q is not S256(verifier)", f.challenge)
	}
}

func TestLoginPKCECSRFBinding(t *testing.T) {
	f := &fakePKCE{t: t, authCode: "c", userToken: "tok"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	if _, err := LoginPKCE(context.Background(), cfg, "", "u", []byte("p"), nil); err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}
	if f.primaryCSRFField == "" {
		t.Fatal("csrfTokenTextbox field was empty")
	}
	if f.primaryCSRFField != f.primaryCSRFCooky {
		t.Errorf("CSRF field %q != cookie %q", f.primaryCSRFField, f.primaryCSRFCooky)
	}
}

func TestLoginPKCEDefaultsProvider(t *testing.T) {
	f := &fakePKCE{t: t, authCode: "c", userToken: "tok"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	// An empty provider defaults to the local provider without a lookup.
	if _, err := LoginPKCE(context.Background(), cfg, "  ", "u", []byte("p"), nil); err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}
	if f.directoryField != "local" {
		t.Errorf("directoryComboBox = %q, want local", f.directoryField)
	}
}

func TestLoginPKCEResolvesProvider(t *testing.T) {
	providers := []provider{
		{Name: "Local", RstsProviderID: "local", RstsProviderScope: "rsts:sts:primaryproviderid:local"},
		{Name: "Corp AD", RstsProviderID: "ad-1234", RstsProviderScope: "rsts:sts:primaryproviderid:ad-1234"},
	}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"display name resolves to id", "Corp AD", "ad-1234"},
		{"exact id passes through", "ad-1234", "ad-1234"},
		{"substring of id", "1234", "ad-1234"},
		{"unknown falls back to input", "vault-x", "vault-x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakePKCE{t: t, providers: providers, authCode: "c", userToken: "tok"}
			cfg, done := newFakePKCEConfig(t, f)
			defer done()

			if _, err := LoginPKCE(context.Background(), cfg, tc.input, "u", []byte("p"), nil); err != nil {
				t.Fatalf("LoginPKCE: %v", err)
			}
			if f.directoryField != tc.want {
				t.Errorf("directoryComboBox = %q, want %q", f.directoryField, tc.want)
			}
		})
	}
}

func TestLoginPKCESecondaryFactor(t *testing.T) {
	f := &fakePKCE{t: t, requireMFA: true, mfaCode: "999111", authCode: "c", userToken: "mfa-tok"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	var gotPrompt string
	secondary := func(_ context.Context, prompt string) ([]byte, error) {
		gotPrompt = prompt
		return []byte("999111"), nil
	}

	token, err := LoginPKCE(context.Background(), cfg, "", "admin", []byte("Admin123"), secondary)
	if err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}
	if string(token) != "mfa-tok" {
		t.Errorf("token = %q, want mfa-tok", token)
	}
	wantSteps := []string{pkceStepInit, pkceStepPrimaryAuth, pkceStepSecondaryInit, pkceStepSecondaryAuth, pkceStepGenerateClaims}
	if strings.Join(f.steps, ",") != strings.Join(wantSteps, ",") {
		t.Errorf("steps = %v, want %v", f.steps, wantSteps)
	}
	if gotPrompt != "Enter your one-time code" {
		t.Errorf("prompt = %q, want the appliance message", gotPrompt)
	}
	if f.secondaryCode != "999111" {
		t.Errorf("secondaryLoginTextbox = %q, want 999111", f.secondaryCode)
	}
	if f.secondaryState != "mfa-state-xyz" {
		t.Errorf("secondaryAuthenticationStateTextbox = %q, want mfa-state-xyz", f.secondaryState)
	}
}

func TestLoginPKCESecondaryRequiredButMissing(t *testing.T) {
	f := &fakePKCE{t: t, requireMFA: true, authCode: "c"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	_, err := LoginPKCE(context.Background(), cfg, "", "u", []byte("p"), nil)
	if !errors.Is(err, ErrSecondaryFactorRequired) {
		t.Fatalf("error = %v, want ErrSecondaryFactorRequired", err)
	}
}

func TestLoginPKCESecondaryRejected(t *testing.T) {
	f := &fakePKCE{t: t, requireMFA: true, rejectMFA: true, authCode: "c"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	secondary := func(_ context.Context, _ string) ([]byte, error) {
		return []byte("000000"), nil
	}
	_, err := LoginPKCE(context.Background(), cfg, "", "u", []byte("p"), secondary)
	if !errors.Is(err, ErrSecondaryFactorFailed) {
		t.Fatalf("error = %v, want ErrSecondaryFactorFailed", err)
	}
}

func TestLoginPKCEMissingAuthCode(t *testing.T) {
	f := &fakePKCE{t: t, claimsExtra: "state=nope"}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()

	_, err := LoginPKCE(context.Background(), cfg, "", "u", []byte("p"), nil)
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("error = %v, want ErrMissingToken", err)
	}
}

func TestLoginPKCENilHTTPClient(t *testing.T) {
	f := &fakePKCE{t: t}
	cfg, done := newFakePKCEConfig(t, f)
	defer done()
	cfg.HTTPClient = nil

	if _, err := LoginPKCE(context.Background(), cfg, "", "u", []byte("p"), nil); err == nil {
		t.Fatal("expected error when HTTPClient is nil")
	}
}

func TestExtractAuthorizationCode(t *testing.T) {
	code, err := extractAuthorizationCode(pkceRedirectURI + "?code=abc123&state=x")
	if err != nil {
		t.Fatalf("extractAuthorizationCode: %v", err)
	}
	if code != "abc123" {
		t.Errorf("code = %q, want abc123", code)
	}
	if _, err := extractAuthorizationCode(pkceRedirectURI + "?state=x"); !errors.Is(err, ErrMissingToken) {
		t.Errorf("error = %v, want ErrMissingToken", err)
	}
}

func hashString(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
