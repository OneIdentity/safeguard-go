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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAppliance is an httptest handler that mimics the RSTS and Core endpoints
// exercised by the broker: the provider list, the RSTS grant, and the Core
// LoginResponse exchange.
type fakeAppliance struct {
	t *testing.T

	providers       []provider
	providersStatus int
	rstsStatus      int
	rstsAccessToken string
	loginStatus     int
	loginBody       string // raw override for the LoginResponse body
	userToken       string
	loginRespStatus string // "Success" by default

	// captured requests for assertions
	lastGrant   map[string]any
	lastScope   string
	lastStsBody string
	sawProvider bool
}

func (f *fakeAppliance) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
			f.serveGrant(w, r)
		case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
			f.serveLogin(w, r)
		case strings.HasSuffix(r.URL.Path, "/AuthenticationProviders"):
			f.serveProviders(w, r)
		default:
			f.t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (f *fakeAppliance) serveProviders(w http.ResponseWriter, r *http.Request) {
	f.sawProvider = true
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("provider lookup must be anonymous, got Authorization header")
	}
	status := f.providersStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == http.StatusOK {
		_ = json.NewEncoder(w).Encode(f.providers)
	}
}

func (f *fakeAppliance) serveGrant(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("rsts grant must not carry Authorization header")
	}
	body, _ := io.ReadAll(r.Body)
	f.lastGrant = map[string]any{}
	if err := json.Unmarshal(body, &f.lastGrant); err != nil {
		f.t.Errorf("grant body not JSON: %v", err)
	}
	if s, ok := f.lastGrant["scope"].(string); ok {
		f.lastScope = s
	}
	status := f.rstsStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == http.StatusOK {
		token := f.rstsAccessToken
		if token == "" {
			token = "rsts-access-token"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token})
	}
}

func (f *fakeAppliance) serveLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var parsed struct {
		StsAccessToken string `json:"StsAccessToken"`
	}
	_ = json.Unmarshal(body, &parsed)
	f.lastStsBody = parsed.StsAccessToken

	status := f.loginStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if f.loginBody != "" {
		_, _ = io.WriteString(w, f.loginBody)
		return
	}
	if status != http.StatusOK {
		return
	}
	respStatus := f.loginRespStatus
	if respStatus == "" {
		respStatus = "Success"
	}
	token := f.userToken
	if token == "" {
		token = "user-token"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"Status": respStatus, "UserToken": token})
}

// newFakeConfig starts a TLS test server for f and returns a Config whose Doer
// and CertDoer both trust it.
func newFakeConfig(t *testing.T, f *fakeAppliance) (Config, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(f.handler())
	client := srv.Client()
	cfg := Config{
		Host:       strings.TrimPrefix(srv.URL, "https://"),
		APIVersion: "v4",
		Doer:       client,
		CertDoer:   client,
	}
	return cfg, srv.Close
}

func TestLoginPasswordDefaultScope(t *testing.T) {
	f := &fakeAppliance{t: t, userToken: "user-token-abc"}
	cfg, done := newFakeConfig(t, f)
	defer done()

	token, err := LoginPassword(context.Background(), cfg, "", "admin", []byte("Admin123"))
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if string(token) != "user-token-abc" {
		t.Fatalf("user token = %q, want user-token-abc", token)
	}
	if f.sawProvider {
		t.Errorf("empty provider must not trigger a provider lookup")
	}
	if f.lastScope != "rsts:sts:primaryproviderid:local" {
		t.Errorf("scope = %q, want default local scope", f.lastScope)
	}
	if f.lastGrant["grant_type"] != "password" {
		t.Errorf("grant_type = %v, want password", f.lastGrant["grant_type"])
	}
	if f.lastGrant["username"] != "admin" || f.lastGrant["password"] != "Admin123" {
		t.Errorf("credentials not forwarded: %v", f.lastGrant)
	}
	if f.lastStsBody != "rsts-access-token" {
		t.Errorf("StsAccessToken = %q, want rsts-access-token", f.lastStsBody)
	}
}

func TestLoginCertificateDefaultScope(t *testing.T) {
	f := &fakeAppliance{t: t, userToken: "cert-user-token"}
	cfg, done := newFakeConfig(t, f)
	defer done()

	token, err := LoginCertificate(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("LoginCertificate: %v", err)
	}
	if string(token) != "cert-user-token" {
		t.Fatalf("user token = %q, want cert-user-token", token)
	}
	if f.lastScope != "rsts:sts:primaryproviderid:certificate" {
		t.Errorf("scope = %q, want default certificate scope", f.lastScope)
	}
	if f.lastGrant["grant_type"] != "client_credentials" {
		t.Errorf("grant_type = %v, want client_credentials", f.lastGrant["grant_type"])
	}
	if _, ok := f.lastGrant["password"]; ok {
		t.Errorf("certificate grant must not carry a password")
	}
}

func TestLoginCertificateRequiresCertDoer(t *testing.T) {
	f := &fakeAppliance{t: t}
	cfg, done := newFakeConfig(t, f)
	defer done()
	cfg.CertDoer = nil

	_, err := LoginCertificate(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error when CertDoer is nil")
	}
}

func TestProviderScopeResolution(t *testing.T) {
	providers := []provider{
		{Name: "Local", RstsProviderID: "local", RstsProviderScope: "rsts:sts:primaryproviderid:local"},
		{Name: "Corp AD", RstsProviderID: "ad-1234", RstsProviderScope: "rsts:sts:primaryproviderid:ad-1234"},
	}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"exact rsts id", "ad-1234", "rsts:sts:primaryproviderid:ad-1234"},
		{"case-insensitive id", "AD-1234", "rsts:sts:primaryproviderid:ad-1234"},
		{"exact name", "Corp AD", "rsts:sts:primaryproviderid:ad-1234"},
		{"substring of id", "ad", "rsts:sts:primaryproviderid:ad-1234"},
		{"unknown falls back", "vault-x", "rsts:sts:primaryproviderid:vault-x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAppliance{t: t, providers: providers, userToken: "tok"}
			cfg, done := newFakeConfig(t, f)
			defer done()

			if _, err := LoginPassword(context.Background(), cfg, tc.input, "u", []byte("p")); err != nil {
				t.Fatalf("LoginPassword: %v", err)
			}
			if f.lastScope != tc.want {
				t.Errorf("scope = %q, want %q", f.lastScope, tc.want)
			}
		})
	}
}

func TestProviderLookupFailureFallsBack(t *testing.T) {
	f := &fakeAppliance{t: t, providersStatus: http.StatusInternalServerError, userToken: "tok"}
	cfg, done := newFakeConfig(t, f)
	defer done()

	if _, err := LoginPassword(context.Background(), cfg, "custom-provider", "u", []byte("p")); err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if f.lastScope != "rsts:sts:primaryproviderid:custom-provider" {
		t.Errorf("scope = %q, want fallback scope", f.lastScope)
	}
}

func TestRSTSGrantErrorStatus(t *testing.T) {
	f := &fakeAppliance{t: t, rstsStatus: http.StatusUnauthorized}
	cfg, done := newFakeConfig(t, f)
	defer done()

	_, err := LoginPassword(context.Background(), cfg, "", "u", []byte("bad"))
	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("error = %v, want *RequestError", err)
	}
	if reqErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", reqErr.StatusCode)
	}
	if reqErr.Op != "rsts grant" {
		t.Errorf("op = %q, want rsts grant", reqErr.Op)
	}
}

func TestLoginResponseNotSuccess(t *testing.T) {
	f := &fakeAppliance{t: t, loginRespStatus: "Failure"}
	cfg, done := newFakeConfig(t, f)
	defer done()

	_, err := LoginPassword(context.Background(), cfg, "", "u", []byte("p"))
	if !errors.Is(err, ErrLoginResponseFailed) {
		t.Fatalf("error = %v, want ErrLoginResponseFailed", err)
	}
}

func TestExchangeRSTSToken(t *testing.T) {
	f := &fakeAppliance{t: t, userToken: "exchanged"}
	cfg, done := newFakeConfig(t, f)
	defer done()

	token, err := ExchangeRSTSToken(context.Background(), cfg, []byte("rsts-in"))
	if err != nil {
		t.Fatalf("ExchangeRSTSToken: %v", err)
	}
	if string(token) != "exchanged" {
		t.Errorf("token = %q, want exchanged", token)
	}
	if f.lastStsBody != "rsts-in" {
		t.Errorf("forwarded StsAccessToken = %q, want rsts-in", f.lastStsBody)
	}
}
