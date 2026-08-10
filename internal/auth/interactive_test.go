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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// newInteractiveServer starts a TLS test server for handler and returns a Config
// trusting it. It mirrors newFakeConfig but takes a bare handler so each
// interactive test can script its own RSTS responses.
func newInteractiveServer(t *testing.T, handler http.HandlerFunc) (Config, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	cfg := Config{
		Host:       strings.TrimPrefix(srv.URL, "https://"),
		APIVersion: "v4",
		HTTPClient: srv.Client(),
	}
	return cfg, srv.Close
}

func TestNewPKCEPair(t *testing.T) {
	pair, err := NewPKCEPair()
	if err != nil {
		t.Fatalf("NewPKCEPair: %v", err)
	}
	if pair.Verifier == "" || pair.Challenge == "" {
		t.Fatalf("empty pair: %+v", pair)
	}
	if want := codeChallenge([]byte(pair.Verifier)); pair.Challenge != want {
		t.Errorf("challenge = %q, want %q (S256 of verifier)", pair.Challenge, want)
	}
	// Two pairs must differ: the verifier is random.
	other, err := NewPKCEPair()
	if err != nil {
		t.Fatalf("NewPKCEPair: %v", err)
	}
	if other.Verifier == pair.Verifier {
		t.Error("two verifiers were identical")
	}
}

func TestBrowserAuthorizeURL(t *testing.T) {
	cfg := Config{Host: "appliance.example", APIVersion: "v4"}

	raw := BrowserAuthorizeURL(cfg, "challenge-xyz", 8400, "admin")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if u.Scheme != "https" || u.Host != "appliance.example" || u.Path != "/RSTS/Login" {
		t.Errorf("unexpected base URL %q", raw)
	}
	q := u.Query()
	cases := map[string]string{
		"response_type":         "code",
		"code_challenge_method": "S256",
		"code_challenge":        "challenge-xyz",
		"redirect_uri":          "urn:InstalledApplicationTcpListener",
		"port":                  "8400",
		"login_hint":            "admin",
	}
	for k, want := range cases {
		if got := q.Get(k); got != want {
			t.Errorf("query %q = %q, want %q", k, got, want)
		}
	}
	if q.Has("client_id") || q.Has("scope") || q.Has("state") {
		t.Errorf("authorize URL must not carry client_id/scope/state: %q", raw)
	}

	// Empty username omits login_hint entirely.
	noHint := BrowserAuthorizeURL(cfg, "c", 1234, "")
	if strings.Contains(noHint, "login_hint") {
		t.Errorf("empty username must omit login_hint: %q", noHint)
	}
}

func TestRedeemBrowserCode(t *testing.T) {
	var gotGrant map[string]any
	var gotSts string
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
			body, _ := io.ReadAll(r.Body)
			gotGrant = map[string]any{}
			_ = json.Unmarshal(body, &gotGrant)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "rsts-from-browser"})
		case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
			body, _ := io.ReadAll(r.Body)
			var p struct{ StsAccessToken string }
			_ = json.Unmarshal(body, &p)
			gotSts = p.StsAccessToken
			_ = json.NewEncoder(w).Encode(map[string]string{"Status": "Success", "UserToken": "browser-user-token"})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
	cfg, done := newInteractiveServer(t, handler)
	defer done()

	token, err := RedeemBrowserCode(context.Background(), cfg, cfg.HTTPClient, "auth-code-1", "verifier-1")
	if err != nil {
		t.Fatalf("RedeemBrowserCode: %v", err)
	}
	if string(token) != "browser-user-token" {
		t.Errorf("token = %q, want browser-user-token", token)
	}
	if gotGrant["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %v, want authorization_code", gotGrant["grant_type"])
	}
	if gotGrant["redirect_uri"] != "urn:InstalledApplicationTcpListener" {
		t.Errorf("redirect_uri = %v, want urn:InstalledApplicationTcpListener", gotGrant["redirect_uri"])
	}
	if gotGrant["code"] != "auth-code-1" || gotGrant["code_verifier"] != "verifier-1" {
		t.Errorf("code/verifier not forwarded: %v", gotGrant)
	}
	if _, ok := gotGrant["client_id"]; ok {
		t.Errorf("browser grant must not carry client_id: %v", gotGrant)
	}
	if gotSts != "rsts-from-browser" {
		t.Errorf("StsAccessToken = %q, want rsts-from-browser", gotSts)
	}
}

func TestStartDeviceCode(t *testing.T) {
	var gotReq map[string]any
	handler := func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/DeviceLogin") {
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		gotReq = map[string]any{}
		_ = json.Unmarshal(body, &gotReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code-abc",
			"user_code":                 "WXYZ-1234",
			"verification_uri":          "https://appliance/RSTS/UserLogin/Device",
			"verification_uri_complete": "https://appliance/RSTS/UserLogin/Device?user_code=WXYZ-1234",
			"expires_in":                120,
		})
	}
	cfg, done := newInteractiveServer(t, handler)
	defer done()

	ch, err := StartDeviceCode(context.Background(), cfg, cfg.HTTPClient)
	if err != nil {
		t.Fatalf("StartDeviceCode: %v", err)
	}
	if ch.DeviceCode != "dev-code-abc" || ch.UserCode != "WXYZ-1234" {
		t.Errorf("codes not parsed: %+v", ch)
	}
	if ch.VerificationURIComplete == "" || ch.VerificationURI == "" {
		t.Errorf("verification URIs not parsed: %+v", ch)
	}
	if ch.ExpiresIn != 120*time.Second {
		t.Errorf("expires = %v, want 120s", ch.ExpiresIn)
	}
	if ch.Interval != deviceDefaultInterval {
		t.Errorf("interval = %v, want default %v", ch.Interval, deviceDefaultInterval)
	}
	if gotReq["client_id"] != "" {
		t.Errorf("client_id = %v, want empty string", gotReq["client_id"])
	}
	if gotReq["scope"] != deviceScope {
		t.Errorf("scope = %v, want %q", gotReq["scope"], deviceScope)
	}
}

func TestStartDeviceCodeDefaultsExpiresIn(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "d", "user_code": "u", "verification_uri": "https://x",
		})
	}
	cfg, done := newInteractiveServer(t, handler)
	defer done()

	ch, err := StartDeviceCode(context.Background(), cfg, cfg.HTTPClient)
	if err != nil {
		t.Fatalf("StartDeviceCode: %v", err)
	}
	if ch.ExpiresIn != deviceDefaultExpiresIn {
		t.Errorf("expires = %v, want default %v", ch.ExpiresIn, deviceDefaultExpiresIn)
	}
}

// deviceTokenScript serves the RSTS token endpoint returning a scripted sequence
// of responses (one per poll) followed by a terminal success, and the Core
// LoginResponse exchange.
type deviceTokenScript struct {
	t         *testing.T
	mu        sync.Mutex
	responses []deviceResp // consumed front to back; last repeats
	polls     int
	gotSts    string
}

type deviceResp struct {
	status int
	body   map[string]any
}

func (s *deviceTokenScript) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
			s.mu.Lock()
			idx := s.polls
			if idx >= len(s.responses) {
				idx = len(s.responses) - 1
			}
			resp := s.responses[idx]
			s.polls++
			s.mu.Unlock()
			w.WriteHeader(resp.status)
			_ = json.NewEncoder(w).Encode(resp.body)
		case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
			body, _ := io.ReadAll(r.Body)
			var p struct{ StsAccessToken string }
			_ = json.Unmarshal(body, &p)
			s.mu.Lock()
			s.gotSts = p.StsAccessToken
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"Status": "Success", "UserToken": "device-user-token"})
		default:
			s.t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestPollDeviceCodeSuccess(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}},
		{status: http.StatusOK, body: map[string]any{"access_token": "rsts-device"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	token, err := PollDeviceCode(context.Background(), cfg, cfg.HTTPClient, "dev-code", time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("PollDeviceCode: %v", err)
	}
	if string(token) != "device-user-token" {
		t.Errorf("token = %q, want device-user-token", token)
	}
	if s.polls < 2 {
		t.Errorf("polls = %d, want at least 2 (pending then success)", s.polls)
	}
	if s.gotSts != "rsts-device" {
		t.Errorf("StsAccessToken = %q, want rsts-device", s.gotSts)
	}
}

func TestPollDeviceCodeSlowDown(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "slow_down"}},
		{status: http.StatusOK, body: map[string]any{"access_token": "rsts-device"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	token, err := PollDeviceCode(context.Background(), cfg, cfg.HTTPClient, "dev-code", time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("PollDeviceCode: %v", err)
	}
	if string(token) != "device-user-token" {
		t.Errorf("token = %q, want device-user-token", token)
	}
}

func TestPollDeviceCodeDenied(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "access_denied"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	_, err := PollDeviceCode(context.Background(), cfg, cfg.HTTPClient, "dev-code", time.Millisecond, time.Second)
	if !errors.Is(err, ErrDeviceCodeDenied) {
		t.Fatalf("error = %v, want ErrDeviceCodeDenied", err)
	}
}

func TestPollDeviceCodeExpiredToken(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "expired_token"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	_, err := PollDeviceCode(context.Background(), cfg, cfg.HTTPClient, "dev-code", time.Millisecond, time.Second)
	if !errors.Is(err, ErrDeviceCodeExpired) {
		t.Fatalf("error = %v, want ErrDeviceCodeExpired", err)
	}
}

func TestPollDeviceCodeTimeout(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	_, err := PollDeviceCode(context.Background(), cfg, cfg.HTTPClient, "dev-code", time.Millisecond, 20*time.Millisecond)
	if !errors.Is(err, ErrDeviceCodeExpired) {
		t.Fatalf("error = %v, want ErrDeviceCodeExpired on timeout", err)
	}
}

func TestPollDeviceCodeContextCancel(t *testing.T) {
	s := &deviceTokenScript{t: t, responses: []deviceResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}},
	}}
	cfg, done := newInteractiveServer(t, s.handler())
	defer done()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PollDeviceCode(ctx, cfg, cfg.HTTPClient, "dev-code", time.Second, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
