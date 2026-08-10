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

package devicecode_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/devicecode"
)

// deviceAppliance is a fake appliance serving the RSTS device authorization, the
// token-endpoint poll (scripted), and the Core LoginResponse exchange.
type deviceAppliance struct {
	t *testing.T

	// pollResponses is the scripted sequence returned by the token endpoint, one
	// per poll; the final entry repeats.
	pollResponses []pollResp

	mu      sync.Mutex
	polls   int
	lastSts string
}

type pollResp struct {
	status int
	body   map[string]any
}

func (a *deviceAppliance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/DeviceLogin"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code",
			"user_code":                 "WXYZ-1234",
			"verification_uri":          "https://appliance/RSTS/UserLogin/Device",
			"verification_uri_complete": "https://appliance/RSTS/UserLogin/Device?user_code=WXYZ-1234",
			"expires_in":                60,
		})
	case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
		a.mu.Lock()
		idx := a.polls
		if idx >= len(a.pollResponses) {
			idx = len(a.pollResponses) - 1
		}
		resp := a.pollResponses[idx]
		a.polls++
		a.mu.Unlock()
		w.WriteHeader(resp.status)
		_ = json.NewEncoder(w).Encode(resp.body)
	case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
		body, _ := io.ReadAll(r.Body)
		var p struct{ StsAccessToken string }
		_ = json.Unmarshal(body, &p)
		a.mu.Lock()
		a.lastSts = p.StsAccessToken
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"Status": "Success", "UserToken": "device-user-token"})
	default:
		a.t.Errorf("unexpected path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func startAppliance(t *testing.T, a *deviceAppliance) (string, []byte, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(a)
	host := strings.TrimPrefix(srv.URL, "https://")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return host, certPEM, srv.Close
}

func TestConnect(t *testing.T) {
	a := &deviceAppliance{t: t, pollResponses: []pollResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}},
		{status: http.StatusOK, body: map[string]any{"access_token": "rsts-device"}},
	}}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	var shown devicecode.Prompt
	prompt := func(_ context.Context, p devicecode.Prompt) error {
		shown = p
		return nil
	}

	client, err := devicecode.Connect(context.Background(), host, prompt,
		devicecode.WithPollInterval(time.Millisecond),
		devicecode.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	if shown.UserCode != "WXYZ-1234" {
		t.Errorf("prompt user code = %q, want WXYZ-1234", shown.UserCode)
	}
	if shown.VerificationURIComplete == "" {
		t.Errorf("prompt missing complete verification URI: %+v", shown)
	}
	if shown.ExpiresIn != 60*time.Second {
		t.Errorf("prompt expires = %v, want 60s", shown.ExpiresIn)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastSts != "rsts-device" {
		t.Errorf("StsAccessToken = %q, want rsts-device", a.lastSts)
	}
	if a.polls < 2 {
		t.Errorf("polls = %d, want at least 2", a.polls)
	}
}

func TestConnectNoPrompt(t *testing.T) {
	_, err := devicecode.Connect(context.Background(), "appliance.example", nil)
	if !errors.Is(err, devicecode.ErrNoPrompt) {
		t.Fatalf("error = %v, want ErrNoPrompt", err)
	}
}

func TestConnectPromptError(t *testing.T) {
	a := &deviceAppliance{t: t, pollResponses: []pollResp{
		{status: http.StatusOK, body: map[string]any{"access_token": "rsts-device"}},
	}}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	prompt := func(_ context.Context, _ devicecode.Prompt) error { return io.ErrUnexpectedEOF }
	_, err := devicecode.Connect(context.Background(), host, prompt,
		devicecode.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if err == nil {
		t.Fatal("expected error when the prompt fails")
	}
}

func TestConnectDenied(t *testing.T) {
	a := &deviceAppliance{t: t, pollResponses: []pollResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "access_denied"}},
	}}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	prompt := func(_ context.Context, _ devicecode.Prompt) error { return nil }
	_, err := devicecode.Connect(context.Background(), host, prompt,
		devicecode.WithPollInterval(time.Millisecond),
		devicecode.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if !errors.Is(err, devicecode.ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

func TestConnectExpiredToken(t *testing.T) {
	a := &deviceAppliance{t: t, pollResponses: []pollResp{
		{status: http.StatusBadRequest, body: map[string]any{"error": "expired_token"}},
	}}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	prompt := func(_ context.Context, _ devicecode.Prompt) error { return nil }
	_, err := devicecode.Connect(context.Background(), host, prompt,
		devicecode.WithPollInterval(time.Millisecond),
		devicecode.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if !errors.Is(err, devicecode.ErrExpired) {
		t.Fatalf("error = %v, want ErrExpired", err)
	}
}
