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

package browser_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/browser"
)

// browserAppliance is a fake appliance serving the RSTS token exchange and the
// Core LoginResponse the browser flow performs after it captures the code.
type browserAppliance struct {
	t *testing.T

	mu        sync.Mutex
	lastGrant map[string]any
	lastSts   string
}

func (a *browserAppliance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.lastGrant = map[string]any{}
		_ = json.Unmarshal(body, &a.lastGrant)
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "rsts-browser"})
	case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
		body, _ := io.ReadAll(r.Body)
		var p struct{ StsAccessToken string }
		_ = json.Unmarshal(body, &p)
		a.mu.Lock()
		a.lastSts = p.StsAccessToken
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"Status": "Success", "UserToken": "browser-user-token"})
	default:
		a.t.Errorf("unexpected path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// startAppliance starts a TLS test server and returns its host and CA bundle.
func startAppliance(t *testing.T, a *browserAppliance) (string, []byte, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(a)
	host := strings.TrimPrefix(srv.URL, "https://")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return host, certPEM, srv.Close
}

// redirectOpener simulates a browser: it parses the loopback port from the
// authorize URL and drives the redirect the appliance would perform, delivering
// the authorization code in the oauth query parameter.
func redirectOpener(t *testing.T, code string, capturedURL *string) func(string) error {
	return func(authURL string) error {
		if capturedURL != nil {
			*capturedURL = authURL
		}
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		port := u.Query().Get("port")
		go func() {
			resp, err := http.Get("http://127.0.0.1:" + port + "/?oauth=" + url.QueryEscape(code))
			if err != nil {
				t.Logf("loopback redirect failed: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
}

func TestConnect(t *testing.T) {
	a := &browserAppliance{t: t}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	var authURL string
	client, err := browser.Connect(context.Background(), host,
		browser.WithBrowserOpener(redirectOpener(t, "the-code", &authURL)),
		browser.WithLoginHint("admin"),
		browser.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The authorize URL the opener saw must carry the browser flow's parameters.
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	if u.Path != "/RSTS/Login" {
		t.Errorf("authorize path = %q, want /RSTS/Login", u.Path)
	}
	if got := u.Query().Get("login_hint"); got != "admin" {
		t.Errorf("login_hint = %q, want admin", got)
	}
	if got := u.Query().Get("redirect_uri"); got != "urn:InstalledApplicationTcpListener" {
		t.Errorf("redirect_uri = %q, want urn:InstalledApplicationTcpListener", got)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastGrant["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %v, want authorization_code", a.lastGrant["grant_type"])
	}
	if a.lastGrant["code"] != "the-code" {
		t.Errorf("code = %v, want the-code", a.lastGrant["code"])
	}
	if a.lastGrant["code_verifier"] == nil || a.lastGrant["code_verifier"] == "" {
		t.Errorf("code_verifier not sent: %v", a.lastGrant)
	}
	if a.lastSts != "rsts-browser" {
		t.Errorf("StsAccessToken = %q, want rsts-browser", a.lastSts)
	}
}

func TestConnectOpenerError(t *testing.T) {
	a := &browserAppliance{t: t}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	openErr := func(string) error { return io.ErrClosedPipe }
	_, err := browser.Connect(context.Background(), host,
		browser.WithBrowserOpener(openErr),
		browser.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if err == nil {
		t.Fatal("expected error when the browser opener fails")
	}
}

func TestConnectContextCanceled(t *testing.T) {
	a := &browserAppliance{t: t}
	host, certPEM, done := startAppliance(t, a)
	defer done()

	// An opener that never delivers a code lets the context deadline fire.
	noop := func(string) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := browser.Connect(ctx, host,
		browser.WithBrowserOpener(noop),
		browser.WithConnectionOptions(safeguard.WithCABundle(certPEM)),
	)
	if err == nil {
		t.Fatal("expected error when the context is canceled before a code arrives")
	}
}
