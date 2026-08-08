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

package safeguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refreshAppliance is a fake appliance for exercising refresh and 401 replay. Its
// Protected endpoint returns 200 only for the current user token; rotating the
// token makes previously issued tokens 401 until the client re-authenticates. It
// counts logins (RSTS grants) so tests can assert single-flight behavior, and
// records whether Token/Logout was called.
type refreshAppliance struct {
	t *testing.T

	mu        sync.Mutex
	logins    int
	current   string
	loggedOut bool

	// grantDelay widens the refresh window so concurrent callers contend on the
	// single-flight barrier.
	grantDelay time.Duration
}

func newRefreshAppliance(t *testing.T) *refreshAppliance {
	return &refreshAppliance{t: t}
}

func (a *refreshAppliance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
		if a.grantDelay > 0 {
			time.Sleep(a.grantDelay)
		}
		a.mu.Lock()
		a.logins++
		a.current = fmt.Sprintf("user-token-%d", a.logins)
		a.mu.Unlock()
		writeJSON(w, `{"access_token":"rsts"}`)
	case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
		a.mu.Lock()
		tok := a.current
		a.mu.Unlock()
		writeJSON(w, `{"Status":"Success","UserToken":"`+tok+`"}`)
	case strings.HasSuffix(r.URL.Path, "/Token/Logout"):
		a.mu.Lock()
		a.loggedOut = true
		a.mu.Unlock()
		writeJSON(w, `{}`)
	case strings.HasSuffix(r.URL.Path, "/LoginMessage"):
		w.Header().Set("X-TokenLifetimeRemaining", "42")
		writeJSON(w, `"welcome"`)
	case strings.HasSuffix(r.URL.Path, "/Protected"):
		a.serveProtected(w, r)
	default:
		a.t.Errorf("unexpected path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (a *refreshAppliance) serveProtected(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	want := "Bearer " + a.current
	a.mu.Unlock()
	if r.Header.Get("Authorization") != want {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"Code":401,"Message":"expired"}`))
		return
	}
	writeJSON(w, `{"ok":true}`)
}

// rotate invalidates the current token so the next Protected call 401s.
func (a *refreshAppliance) rotate() {
	a.mu.Lock()
	a.current = "rotated-out"
	a.mu.Unlock()
}

func (a *refreshAppliance) loginCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.logins
}

func (a *refreshAppliance) sawLogout() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loggedOut
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func connectRefreshable(t *testing.T, a *refreshAppliance) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(a)
	t.Cleanup(srv.Close)
	client, err := Connect(context.Background(), testHost(srv),
		UsernamePassword("", "admin", NewSecretString("pw")),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return client, srv
}

func TestRefreshOn401ReplaysWithFreshToken(t *testing.T) {
	a := newRefreshAppliance(t)
	client, _ := connectRefreshable(t, a)
	defer closeClient(t, client)

	if got := a.loginCount(); got != 1 {
		t.Fatalf("logins after Connect = %d, want 1", got)
	}
	a.rotate()

	full, err := client.Get(context.Background(), Core, "Protected")
	if err != nil {
		t.Fatalf("Get after rotation: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", full.StatusCode)
	}
	if got := a.loginCount(); got != 2 {
		t.Fatalf("logins = %d, want 2 (initial + one refresh)", got)
	}
}

func TestNonRefreshableTokenSurfaces401(t *testing.T) {
	a := newRefreshAppliance(t)
	srv := httptest.NewTLSServer(a)
	t.Cleanup(srv.Close)

	client, err := Connect(context.Background(), testHost(srv),
		Token(NewSecretString("stale-token")),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer closeClient(t, client)

	_, err = client.Get(context.Background(), Core, "Protected")
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("Get = %v, want *AuthenticationError", err)
	}
	if got := a.loginCount(); got != 0 {
		t.Fatalf("logins = %d, want 0 (Token credential must never refresh)", got)
	}
}

func TestSingleFlightRefresh(t *testing.T) {
	a := newRefreshAppliance(t)
	a.grantDelay = 40 * time.Millisecond
	client, _ := connectRefreshable(t, a)
	defer closeClient(t, client)

	loginsAfterConnect := a.loginCount()
	a.rotate()

	const callers = 8
	var wg sync.WaitGroup
	var oks int32
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			full, err := client.Get(context.Background(), Core, "Protected")
			if err == nil && full.StatusCode == http.StatusOK {
				atomic.AddInt32(&oks, 1)
			}
		}()
	}
	wg.Wait()

	if oks != callers {
		t.Fatalf("successful callers = %d, want %d", oks, callers)
	}
	if got := a.loginCount() - loginsAfterConnect; got != 1 {
		t.Fatalf("refresh logins = %d, want 1 (single flight)", got)
	}
}

func TestExplicitRefreshToken(t *testing.T) {
	a := newRefreshAppliance(t)
	client, _ := connectRefreshable(t, a)
	defer closeClient(t, client)

	before := a.loginCount()
	if err := client.RefreshToken(context.Background()); err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if got := a.loginCount() - before; got != 1 {
		t.Fatalf("logins from explicit refresh = %d, want 1", got)
	}
	if _, err := client.Get(context.Background(), Core, "Protected"); err != nil {
		t.Fatalf("Get after explicit refresh: %v", err)
	}
}

func TestTokenLifetimeRemainingQueriesAppliance(t *testing.T) {
	a := newRefreshAppliance(t)
	client, _ := connectRefreshable(t, a)
	defer closeClient(t, client)

	d, err := client.TokenLifetimeRemaining(context.Background())
	if err != nil {
		t.Fatalf("TokenLifetimeRemaining: %v", err)
	}
	if want := 42 * time.Minute; d != want {
		t.Fatalf("lifetime = %v, want %v", d, want)
	}
}

func TestLogoutCallsAppliance(t *testing.T) {
	a := newRefreshAppliance(t)
	client, _ := connectRefreshable(t, a)
	defer closeClient(t, client)

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !a.sawLogout() {
		t.Fatal("appliance did not observe a Token/Logout call")
	}
	if got := client.currentAuthorization().headerValue(); got != "" {
		t.Fatalf("authorization after Logout = %q, want empty", got)
	}
}
