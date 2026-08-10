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
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestConnectAuthorizedSession exercises the add-on handoff: the LoginFunc
// receives a working server-trust transport plus the appliance coordinates,
// exchanges an RSTS token for a user token over that transport, and the resulting
// session is authenticated but not refreshable.
func TestConnectAuthorizedSession(t *testing.T) {
	h := &fakeApplianceHandler{t: t, userToken: "addon-token"}
	srv := newFakeAppliance(t, h, false)

	var (
		gotHost       string
		gotAPIVersion string
	)
	login := func(ctx context.Context, tr LoginTransport) (Secret, error) {
		gotHost = tr.Host()
		gotAPIVersion = tr.APIVersion()
		// Simulate the add-on's RSTS-token -> user-token exchange over the
		// client's own transport (which honors the connection's TLS policy).
		body := strings.NewReader(`{"StsAccessToken":"rsts-token"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://"+tr.Host()+"/service/core/"+tr.APIVersion()+"/Token/LoginResponse", body)
		if err != nil {
			return Secret{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := tr.Do(req)
		if err != nil {
			return Secret{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		// Minimal parse: the fake returns {"Status":"Success","UserToken":"addon-token"}.
		const marker = `"UserToken":"`
		i := strings.Index(string(raw), marker)
		if i < 0 {
			return Secret{}, errors.New("no user token")
		}
		rest := string(raw)[i+len(marker):]
		token := rest[:strings.IndexByte(rest, '"')]
		return NewSecretString(token), nil
	}

	ctx := context.Background()
	client, err := Connect(ctx, testHost(srv),
		AuthorizedSession(login),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect AuthorizedSession: %v", err)
	}
	defer closeClient(t, client)

	if gotHost != client.Host() {
		t.Errorf("LoginTransport.Host() = %q, want %q", gotHost, client.Host())
	}
	if gotAPIVersion != client.APIVersion() {
		t.Errorf("LoginTransport.APIVersion() = %q, want %q", gotAPIVersion, client.APIVersion())
	}

	if _, err := client.Get(ctx, Core, "Me"); err != nil {
		t.Fatalf("authenticated Get: %v", err)
	}
	if h.lastBearer != "Bearer addon-token" {
		t.Errorf("Authorization = %q, want Bearer addon-token", h.lastBearer)
	}

	// Interactive add-on sessions are not refreshable, matching SafeguardDotNet
	// and PySafeguard.
	if err := client.RefreshToken(ctx); !errors.Is(err, ErrNotRefreshable) {
		t.Errorf("RefreshToken on AuthorizedSession = %v, want ErrNotRefreshable", err)
	}
}

func TestAuthorizedSessionNilLoginFunc(t *testing.T) {
	_, err := Connect(context.Background(), "example.test", AuthorizedSession(nil))
	if !errors.Is(err, errNilLoginFunc) {
		t.Fatalf("Connect AuthorizedSession(nil) = %v, want errNilLoginFunc", err)
	}
}

func TestAuthorizedSessionEmptyToken(t *testing.T) {
	h := &fakeApplianceHandler{t: t}
	srv := newFakeAppliance(t, h, false)

	login := func(_ context.Context, _ LoginTransport) (Secret, error) {
		return Secret{}, nil
	}
	_, err := Connect(context.Background(), testHost(srv),
		AuthorizedSession(login),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if !errors.Is(err, errEmptyToken) {
		t.Fatalf("Connect with empty token = %v, want errEmptyToken", err)
	}
}

func TestAuthorizedSessionLoginError(t *testing.T) {
	h := &fakeApplianceHandler{t: t}
	srv := newFakeAppliance(t, h, false)

	sentinel := errors.New("browser cancelled")
	login := func(_ context.Context, _ LoginTransport) (Secret, error) {
		return Secret{}, sentinel
	}
	_, err := Connect(context.Background(), testHost(srv),
		AuthorizedSession(login),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Connect with login error = %v, want sentinel", err)
	}
}
