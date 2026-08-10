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

package safeguard_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/auth"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveTokenConnect proves the Token credential against the appliance named by
// SPP_HOST. It first mints a genuine user token with a headless PKCE login, then
// connects a fresh client with that token alone, calls an authenticated endpoint,
// and confirms the token session is not refreshable (the SDK holds no credential
// to mint a replacement, so RefreshToken reports ErrNotRefreshable).
func TestLiveTokenConnect(t *testing.T) {
	host := livetest.Host(t)
	provider, username, password := livetest.Creds()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	authCfg := auth.Config{Host: host, APIVersion: "v4", HTTPClient: livetest.TrustedHTTPClient(t, host)}
	token, err := auth.LoginPKCE(ctx, authCfg, provider, username, []byte(password), nil)
	if err != nil {
		t.Fatalf("mint token via PKCE: %v", err)
	}

	client, err := safeguard.Connect(ctx, host,
		safeguard.Token(safeguard.NewSecret(token)),
		livetest.Options(t, host)...,
	)
	if err != nil {
		t.Fatalf("Connect with Token against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
	if err := client.RefreshToken(ctx); !errors.Is(err, safeguard.ErrNotRefreshable) {
		t.Errorf("RefreshToken on Token session = %v, want ErrNotRefreshable", err)
	}
}

// TestLiveAnonymousConnect proves the Anonymous credential against the appliance
// named by SPP_HOST: a token-less session can reach anonymous endpoints (the
// Notification service) but is rejected from an authenticated endpoint.
func TestLiveAnonymousConnect(t *testing.T) {
	host := livetest.Host(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := safeguard.Connect(ctx, host,
		safeguard.Anonymous(),
		livetest.Options(t, host)...,
	)
	if err != nil {
		t.Fatalf("Connect anonymous against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	full, err := client.Get(ctx, safeguard.Notification, "Status")
	if err != nil {
		t.Fatalf("anonymous Get Notification Status: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("Notification Status StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}

	if _, err := client.Get(ctx, safeguard.Core, "Me"); err == nil {
		t.Fatal("anonymous Get Core/Me succeeded, want authorization error")
	}
}

// TestLivePasswordConnect proves the UsernamePassword (Resource Owner Grant)
// credential against the appliance named by SPP_HOST. Because appliances commonly
// disable the Resource Owner Grant (Dan's does), the test enables it with an admin
// PKCE client, restoring the original setting afterward. It then connects with the
// password credential, calls an authenticated endpoint, and -- unlike the OAuth
// flows -- confirms the session is refreshable by actually refreshing the token
// and calling the endpoint again.
func TestLivePasswordConnect(t *testing.T) {
	host := livetest.Host(t)
	provider, username, password := livetest.Creds()

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	restore := livetest.SetGrant(adminCtx, t, admin, "ResourceOwner", true)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := safeguard.Connect(ctx, host,
		safeguard.UsernamePassword(provider, username, safeguard.NewSecretString(password)),
		livetest.Options(t, host)...,
	)
	if err != nil {
		t.Fatalf("Connect with UsernamePassword against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
	if err := client.RefreshToken(ctx); err != nil {
		t.Fatalf("RefreshToken on password session: %v", err)
	}
	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("Get Me after refresh: %v", err)
	}
}
