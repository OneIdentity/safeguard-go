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
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/browser"
	"github.com/OneIdentity/safeguard-go/internal/auth"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveBrowserConnect is the unattended end-to-end floor for the browser
// add-on against the appliance named by SPP_HOST. A real system browser cannot be
// driven unattended, so the test supplies a browser opener that reproduces
// exactly what a human's browser would do: it walks the appliance's RSTS form
// controller for the authorize URL the add-on generated (obtaining a genuine
// authorization code from the live appliance) and then performs the loopback
// redirect back to the add-on's listener, delivering the code in the oauth query
// parameter. That drives the whole add-on path live -- authorize-URL acceptance,
// loopback capture, code redemption, and the Core token exchange -- and proves
// the resulting session is authenticated and non-refreshable. The only part not
// covered here is the appliance's own browser-page redirect to the loopback,
// which the interactive suite exercises with a real browser.
func TestLiveBrowserConnect(t *testing.T) {
	host := livetest.Host(t)
	provider, username, password := livetest.Creds()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	authCfg := auth.Config{Host: host, APIVersion: "v4", HTTPClient: livetest.TrustedHTTPClient(t, host)}
	loopbackClient := &http.Client{Timeout: 15 * time.Second}

	// opener mimics the user's browser: it drives the RSTS form controller to a
	// real authorization code and redirects it to the add-on's loopback listener.
	opener := func(authURL string) error {
		loopbackURL, err := auth.AcquireBrowserLoopbackURL(ctx, authCfg, authCfg.HTTPClient, authURL, provider, username, []byte(password), nil)
		if err != nil {
			return fmt.Errorf("drive form controller: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loopbackURL, nil)
		if err != nil {
			return err
		}
		resp, err := loopbackClient.Do(req)
		if err != nil {
			return fmt.Errorf("deliver loopback redirect: %w", err)
		}
		return resp.Body.Close()
	}

	client, err := browser.Connect(ctx, host,
		browser.WithLoginHint(username),
		browser.WithBrowserOpener(opener),
		browser.WithConnectionOptions(livetest.Options(t, host)...),
	)
	if err != nil {
		t.Fatalf("browser.Connect against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
	if err := client.RefreshToken(ctx); !errors.Is(err, safeguard.ErrNotRefreshable) {
		t.Errorf("RefreshToken on browser session = %v, want ErrNotRefreshable", err)
	}
}
