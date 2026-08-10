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

//go:build interactive

// This file holds the browser add-on's genuinely interactive end-to-end test. It
// is excluded from the default build and only compiled with the interactive build
// tag (go test -tags interactive), because it opens a real system browser and
// waits for a human to complete authentication. Run it attended, for example:
//
//	SPP_HOST=... SPP_USERNAME=... SPP_PASSWORD=... \
//	  go test -tags interactive -run TestInteractiveBrowserConnect -v ./browser/
package browser_test

import (
	"context"
	"errors"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/browser"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestInteractiveBrowserConnect opens the real system browser and blocks until a
// human completes the login, then verifies the resulting session. It exercises
// the one part the unattended floor cannot: the appliance's own browser page
// redirecting to the loopback listener.
func TestInteractiveBrowserConnect(t *testing.T) {
	host := livetest.Host(t)
	_, username, _ := livetest.Creds()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t.Logf("a system browser will open; complete the Safeguard login for %q", host)

	client, err := browser.Connect(ctx, host,
		browser.WithLoginHint(username),
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
