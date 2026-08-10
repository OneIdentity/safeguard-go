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

// This file holds the device-code add-on's genuinely interactive end-to-end test.
// It is excluded from the default build and only compiled with the interactive
// build tag (go test -tags interactive), because it prints a user code and waits
// for a human to approve it in a browser. Run it attended, for example:
//
//	SPP_HOST=... SPP_USERNAME=... SPP_PASSWORD=... \
//	  go test -tags interactive -run TestInteractiveDeviceCodeConnect -v ./devicecode/
package devicecode_test

import (
	"context"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/devicecode"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestInteractiveDeviceCodeConnect starts a device-code login, prints the user
// code and verification URL, and blocks until a human approves it, then verifies
// the resulting session. It enables the DeviceCode grant with an admin PKCE client
// and restores it afterward.
func TestInteractiveDeviceCodeConnect(t *testing.T) {
	host := livetest.Host(t)

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	restore := livetest.SetGrant(adminCtx, t, admin, "DeviceCode", true)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	prompt := func(_ context.Context, p devicecode.Prompt) error {
		t.Logf("To sign in, open %s and enter code: %s", p.VerificationURI, p.UserCode)
		if p.VerificationURIComplete != "" {
			t.Logf("Or open the pre-filled URL: %s", p.VerificationURIComplete)
		}
		t.Logf("waiting up to %s for you to approve...", p.ExpiresIn)
		return nil
	}

	client, err := devicecode.Connect(ctx, host, prompt,
		devicecode.WithConnectionOptions(livetest.Options(t, host)...),
	)
	if err != nil {
		t.Fatalf("devicecode.Connect against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
}
