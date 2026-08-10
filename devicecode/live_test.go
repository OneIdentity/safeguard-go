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
	"errors"
	"strings"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/devicecode"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveDeviceCodeChallenge is the unattended end-to-end floor for the
// device-code add-on against the appliance named by SPP_HOST. It enables the
// DeviceCode grant with an admin PKCE client, then drives devicecode.Connect with
// a prompt that captures the real challenge the appliance issued and cancels the
// context the instant it arrives. That exercises the whole start-and-prompt path
// live without a human completing the browser step: it proves the appliance
// issued a usable user code, verification URI, and lifetime. The interactive
// completion (a human approving the code) lives in the interactive suite.
func TestLiveDeviceCodeChallenge(t *testing.T) {
	host := livetest.Host(t)

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	restore := livetest.SetGrant(adminCtx, t, admin, "DeviceCode", true)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var got devicecode.Prompt
	prompt := func(_ context.Context, p devicecode.Prompt) error {
		got = p
		// The challenge has been delivered; cancel so polling stops immediately
		// rather than waiting for a human to approve the code.
		cancel()
		return nil
	}

	_, err := devicecode.Connect(ctx, host, prompt, devicecode.WithConnectionOptions(livetest.Options(t, host)...))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect device-code = %v, want context.Canceled after challenge", err)
	}

	if got.UserCode == "" {
		t.Error("prompt UserCode is empty")
	}
	if got.VerificationURI == "" {
		t.Error("prompt VerificationURI is empty")
	}
	if !strings.Contains(got.VerificationURI, host) {
		t.Errorf("VerificationURI %q does not reference host %q", got.VerificationURI, host)
	}
	if got.ExpiresIn <= 0 {
		t.Errorf("prompt ExpiresIn = %v, want positive", got.ExpiresIn)
	}
}

// TestLiveDeviceCodeGrantDisabled proves the device-code add-on surfaces a clear
// failure when the appliance has the DeviceCode grant disabled. It disables the
// grant with an admin PKCE client (restoring it afterward) and asserts Connect
// fails before any user code could be shown.
func TestLiveDeviceCodeGrantDisabled(t *testing.T) {
	host := livetest.Host(t)

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	restore := livetest.SetGrant(adminCtx, t, admin, "DeviceCode", false)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	promptCalled := false
	prompt := func(_ context.Context, _ devicecode.Prompt) error {
		promptCalled = true
		return nil
	}

	_, err := devicecode.Connect(ctx, host, prompt, devicecode.WithConnectionOptions(livetest.Options(t, host)...))
	if err == nil {
		t.Fatal("Connect device-code with grant disabled = nil, want error")
	}
	if promptCalled {
		t.Error("prompt was called even though the DeviceCode grant is disabled")
	}
	t.Logf("device-code grant-disabled error: %v", err)
	var apiErr *safeguard.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Connect device-code error = %v, want APIError", err)
	}
}
