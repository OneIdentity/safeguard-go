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
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// eventPasswordUpdated is the event Safeguard raises when an asset account's
// stored password changes. Both a user session that can see the account and an
// A2A credential bound to the account receive it.
const eventPasswordUpdated = "AssetAccountPasswordUpdated"

// TestLiveEvents proves the SignalR event listener end to end against the
// appliance named by SPP_HOST. It provisions a complete A2A environment (asset,
// account, certificate user, and registration) and then, from that one
// environment, exercises both listener flavors: a user-session listener built on
// the temporary AssetAdmin client that owns the account, and an A2A listener
// authorized by the account's password API key. In each case it registers a
// handler for AssetAccountPasswordUpdated, starts the listener, changes the
// account password to trigger the event, and asserts the handler fires with the
// expected name and a decodable payload. All provisioned state is removed
// afterward.
func TestLiveEvents(t *testing.T) {
	host := livetest.Host(t)

	certPEM, err := os.ReadFile("testdata/CERTS/user-cert.pem")
	if err != nil {
		t.Fatalf("read test certificate: %v", err)
	}
	keyPEM, err := os.ReadFile("testdata/CERTS/user-key.pem")
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	env, cleanup := livetest.ProvisionA2A(adminCtx, t, admin, certPEM)
	defer cleanup()

	// changePassword stores a fresh password on the provisioned account, which
	// raises AssetAccountPasswordUpdated. It uses the temp AssetAdmin that owns
	// the account.
	changePassword := func(ctx context.Context, t *testing.T) {
		t.Helper()
		newPass := "SgGo-Evt-" + fmt.Sprint(time.Now().UnixNano()) + "!1"
		body, err := json.Marshal(newPass)
		if err != nil {
			t.Fatalf("marshal password body: %v", err)
		}
		path := fmt.Sprintf("AssetAccounts/%d/Password", env.AccountID)
		if _, err := env.Admin.Put(ctx, safeguard.Core, path, json.RawMessage(body)); err != nil {
			t.Fatalf("store account password to trigger event: %v", err)
		}
	}

	t.Run("UserListener", func(t *testing.T) {
		listener := env.Admin.NewEventListener()
		fired := make(chan string, 4)
		listener.RegisterEventHandler(eventPasswordUpdated, func(name string, data json.RawMessage) {
			if !json.Valid(data) {
				t.Errorf("event %q payload is not valid JSON: %s", name, data)
			}
			fired <- name
		})

		startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := listener.Start(startCtx); err != nil {
			t.Fatalf("start user event listener: %v", err)
		}
		defer listener.Stop()

		// Give the appliance a moment to register the subscription before the
		// triggering change.
		time.Sleep(2 * time.Second)
		changePassword(startCtx, t)

		select {
		case name := <-fired:
			if name != eventPasswordUpdated {
				t.Fatalf("received event %q, want %q", name, eventPasswordUpdated)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for AssetAccountPasswordUpdated on user listener")
		case <-listener.Done():
			t.Fatalf("user listener stopped before event: %v", listener.Err())
		}
	})

	t.Run("A2AListener", func(t *testing.T) {
		a2a, err := safeguard.NewA2AContext(host, certPEM, safeguard.Secret{},
			safeguard.WithA2APrivateKeyPEM(keyPEM),
			safeguard.WithA2AConnectionOptions(livetest.Options(t, host)...),
		)
		if err != nil {
			t.Fatalf("NewA2AContext against %s: %v", host, err)
		}
		defer func() { _ = a2a.Close() }()

		listener := a2a.NewEventListener(safeguard.NewSecretString(env.PasswordAPIKey))
		fired := make(chan string, 4)
		listener.RegisterEventHandler(eventPasswordUpdated, func(name string, data json.RawMessage) {
			if !json.Valid(data) {
				t.Errorf("event %q payload is not valid JSON: %s", name, data)
			}
			fired <- name
		})

		startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := listener.Start(startCtx); err != nil {
			t.Fatalf("start A2A event listener: %v", err)
		}
		defer listener.Stop()

		time.Sleep(2 * time.Second)
		changePassword(startCtx, t)

		select {
		case name := <-fired:
			if name != eventPasswordUpdated {
				t.Fatalf("received event %q, want %q", name, eventPasswordUpdated)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for AssetAccountPasswordUpdated on A2A listener")
		case <-listener.Done():
			t.Fatalf("A2A listener stopped before event: %v", listener.Err())
		}
	})

	t.Run("PersistentUserListener", func(t *testing.T) {
		listener := env.Admin.NewPersistentEventListener()
		fired := make(chan string, 4)
		listener.RegisterEventHandler(eventPasswordUpdated, func(name string, data json.RawMessage) {
			if !json.Valid(data) {
				t.Errorf("event %q payload is not valid JSON: %s", name, data)
			}
			fired <- name
		})

		startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := listener.Start(startCtx); err != nil {
			t.Fatalf("start persistent event listener: %v", err)
		}
		defer listener.Stop()

		// The persistent listener connects asynchronously, so allow a little
		// longer for the initial subscription to register.
		time.Sleep(4 * time.Second)
		changePassword(startCtx, t)

		select {
		case name := <-fired:
			if name != eventPasswordUpdated {
				t.Fatalf("received event %q, want %q", name, eventPasswordUpdated)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for AssetAccountPasswordUpdated on persistent listener")
		case <-listener.Done():
			t.Fatalf("persistent listener stopped before event: %v", listener.Err())
		}
	})

	t.Run("PersistentA2AListener", func(t *testing.T) {
		a2a, err := safeguard.NewA2AContext(host, certPEM, safeguard.Secret{},
			safeguard.WithA2APrivateKeyPEM(keyPEM),
			safeguard.WithA2AConnectionOptions(livetest.Options(t, host)...),
		)
		if err != nil {
			t.Fatalf("NewA2AContext against %s: %v", host, err)
		}
		defer func() { _ = a2a.Close() }()

		listener := a2a.NewPersistentEventListener(safeguard.NewSecretString(env.PasswordAPIKey))
		fired := make(chan string, 4)
		listener.RegisterEventHandler(eventPasswordUpdated, func(name string, data json.RawMessage) {
			if !json.Valid(data) {
				t.Errorf("event %q payload is not valid JSON: %s", name, data)
			}
			fired <- name
		})

		startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := listener.Start(startCtx); err != nil {
			t.Fatalf("start persistent A2A event listener: %v", err)
		}
		defer listener.Stop()

		// The persistent listener connects asynchronously, so allow a little
		// longer for the initial subscription to register.
		time.Sleep(4 * time.Second)
		changePassword(startCtx, t)

		select {
		case name := <-fired:
			if name != eventPasswordUpdated {
				t.Fatalf("received event %q, want %q", name, eventPasswordUpdated)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for AssetAccountPasswordUpdated on persistent A2A listener")
		case <-listener.Done():
			t.Fatalf("persistent A2A listener stopped before event: %v", listener.Err())
		}
	})
}
