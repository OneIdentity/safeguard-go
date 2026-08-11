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
	"os"
	"strings"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveA2ARetrieve proves A2A credential retrieval end to end against the
// appliance named by SPP_HOST. It provisions a complete A2A environment with an
// admin PKCE client -- the A2A service is enabled, the checked-in test
// certificate (testdata/CERTS) becomes a certificate user, a manually-managed
// asset and account are created with a known password, an appliance-generated SSH
// key, and an account API key with a known client secret, and the account is
// registered as Password-, PrivateKey-, and ApiKey-retrievable -- then builds an
// A2AContext from the same certificate and confirms each credential it retrieves
// over mutual TLS matches what was stored. All provisioned state is removed
// afterward.
func TestLiveA2ARetrieve(t *testing.T) {
	host := livetest.Host(t)

	certPEM, err := os.ReadFile("testdata/CERTS/user-cert.pem")
	if err != nil {
		t.Fatalf("read test certificate: %v", err)
	}
	keyPEM, err := os.ReadFile("testdata/CERTS/user-key.pem")
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	env, cleanup := livetest.ProvisionA2A(adminCtx, t, admin, certPEM)
	defer cleanup()

	a2a, err := safeguard.NewA2AContext(host, certPEM, safeguard.Secret{},
		safeguard.WithA2APrivateKeyPEM(keyPEM),
		safeguard.WithA2AConnectionOptions(livetest.Options(t, host)...),
	)
	if err != nil {
		t.Fatalf("NewA2AContext against %s: %v", host, err)
	}
	defer func() { _ = a2a.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("Password", func(t *testing.T) {
		password, err := a2a.RetrievePassword(ctx, safeguard.NewSecretString(env.PasswordAPIKey))
		if err != nil {
			t.Fatalf("RetrievePassword: %v", err)
		}
		if got := password.ExposeString(); got != env.Password {
			t.Fatalf("retrieved password = %q, want the stored password", got)
		}
	})

	t.Run("PrivateKey", func(t *testing.T) {
		key, err := a2a.RetrievePrivateKey(ctx, safeguard.NewSecretString(env.PrivateKeyAPIKey), safeguard.KeyFormatOpenSSH)
		if err != nil {
			t.Fatalf("RetrievePrivateKey: %v", err)
		}
		got := key.ExposeString()
		if !strings.Contains(got, "PRIVATE KEY") {
			t.Fatalf("retrieved private key = %q, want a PEM private key", got)
		}
	})

	t.Run("APIKeySecret", func(t *testing.T) {
		secrets, err := a2a.RetrieveAPIKeySecret(ctx, safeguard.NewSecretString(env.APIKeyAPIKey))
		if err != nil {
			t.Fatalf("RetrieveAPIKeySecret: %v", err)
		}
		if len(secrets) != 1 {
			t.Fatalf("retrieved %d API key secrets, want 1", len(secrets))
		}
		if got := secrets[0].ClientID; got != env.APIKeyClientID {
			t.Fatalf("retrieved client id = %q, want %q", got, env.APIKeyClientID)
		}
		if got := secrets[0].ClientSecret.ExposeString(); got != env.APIKeyClientSecret {
			t.Fatalf("retrieved client secret does not match the stored secret")
		}
	})

	t.Run("BogusAPIKey", func(t *testing.T) {
		// A wrong API key must be rejected, proving the API key -- not just the
		// client certificate -- authorizes the retrieval.
		if _, err := a2a.RetrievePassword(ctx, safeguard.NewSecretString("not-a-real-api-key")); err == nil {
			t.Fatal("RetrievePassword with a bogus API key = nil error, want failure")
		}
	})
}
