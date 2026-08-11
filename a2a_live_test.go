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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

	t.Run("GetRetrievableAccounts", func(t *testing.T) {
		accounts, err := a2a.GetRetrievableAccounts(ctx, "")
		if err != nil {
			t.Fatalf("GetRetrievableAccounts: %v", err)
		}

		var match *safeguard.A2ARetrievableAccount
		for i := range accounts {
			if accounts[i].AccountID == env.AccountID {
				if match != nil {
					t.Fatalf("provisioned account listed more than once")
				}
				match = &accounts[i]
			}
		}
		if match == nil {
			t.Fatalf("provisioned account %d not found among %d retrievable accounts", env.AccountID, len(accounts))
		}
		if match.AccountName != env.AccountName {
			t.Errorf("account name = %q, want %q", match.AccountName, env.AccountName)
		}
		if match.ApplicationName == "" {
			t.Error("retrievable account has an empty application name")
		}
		if match.APIKey.ExposeString() == "" {
			t.Fatal("retrievable account has an empty API key")
		}

		// The discovered API key must actually authorize retrieval, proving the
		// enumeration returns a usable credential and not just metadata.
		password, err := a2a.RetrievePassword(ctx, match.APIKey)
		if err != nil {
			t.Fatalf("RetrievePassword with discovered API key: %v", err)
		}
		if got := password.ExposeString(); got != env.Password {
			t.Fatalf("retrieved password = %q, want the stored password", got)
		}
	})
}

// TestLiveA2ASet proves A2A credential write-back end to end against the appliance
// named by SPP_HOST. It provisions its own A2A environment (whose registration is
// bidirectional), then, over mutual TLS, sets a new account password and a new SSH
// private key with the A2A API keys and confirms each change by retrieving the
// credential back. It uses a separate environment from TestLiveA2ARetrieve so the
// mutations do not disturb the read-only assertions. All state is removed
// afterward.
func TestLiveA2ASet(t *testing.T) {
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

	t.Run("SetPassword", func(t *testing.T) {
		newPassword := "SgGo-A2ASet-" + strings.ReplaceAll(t.Name(), "/", "-") + "!2"
		apiKey := safeguard.NewSecretString(env.PasswordAPIKey)
		if err := a2a.SetPassword(ctx, apiKey, safeguard.NewSecretString(newPassword)); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}
		got, err := a2a.RetrievePassword(ctx, apiKey)
		if err != nil {
			t.Fatalf("RetrievePassword after SetPassword: %v", err)
		}
		if got.ExposeString() != newPassword {
			t.Fatal("retrieved password does not match the one just set")
		}
		if got.ExposeString() == env.Password {
			t.Fatal("password was not changed from the provisioned value")
		}
	})

	t.Run("SetPrivateKey", func(t *testing.T) {
		apiKey := safeguard.NewSecretString(env.PrivateKeyAPIKey)
		before, err := a2a.RetrievePrivateKey(ctx, apiKey, safeguard.KeyFormatOpenSSH)
		if err != nil {
			t.Fatalf("RetrievePrivateKey before SetPrivateKey: %v", err)
		}

		newKey := newRSAPrivateKeyPEM(t)
		if err := a2a.SetPrivateKey(ctx, apiKey, safeguard.NewSecretString(newKey), safeguard.Secret{}, safeguard.KeyFormatOpenSSH); err != nil {
			t.Fatalf("SetPrivateKey: %v", err)
		}
		after, err := a2a.RetrievePrivateKey(ctx, apiKey, safeguard.KeyFormatOpenSSH)
		if err != nil {
			t.Fatalf("RetrievePrivateKey after SetPrivateKey: %v", err)
		}
		if !strings.Contains(after.ExposeString(), "PRIVATE KEY") {
			t.Fatalf("retrieved key after set = %q, want a PEM private key", after.ExposeString())
		}
		if after.ExposeString() == before.ExposeString() {
			t.Fatal("private key was not changed by SetPrivateKey")
		}
	})
}

// TestLiveA2ABroker proves A2A access-request brokering end to end against the
// appliance named by SPP_HOST. It provisions its own environment -- an asset and
// account, a certificate user authorized to broker, a target user with an
// auto-approving Password access policy scoped to the account, and the
// registration's access request broker -- then, over mutual TLS, brokers a
// Password access request for the target user with the broker API key and
// confirms the appliance created it and auto-approved it to the RequestAvailable
// state. The brokered request is closed and all provisioned state is removed
// afterward.
func TestLiveA2ABroker(t *testing.T) {
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

	env, cleanup := livetest.ProvisionA2ABroker(adminCtx, t, admin, certPEM)
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

	req, err := a2a.BrokerAccessRequest(ctx, safeguard.NewSecretString(env.BrokerAPIKey), safeguard.BrokeredAccessRequest{
		AccessRequestType: safeguard.AccessRequestPassword,
		ForUserID:         env.ForUserID,
		AssetID:           env.AssetID,
		AccountID:         env.AccountID,
	})
	if err != nil {
		t.Fatalf("BrokerAccessRequest: %v", err)
	}
	// Close the brokered request before teardown so it does not hold the account.
	if req.ID != "" {
		defer func() {
			_, _ = env.Admin.Post(ctx, safeguard.Core, "AccessRequests/"+req.ID+"/Close", nil)
		}()
	}

	if req.ID == "" {
		t.Fatal("brokered access request has no Id")
	}
	if req.State != "RequestAvailable" {
		t.Fatalf("brokered access request state = %q, want %q (auto-approval should make it immediately available)", req.State, "RequestAvailable")
	}
	if req.AccountID != env.AccountID {
		t.Errorf("brokered request account id = %d, want %d", req.AccountID, env.AccountID)
	}
	if req.AccessRequestType != safeguard.AccessRequestPassword {
		t.Errorf("brokered request type = %q, want %q", req.AccessRequestType, safeguard.AccessRequestPassword)
	}
}

// newRSAPrivateKeyPEM returns a freshly generated 2048-bit RSA private key in
// PKCS#1 PEM form, for proving SetPrivateKey changes the stored key.
func newRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}
