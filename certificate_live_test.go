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
	"os"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveCertificateConnect proves the Certificate credential against the
// appliance named by SPP_HOST. Because a certificate login only works once the
// appliance trusts the certificate and maps it to a user, the test provisions
// that state with an admin PKCE client: it uploads the checked-in test
// certificate (testdata/CERTS) as a trusted certificate and creates a temporary
// certificate-authentication user mapped to the certificate's thumbprint,
// removing both afterward. It then connects with the certificate over mutual TLS,
// confirms the authenticated identity is the provisioned user, and -- because a
// certificate session holds a reusable credential -- refreshes the token and
// calls the endpoint again.
func TestLiveCertificateConnect(t *testing.T) {
	host := livetest.Host(t)

	certPEM, err := os.ReadFile("testdata/CERTS/user-cert.pem")
	if err != nil {
		t.Fatalf("read test certificate: %v", err)
	}
	keyPEM, err := os.ReadFile("testdata/CERTS/user-key.pem")
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}

	adminCtx, adminCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer adminCancel()
	admin := livetest.AdminClient(adminCtx, t)
	defer func() { _ = admin.Close() }()

	userName, cleanup := livetest.ProvisionCertificateUser(adminCtx, t, admin, certPEM)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := safeguard.Connect(ctx, host,
		safeguard.Certificate(certPEM, safeguard.Secret{}, safeguard.WithPrivateKeyPEM(keyPEM)),
		livetest.Options(t, host)...,
	)
	if err != nil {
		t.Fatalf("Connect with Certificate against %s: %v", host, err)
	}
	defer func() { _ = client.Close() }()

	me, err := client.Get(ctx, safeguard.Core, "Me")
	if err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
	var identity struct{ Name string }
	if err := json.Unmarshal(me.Body, &identity); err != nil {
		t.Fatalf("decode Me: %v", err)
	}
	if identity.Name != userName {
		t.Errorf("authenticated as %q, want the provisioned certificate user %q", identity.Name, userName)
	}

	if err := client.RefreshToken(ctx); err != nil {
		t.Fatalf("RefreshToken on certificate session: %v", err)
	}
	if _, err := client.Get(ctx, safeguard.Core, "Me"); err != nil {
		t.Fatalf("Get Me after refresh: %v", err)
	}
}
