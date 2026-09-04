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
	"crypto/tls"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/livetest"
)

// TestLiveCertificateConnectTLS13 proves certificate authentication negotiating
// TLS 1.3 against the appliance Cert SNI hostname.
//
// On the appliance Standard binding the certificate is requested after the
// handshake, which Go's TLS stack supports only at TLS 1.2, so the clientCert
// transport caps its maximum there by default. The appliance Cert SNI binding
// instead requests the certificate in the handshake, so an explicit
// WithMinTLSVersion(tls.VersionTLS13) both lifts that default cap and forces the
// login to negotiate TLS 1.3; a successful certificate login therefore proves
// certificate auth working over TLS 1.3.
//
// The test provisions the certificate user against the management host named by
// SPP_HOST but performs the certificate login against the Cert SNI hostname named
// by SPP_CERT_SNI_HOST. It is skipped unless SPP_CERT_SNI_HOST is set, because it
// requires appliance-side Cert SNI configuration for that hostname.
func TestLiveCertificateConnectTLS13(t *testing.T) {
	// SPP_HOST selects the management host the admin client provisions against;
	// the certificate login itself targets the Cert SNI hostname below.
	_ = livetest.Host(t)
	sniHost := strings.TrimSpace(os.Getenv("SPP_CERT_SNI_HOST"))
	if sniHost == "" {
		t.Skip("set SPP_CERT_SNI_HOST to the appliance Cert SNI hostname to run the TLS 1.3 certificate test")
	}

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

	userName, _, cleanup := livetest.ProvisionCertificateUser(adminCtx, t, admin, certPEM)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cred := safeguard.Certificate(certPEM, safeguard.Secret{}, safeguard.WithPrivateKeyPEM(keyPEM))
	opts := []safeguard.Option{safeguard.WithMinTLSVersion(tls.VersionTLS13)}
	opts = append(opts, livetest.Options(t, sniHost)...)

	client, err := safeguard.Connect(ctx, sniHost, cred, opts...)
	if err != nil {
		t.Fatalf("Connect with Certificate over TLS 1.3 against Cert SNI host %s: %v", sniHost, err)
	}
	defer func() { _ = client.Close() }()

	me, err := client.Get(ctx, safeguard.Core, "Me")
	if err != nil {
		t.Fatalf("authenticated Get Me over TLS 1.3: %v", err)
	}
	var identity struct{ Name string }
	if err := json.Unmarshal(me.Body, &identity); err != nil {
		t.Fatalf("decode Me: %v", err)
	}
	if identity.Name != userName {
		t.Errorf("authenticated as %q, want the provisioned certificate user %q", identity.Name, userName)
	}
}
