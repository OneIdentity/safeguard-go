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

package safeguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeApplianceHandler serves the RSTS grant, the Core LoginResponse exchange,
// the provider list, and an authenticated echo endpoint. It records what it saw
// so tests can assert on the exchange.
type fakeApplianceHandler struct {
	t *testing.T

	userToken string

	sawProviderLookup bool
	sawClientCert     bool
	lastGrantType     string
	lastScope         string
	lastBearer        string

	rstsStatus int
}

func (f *fakeApplianceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/RSTS/oauth2/token"):
		f.serveGrant(w, r)
	case strings.HasSuffix(r.URL.Path, "/Token/LoginResponse"):
		f.serveLogin(w, r)
	case strings.HasSuffix(r.URL.Path, "/AuthenticationProviders"):
		f.sawProviderLookup = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	case strings.HasSuffix(r.URL.Path, "/Me"):
		f.lastBearer = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Name":"admin"}`))
	default:
		f.t.Errorf("unexpected path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeApplianceHandler) serveGrant(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.PeerCertificates) > 0 {
		f.sawClientCert = true
	}
	var grant struct {
		GrantType string `json:"grant_type"`
		Scope     string `json:"scope"`
	}
	_ = json.NewDecoder(r.Body).Decode(&grant)
	f.lastGrantType = grant.GrantType
	f.lastScope = grant.Scope

	if f.rstsStatus != 0 {
		w.WriteHeader(f.rstsStatus)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"rsts-token"}`))
}

func (f *fakeApplianceHandler) serveLogin(w http.ResponseWriter, _ *http.Request) {
	token := f.userToken
	if token == "" {
		token = "user-token"
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"Status":"Success","UserToken":"` + token + `"}`))
}

func newFakeAppliance(t *testing.T, h *fakeApplianceHandler, requireClientCert bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	if requireClientCert {
		srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectUsernamePassword(t *testing.T) {
	h := &fakeApplianceHandler{t: t, userToken: "user-token-1"}
	srv := newFakeAppliance(t, h, false)

	ctx := context.Background()
	client, err := Connect(ctx, testHost(srv),
		UsernamePassword("", "admin", NewSecretString("Admin123")),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer closeClient(t, client)

	if h.sawProviderLookup {
		t.Error("empty provider must not trigger a provider lookup")
	}
	if h.lastGrantType != "password" {
		t.Errorf("grant_type = %q, want password", h.lastGrantType)
	}

	if _, err := client.Get(ctx, Core, "Me"); err != nil {
		t.Fatalf("authenticated Get: %v", err)
	}
	if h.lastBearer != "Bearer user-token-1" {
		t.Errorf("Authorization = %q, want Bearer user-token-1", h.lastBearer)
	}
}

func TestConnectToken(t *testing.T) {
	h := &fakeApplianceHandler{t: t}
	srv := newFakeAppliance(t, h, false)

	ctx := context.Background()
	client, err := Connect(ctx, testHost(srv),
		Token(NewSecretString("preexisting-token")),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.Get(ctx, Core, "Me"); err != nil {
		t.Fatalf("authenticated Get: %v", err)
	}
	if h.lastBearer != "Bearer preexisting-token" {
		t.Errorf("Authorization = %q, want Bearer preexisting-token", h.lastBearer)
	}

	if err := client.RefreshToken(ctx); !errors.Is(err, ErrNotRefreshable) {
		t.Errorf("RefreshToken on Token credential = %v, want ErrNotRefreshable", err)
	}
}

func TestConnectAnonymous(t *testing.T) {
	h := &fakeApplianceHandler{t: t}
	srv := newFakeAppliance(t, h, false)

	ctx := context.Background()
	client, err := Connect(ctx, testHost(srv),
		Anonymous(),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.Get(ctx, Core, "Me"); err != nil {
		t.Fatalf("anonymous Get: %v", err)
	}
	if h.lastBearer != "" {
		t.Errorf("anonymous request carried Authorization %q", h.lastBearer)
	}
	if _, err := client.TokenLifetimeRemaining(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("TokenLifetimeRemaining on anonymous = %v, want ErrNotAuthenticated", err)
	}
}

func TestConnectNilCredential(t *testing.T) {
	_, err := Connect(context.Background(), "example.test", nil)
	if !errors.Is(err, errNilCredential) {
		t.Fatalf("Connect nil credential = %v, want errNilCredential", err)
	}
}

func TestConnectBadPassword(t *testing.T) {
	h := &fakeApplianceHandler{t: t, rstsStatus: http.StatusBadRequest}
	srv := newFakeAppliance(t, h, false)

	_, err := Connect(context.Background(), testHost(srv),
		UsernamePassword("", "admin", NewSecretString("wrong")),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Connect bad password = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", apiErr.StatusCode)
	}
}

func TestConnectCertificate(t *testing.T) {
	h := &fakeApplianceHandler{t: t, userToken: "cert-token"}
	srv := newFakeAppliance(t, h, true)

	certPEM := generateClientCertPEM(t)

	ctx := context.Background()
	client, err := Connect(ctx, testHost(srv),
		Certificate(certPEM, Secret{}),
		WithCABundle(testServerCertPEM(t, srv)),
	)
	if err != nil {
		t.Fatalf("Connect certificate: %v", err)
	}
	defer closeClient(t, client)

	if !h.sawClientCert {
		t.Error("appliance did not observe a client certificate on the RSTS grant")
	}
	if h.lastGrantType != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", h.lastGrantType)
	}
	if h.lastScope != "rsts:sts:primaryproviderid:certificate" {
		t.Errorf("scope = %q, want default certificate scope", h.lastScope)
	}
}

func TestParseClientCertificateErrors(t *testing.T) {
	t.Run("pkcs12 rejected", func(t *testing.T) {
		_, err := parseClientCertificate([]byte{0x30, 0x82, 0x01, 0x02}, Secret{}, nil)
		if !errors.Is(err, errPKCS12Unsupported) {
			t.Fatalf("err = %v, want errPKCS12Unsupported", err)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		_, err := parseClientCertificate(certOnlyPEM(t), Secret{}, nil)
		if !errors.Is(err, errNoPrivateKeyInPEM) {
			t.Fatalf("err = %v, want errNoPrivateKeyInPEM", err)
		}
	})
	t.Run("missing cert", func(t *testing.T) {
		_, err := parseClientCertificate(keyOnlyPEM(t), Secret{}, nil)
		if !errors.Is(err, errNoCertificateInPEM) {
			t.Fatalf("err = %v, want errNoCertificateInPEM", err)
		}
	})
	t.Run("separate key input", func(t *testing.T) {
		cert, key := certAndKeyPEM(t)
		if _, err := parseClientCertificate(cert, Secret{}, key); err != nil {
			t.Fatalf("separate key input: %v", err)
		}
	})
}

// --- certificate generation helpers -----------------------------------------

func generateClientCertPEM(t *testing.T) []byte {
	t.Helper()
	cert, key := certAndKeyPEM(t)
	return append(append([]byte(nil), cert...), key...)
}

func certOnlyPEM(t *testing.T) []byte {
	t.Helper()
	cert, _ := certAndKeyPEM(t)
	return cert
}

func keyOnlyPEM(t *testing.T) []byte {
	t.Helper()
	_, key := certAndKeyPEM(t)
	return key
}

func certAndKeyPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "safeguard-go-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
