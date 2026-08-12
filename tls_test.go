package safeguard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestBuildTLSConfigRejectsInsecureWithValidator(t *testing.T) {
	cfg := defaultClientConfig()
	err := cfg.apply(
		WithInsecureTLS(),
		WithServerCertValidator(func(_ *x509.Certificate, _ [][]*x509.Certificate) error {
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	_, err = cfg.buildTLSConfig()
	if !errors.Is(err, errInsecureWithValidator) {
		t.Fatalf("buildTLSConfig error = %v, want errInsecureWithValidator", err)
	}
}

func TestBuildTLSConfigCABundle(t *testing.T) {
	cfg := defaultClientConfig()
	err := cfg.apply(WithCABundle([]byte("not pem")))
	if err != nil {
		t.Fatalf("apply invalid CA bundle: %v", err)
	}
	_, err = cfg.buildTLSConfig()
	if !errors.Is(err, errInvalidCABundle) {
		t.Fatalf("buildTLSConfig error = %v, want errInvalidCABundle", err)
	}

	cfg = defaultClientConfig()
	err = cfg.apply(WithCABundle(testSelfSignedCertPEM(t)))
	if err != nil {
		t.Fatalf("apply valid CA bundle: %v", err)
	}
	tlsConfig, err := cfg.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig valid CA bundle: %v", err)
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("RootCAs = nil, want non-nil")
	}
}

func TestBuildTLSConfigInsecure(t *testing.T) {
	cfg := defaultClientConfig()
	err := cfg.apply(WithInsecureTLS())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	tlsConfig, err := cfg.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
}

func TestBuildTLSConfigValidator(t *testing.T) {
	cfg := defaultClientConfig()
	err := cfg.apply(WithServerCertValidator(func(_ *x509.Certificate, _ [][]*x509.Certificate) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	tlsConfig, err := cfg.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tlsConfig.VerifyConnection == nil {
		t.Fatal("VerifyConnection = nil, want non-nil")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want %d", tlsConfig.MinVersion, tls.VersionTLS12)
	}
	// The shared config must NOT enable renegotiation; free client renegotiation
	// is scoped to the client-certificate transport only (see
	// TestClientCertTransportEnablesRenegotiation).
	if tlsConfig.Renegotiation != tls.RenegotiateNever {
		t.Fatalf("Renegotiation = %d, want %d (RenegotiateNever)", tlsConfig.Renegotiation, tls.RenegotiateNever)
	}
}

// TestClientCertTransportEnablesRenegotiation verifies that free client
// renegotiation is enabled on the client-certificate transport (for the legacy
// A2A/RSTS endpoints) but stays disabled on the shared server-trust transport.
func TestClientCertTransportEnablesRenegotiation(t *testing.T) {
	ts := newTransportSet(&tls.Config{MinVersion: tls.VersionTLS12}, Timeouts{})
	ts.setClientCerts([]tls.Certificate{{Certificate: [][]byte{{0x01}}}})

	server, err := ts.client(serverTrust)
	if err != nil {
		t.Fatalf("client(serverTrust): %v", err)
	}
	if got := server.Transport.(*http.Transport).TLSClientConfig.Renegotiation; got != tls.RenegotiateNever {
		t.Fatalf("serverTrust Renegotiation = %d, want RenegotiateNever", got)
	}

	cert, err := ts.client(clientCert)
	if err != nil {
		t.Fatalf("client(clientCert): %v", err)
	}
	if got := cert.Transport.(*http.Transport).TLSClientConfig.Renegotiation; got != tls.RenegotiateFreelyAsClient {
		t.Fatalf("clientCert Renegotiation = %d, want RenegotiateFreelyAsClient", got)
	}
}

func testSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
