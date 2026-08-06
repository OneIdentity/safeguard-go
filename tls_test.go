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
	if tlsConfig.Renegotiation != tls.RenegotiateFreelyAsClient {
		t.Fatalf("Renegotiation = %d, want %d", tlsConfig.Renegotiation, tls.RenegotiateFreelyAsClient)
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
