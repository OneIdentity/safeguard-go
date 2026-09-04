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
	ts := newTransportSet(&tls.Config{MinVersion: tls.VersionTLS12}, Timeouts{}, 0)
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

// TestClientCertMaxTLSResolver verifies the per-transport TLS 1.2 default cap for
// certificate auth is applied only when the caller expresses no explicit TLS
// version preference.
func TestClientCertMaxTLSResolver(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want uint16
	}{
		{"default caps clientCert to 1.2", nil, tls.VersionTLS12},
		{"explicit max disables cap", []Option{WithMaxTLSVersion(tls.VersionTLS13)}, 0},
		{"explicit min disables cap", []Option{WithMinTLSVersion(tls.VersionTLS13)}, 0},
		{"explicit max 1.2 disables cap", []Option{WithMaxTLSVersion(tls.VersionTLS12)}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultClientConfig()
			if err := cfg.apply(tc.opts...); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := cfg.clientCertMaxTLS(); got != tc.want {
				t.Fatalf("clientCertMaxTLS() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestClientCertTransportCapsMaxTLS verifies the hybrid default at the transport
// layer: with no explicit preference the clientCert transport is capped to
// TLS 1.2 while the serverTrust transport stays open to the crypto/tls maximum,
// and an explicit maximum lifts the cap on both.
func TestClientCertTransportCapsMaxTLS(t *testing.T) {
	maxVersionFor := func(t *testing.T, opts ...Option) (server, cert uint16) {
		t.Helper()
		cfg := defaultClientConfig()
		if err := cfg.apply(opts...); err != nil {
			t.Fatalf("apply: %v", err)
		}
		tlsConfig, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		ts := newTransportSet(tlsConfig, Timeouts{}, cfg.clientCertMaxTLS())
		ts.setClientCerts([]tls.Certificate{{Certificate: [][]byte{{0x01}}}})
		sc, err := ts.client(serverTrust)
		if err != nil {
			t.Fatalf("client(serverTrust): %v", err)
		}
		cc, err := ts.client(clientCert)
		if err != nil {
			t.Fatalf("client(clientCert): %v", err)
		}
		return sc.Transport.(*http.Transport).TLSClientConfig.MaxVersion,
			cc.Transport.(*http.Transport).TLSClientConfig.MaxVersion
	}

	t.Run("default", func(t *testing.T) {
		server, cert := maxVersionFor(t)
		if server != 0 {
			t.Fatalf("serverTrust MaxVersion = %d, want 0 (open)", server)
		}
		if cert != tls.VersionTLS12 {
			t.Fatalf("clientCert MaxVersion = %d, want %d", cert, tls.VersionTLS12)
		}
	})

	t.Run("explicit max 1.3 lifts the cap", func(t *testing.T) {
		server, cert := maxVersionFor(t, WithMaxTLSVersion(tls.VersionTLS13))
		if server != tls.VersionTLS13 {
			t.Fatalf("serverTrust MaxVersion = %d, want %d", server, tls.VersionTLS13)
		}
		if cert != tls.VersionTLS13 {
			t.Fatalf("clientCert MaxVersion = %d, want %d", cert, tls.VersionTLS13)
		}
	})
}

func TestBuildTLSConfigVersionWindow(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := defaultClientConfig()
		tc, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if tc.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS12)
		}
		if tc.MaxVersion != 0 {
			t.Fatalf("MaxVersion = %d, want 0 (crypto/tls default)", tc.MaxVersion)
		}
	})

	t.Run("min and max set", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithMinTLSVersion(tls.VersionTLS13), WithMaxTLSVersion(tls.VersionTLS13)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		tc, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if tc.MinVersion != tls.VersionTLS13 || tc.MaxVersion != tls.VersionTLS13 {
			t.Fatalf("versions = [%d,%d], want [%d,%d]", tc.MinVersion, tc.MaxVersion, tls.VersionTLS13, tls.VersionTLS13)
		}
	})

	t.Run("pin max to 1.2", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithMaxTLSVersion(tls.VersionTLS12)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		tc, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if tc.MaxVersion != tls.VersionTLS12 {
			t.Fatalf("MaxVersion = %d, want %d", tc.MaxVersion, tls.VersionTLS12)
		}
	})

	t.Run("sub-1.2 minimum is an explicit escape hatch", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithMinTLSVersion(tls.VersionTLS10)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		tc, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if tc.MinVersion != tls.VersionTLS10 {
			t.Fatalf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS10)
		}
	})

	t.Run("inverted range is rejected", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithMinTLSVersion(tls.VersionTLS13), WithMaxTLSVersion(tls.VersionTLS12)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		_, err := cfg.buildTLSConfig()
		if !errors.Is(err, errTLSVersionRange) {
			t.Fatalf("buildTLSConfig error = %v, want errTLSVersionRange", err)
		}
	})

	t.Run("max below default minimum is rejected", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithMaxTLSVersion(tls.VersionTLS11)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		_, err := cfg.buildTLSConfig()
		if !errors.Is(err, errTLSVersionRange) {
			t.Fatalf("buildTLSConfig error = %v, want errTLSVersionRange", err)
		}
	})

	t.Run("version window applies to the insecure transport", func(t *testing.T) {
		cfg := defaultClientConfig()
		if err := cfg.apply(WithInsecureTLS(), WithMinTLSVersion(tls.VersionTLS13)); err != nil {
			t.Fatalf("apply: %v", err)
		}
		tc, err := cfg.buildTLSConfig()
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if !tc.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify = false, want true")
		}
		if tc.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS13)
		}
	})
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
