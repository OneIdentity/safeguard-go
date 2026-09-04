package safeguard

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveTLSVersions proves the WithMinTLSVersion/WithMaxTLSVersion options
// against the live appliance named by SPP_HOST. It exercises the version window
// end to end rather than only in unit tests: a rejected inverted window never
// reaches the network, a TLS 1.2 ceiling still connects, a 1.2-1.3 window
// connects, and a TLS 1.3 floor connects on an appliance that supports TLS 1.3
// or fails closed on one that does not. The TLS 1.3 subtest probes the
// appliance's capability so the same test proves the positive path on a 9.0
// appliance and the fail-closed path on an 8.x appliance.
func TestLiveTLSVersions(t *testing.T) {
	host := liveHost(t)

	t.Run("min greater than max rejected", func(t *testing.T) {
		_, err := newClient(host, WithMinTLSVersion(tls.VersionTLS13), WithMaxTLSVersion(tls.VersionTLS12))
		if !errors.Is(err, errTLSVersionRange) {
			t.Fatalf("newClient with min>max error = %v, want errTLSVersionRange", err)
		}
	})

	t.Run("max tls 1.2 connects", func(t *testing.T) {
		opts := append(liveTrustOptions(t, host), WithMaxTLSVersion(tls.VersionTLS12))
		client, err := newClient(host, opts...)
		if err != nil {
			t.Fatalf("newClient with max TLS 1.2: %v", err)
		}
		defer closeClient(t, client)
		assertLiveStatusOK(t, client)
	})

	t.Run("version window 1.2 to 1.3 connects", func(t *testing.T) {
		opts := append(liveTrustOptions(t, host), WithMinTLSVersion(tls.VersionTLS12), WithMaxTLSVersion(tls.VersionTLS13))
		client, err := newClient(host, opts...)
		if err != nil {
			t.Fatalf("newClient with TLS 1.2-1.3 window: %v", err)
		}
		defer closeClient(t, client)
		assertLiveStatusOK(t, client)
	})

	t.Run("min tls 1.3", func(t *testing.T) {
		supports13 := applianceSupportsTLS13(t, host)
		opts := append(liveTrustOptions(t, host), WithMinTLSVersion(tls.VersionTLS13))
		client, err := newClient(host, opts...)
		if err != nil {
			t.Fatalf("newClient with min TLS 1.3: %v", err)
		}
		defer closeClient(t, client)

		ctx, cancel := liveContext(t)
		defer cancel()
		_, err = client.Get(ctx, Notification, "Status")

		if supports13 {
			if err != nil {
				t.Fatalf("min TLS 1.3 Get against a TLS 1.3 appliance error = %v, want success", err)
			}
			return
		}

		if err == nil {
			t.Fatal("min TLS 1.3 Get against a non-TLS-1.3 appliance error = nil, want fail-closed error")
		}
		var transportErr *TransportError
		if !errors.As(err, &transportErr) {
			t.Fatalf("min TLS 1.3 Get against a non-TLS-1.3 appliance error = %v, want TransportError", err)
		}
	})
}

// liveTrustOptions returns the connection options that establish TLS trust for
// the live appliance, mirroring liveClient: an explicit CA bundle (SPP_CA_BUNDLE),
// insecure skip-verify (SPP_INSECURE), or a pin to the appliance leaf certificate.
// It is used by tests that need to combine the trust policy with additional
// options such as a pinned TLS version.
func liveTrustOptions(t *testing.T, host string) []Option {
	t.Helper()
	if caBundle := strings.TrimSpace(os.Getenv("SPP_CA_BUNDLE")); caBundle != "" {
		// #nosec G304 -- live tests intentionally read the caller-provided CA bundle path.
		pemBytes, err := os.ReadFile(caBundle)
		if err != nil {
			t.Fatalf("read SPP_CA_BUNDLE: %v", err)
		}
		return []Option{WithCABundle(pemBytes)}
	}
	if isTruthy(os.Getenv("SPP_INSECURE")) {
		return []Option{WithInsecureTLS()}
	}
	return []Option{WithCABundle(applianceCertPEM(t, host))}
}

// applianceSupportsTLS13 reports whether the appliance at host completes a TLS
// 1.3 handshake. It is a capability probe that lets a single live test assert the
// positive path on a TLS 1.3 appliance and the fail-closed path on one whose
// maximum is TLS 1.2, without hardcoding which appliance is under test.
func applianceSupportsTLS13(t *testing.T, host string) bool {
	t.Helper()
	dialAddr, serverName := liveDialAddress(t, host)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	// #nosec G402 -- capability probe only; it exchanges no application data.
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// appliancePassesDefaultTrust reports whether a TLS handshake to host using the
// operating system's default trust store (no CA bundle, no skip-verify) verifies
// the appliance certificate chain. It mirrors the TLS policy the SDK's
// server-trust transport uses on its default path, so a live test can assert the
// SDK reaches the same accept-or-reject verdict as the host itself.
func appliancePassesDefaultTrust(t *testing.T, host string) bool {
	t.Helper()
	dialAddr, serverName := liveDialAddress(t, host)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
