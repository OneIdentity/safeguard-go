package safeguard

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func liveClient(t *testing.T, opts ...Option) *Client {
	t.Helper()

	host := liveHost(t)
	if len(opts) == 0 {
		if caBundle := strings.TrimSpace(os.Getenv("SPP_CA_BUNDLE")); caBundle != "" {
			// #nosec G304 -- live tests intentionally read the caller-provided CA bundle path.
			pemBytes, err := os.ReadFile(caBundle)
			if err != nil {
				t.Fatalf("read SPP_CA_BUNDLE: %v", err)
			}
			opts = append(opts, WithCABundle(pemBytes))
		} else if isTruthy(os.Getenv("SPP_INSECURE")) {
			opts = append(opts, WithInsecureTLS())
		} else {
			opts = append(opts, WithCABundle(applianceCertPEM(t, host)))
		}
	}

	client, err := newClient(host, opts...)
	if err != nil {
		t.Fatalf("newClient live: %v", err)
	}
	return client
}

func liveHost(t *testing.T) string {
	t.Helper()

	host := strings.TrimSpace(os.Getenv("SPP_HOST"))
	if host == "" {
		t.Skip("set SPP_HOST to run live tests")
	}
	return host
}

func requireLive(t *testing.T) {
	t.Helper()
	_ = liveHost(t)
}

func applianceCertPEM(t *testing.T, host string) []byte {
	t.Helper()

	dialAddr, serverName := liveDialAddress(t, host)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	// #nosec G402 -- this intentionally fetches the appliance leaf certificate before trusting it in live tests.
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err != nil {
		t.Fatalf("dial appliance TLS: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("close TLS connection: %v", err)
		}
	}()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("appliance returned no peer certificates")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
}

func liveDialAddress(t *testing.T, host string) (string, string) {
	t.Helper()

	rawHost := strings.TrimSpace(host)
	if !strings.Contains(rawHost, "://") {
		rawHost = "https://" + rawHost
	}
	parsed, err := url.Parse(rawHost)
	if err != nil {
		t.Fatalf("parse SPP_HOST: %v", err)
	}
	if parsed.Host == "" {
		t.Fatalf("SPP_HOST %q has no host", host)
	}
	hostName := parsed.Hostname()
	if hostName == "" {
		t.Fatalf("SPP_HOST %q has no hostname", host)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(hostName, port), hostName
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
