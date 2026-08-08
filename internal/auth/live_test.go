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

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Live appliance end-to-end is the authoritative standard for the auth broker:
// the fake-appliance unit tests are a fast supplement, but the real proof that a
// login flow works is a two-step exchange against a running Safeguard. This test
// runs the password (Resource Owner Grant) login against the appliance named by
// SPP_HOST and is skipped entirely when SPP_HOST is unset, so ordinary
// `go test ./...` stays hermetic.
//
// Environment:
//
//	SPP_HOST      appliance host, e.g. spp1.dan.laptop or 192.168.99.15 (required)
//	SPP_USERNAME  bootstrap user (default "admin")
//	SPP_PASSWORD  bootstrap password (default "Admin123")
//	SPP_PROVIDER  authentication provider (default "" -> local scope)
//	SPP_INSECURE  when truthy, skip TLS verification instead of pinning the leaf
func TestLivePasswordLogin(t *testing.T) {
	host := strings.TrimSpace(os.Getenv("SPP_HOST"))
	if host == "" {
		t.Skip("set SPP_HOST to run live auth tests")
	}

	username := envOr("SPP_USERNAME", "admin")
	password := envOr("SPP_PASSWORD", "Admin123")
	provider := strings.TrimSpace(os.Getenv("SPP_PROVIDER"))

	client := liveHTTPClient(t, host)
	cfg := Config{
		Host:           host,
		APIVersion:     "v4",
		HTTPClient:     client,
		CertHTTPClient: client,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := LoginPassword(ctx, cfg, provider, username, []byte(password))
	if err != nil {
		if isROGDisabled(err) {
			t.Skipf("appliance %s has Resource Owner Grant disabled; password login is expected to be unavailable (use PKCE-headless): %v", host, err)
		}
		t.Fatalf("LoginPassword against %s: %v", host, err)
	}
	if len(token) == 0 {
		t.Fatal("live login returned an empty user token")
	}
	zero(token)
}

// isROGDisabled reports whether err is the appliance rejecting the Resource
// Owner Grant because that grant type is disabled. Such appliances are a
// supported configuration (PKCE-headless is the intended automation flow), so
// live password tests skip rather than fail on this condition.
func isROGDisabled(err error) bool {
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.StatusCode != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(string(reqErr.Body())), "grant type is not allowed")
}

// liveHTTPClient builds an HTTP client that trusts the live appliance, pinning
// its leaf certificate unless SPP_INSECURE requests skipping verification.
func liveHTTPClient(t *testing.T, host string) *http.Client {
	t.Helper()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if truthy(os.Getenv("SPP_INSECURE")) {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- opt-in for bootstrap/dev appliances via SPP_INSECURE.
	} else {
		dialAddr, serverName := liveDialAddress(t, host)
		leaf := fetchLeafCert(t, dialAddr, serverName)
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		tlsCfg.RootCAs = pool
		tlsCfg.ServerName = serverName
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// fetchLeafCert dials the appliance once to capture its leaf certificate so the
// test can pin it, mirroring the root package's live-test trust bootstrap.
func fetchLeafCert(t *testing.T, dialAddr, serverName string) *x509.Certificate {
	t.Helper()

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	// #nosec G402 -- intentionally captures the appliance leaf certificate before trusting it.
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err != nil {
		t.Fatalf("dial appliance TLS: %v", err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("appliance returned no peer certificates")
	}
	return certs[0]
}

// liveDialAddress splits SPP_HOST into a dial address and TLS server name,
// defaulting the port to 443.
func liveDialAddress(t *testing.T, host string) (string, string) {
	t.Helper()

	raw := strings.TrimSpace(host)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse SPP_HOST: %v", err)
	}
	name := parsed.Hostname()
	if name == "" {
		t.Fatalf("SPP_HOST %q has no hostname", host)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(name, port), name
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
