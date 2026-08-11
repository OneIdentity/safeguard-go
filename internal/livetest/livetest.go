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

// Package livetest provides shared helpers for the SDK's live-appliance
// end-to-end tests. It is an internal test-support package: it is imported only
// by _test.go files across the module (the root package and the browser and
// devicecode add-ons) so they share one appliance-bootstrap and grant-toggle
// implementation instead of each duplicating it.
//
// Every helper honors the same environment contract as the root live tests:
// SPP_HOST selects the appliance (its absence skips the test), SPP_USERNAME and
// SPP_PASSWORD supply the bootstrap admin (defaulting to admin/Admin123),
// SPP_PROVIDER selects a non-default RSTS provider, and the TLS trust is pinned
// to the appliance leaf certificate unless SPP_CA_BUNDLE names a bundle or
// SPP_INSECURE disables verification.
package livetest

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha1" //nolint:gosec // #nosec G505 -- SHA-1 is the certificate thumbprint algorithm SPP requires.
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	safeguard "github.com/OneIdentity/safeguard-go"
)

// grantSettingName is the appliance setting listing the enabled OAuth2 grant
// types. Its value is a comma-and-space separated list drawn from
// AuthorizationCode, Implicit, ResourceOwner, and DeviceCode.
const grantSettingName = "Allowed OAuth2 Grant Types"

// dialTimeout bounds the TLS handshake used to fetch the appliance leaf
// certificate.
const dialTimeout = 15 * time.Second

// Host returns the appliance host from SPP_HOST, skipping the test when it is
// unset so the live suite is inert in environments without an appliance.
func Host(tb testing.TB) string {
	tb.Helper()
	host := strings.TrimSpace(os.Getenv("SPP_HOST"))
	if host == "" {
		tb.Skip("set SPP_HOST to run live tests")
	}
	return host
}

// Creds returns the bootstrap provider, username, and password from the
// environment, defaulting the username and password to the appliance factory
// bootstrap account.
func Creds() (provider, username, password string) {
	provider = strings.TrimSpace(os.Getenv("SPP_PROVIDER"))
	username = envOr("SPP_USERNAME", "admin")
	password = envOr("SPP_PASSWORD", "Admin123")
	return provider, username, password
}

// Options returns the connection options that establish TLS trust for host,
// mirroring the root live tests: an explicit CA bundle (SPP_CA_BUNDLE), insecure
// skip-verify (SPP_INSECURE), or, by default, a pin to the appliance leaf
// certificate.
func Options(tb testing.TB, host string) []safeguard.Option {
	tb.Helper()
	if caBundle := strings.TrimSpace(os.Getenv("SPP_CA_BUNDLE")); caBundle != "" {
		// #nosec G304 -- live tests intentionally read the caller-provided CA bundle path.
		pemBytes, err := os.ReadFile(caBundle)
		if err != nil {
			tb.Fatalf("read SPP_CA_BUNDLE: %v", err)
		}
		return []safeguard.Option{safeguard.WithCABundle(pemBytes)}
	}
	if truthy(os.Getenv("SPP_INSECURE")) {
		return []safeguard.Option{safeguard.WithInsecureTLS()}
	}
	return []safeguard.Option{safeguard.WithCABundle(LeafCertPEM(tb, host))}
}

// AdminClient connects to host with the PKCE headless credential using the
// bootstrap admin account and returns the authenticated client. PKCE is used
// because it works even when the Resource Owner Grant is disabled, making it the
// dependable way to bootstrap the appliance mutations the live suite needs.
func AdminClient(ctx context.Context, tb testing.TB) *safeguard.Client {
	tb.Helper()
	host := Host(tb)
	provider, username, password := Creds()

	client, err := safeguard.Connect(ctx, host,
		safeguard.PKCEHeadless(provider, username, safeguard.NewSecretString(password)),
		Options(tb, host)...,
	)
	if err != nil {
		tb.Fatalf("connect PKCE admin against %s: %v", host, err)
	}
	return client
}

// SetGrant enables or disables an OAuth2 grant type (for example "DeviceCode" or
// "ResourceOwner") on the appliance and returns a restore function that puts the
// original setting back. It reads the current grant list, applies the change only
// if needed, and always restores the exact original value, matching how
// PySafeguard and SafeguardDotNet toggle appliance settings around their tests.
// Call the returned function with defer.
func SetGrant(ctx context.Context, tb testing.TB, client *safeguard.Client, grant string, enabled bool) func() {
	tb.Helper()
	path := "Settings/" + url.PathEscape(grantSettingName)

	original := grantValue(ctx, tb, client, path)
	desired := applyGrant(original, grant, enabled)
	if desired != original {
		putGrantValue(ctx, tb, client, path, desired)
	}

	return func() {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		putGrantValue(rctx, tb, client, path, original)
	}
}

// GrantEnabled reports whether grant is currently present in the appliance's
// enabled OAuth2 grant list.
func GrantEnabled(ctx context.Context, tb testing.TB, client *safeguard.Client, grant string) bool {
	tb.Helper()
	path := "Settings/" + url.PathEscape(grantSettingName)
	for _, g := range splitGrants(grantValue(ctx, tb, client, path)) {
		if strings.EqualFold(g, grant) {
			return true
		}
	}
	return false
}

// CertificateThumbprint returns the SHA-1 thumbprint (uppercase hex) of the first
// certificate in certPEM, matching the thumbprint format the appliance uses to map
// a certificate-authentication user to its certificate.
func CertificateThumbprint(tb testing.TB, certPEM []byte) string {
	tb.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		tb.Fatal("no CERTIFICATE block in certificate PEM")
	}
	sum := sha1.Sum(block.Bytes) //nolint:gosec // SHA-1 is the thumbprint algorithm SPP requires.
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// ProvisionCertificateUser makes certPEM usable for a certificate login against
// the appliance: it uploads the certificate as a trusted certificate and creates
// a temporary certificate-authentication user mapped to the certificate's
// thumbprint (PrimaryAuthenticationProvider Id -2, the built-in certificate
// provider), mirroring how PySafeguard, SafeguardDotNet, and SafeguardJava
// provision certificate auth for their live tests. It returns the created user's
// name and a cleanup function that deletes the user and the trusted certificate;
// call the cleanup with defer.
func ProvisionCertificateUser(ctx context.Context, tb testing.TB, client *safeguard.Client, certPEM []byte) (userName string, cleanup func()) {
	tb.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		tb.Fatal("no CERTIFICATE block in certificate PEM")
	}
	thumbprint := CertificateThumbprint(tb, certPEM)

	// Clear any trusted certificate left over from an interrupted run so the
	// upload below starts clean; ignore the not-found error that is expected on a
	// clean appliance.
	_, _ = client.Delete(ctx, safeguard.Core, "TrustedCertificates/"+thumbprint)

	if _, err := client.Post(ctx, safeguard.Core, "TrustedCertificates", map[string]any{
		"Base64CertificateData": base64.StdEncoding.EncodeToString(block.Bytes),
	}); err != nil {
		tb.Fatalf("upload trusted certificate: %v", err)
	}

	userName = "SgGo_CertUser_" + randomSuffix(tb)
	created, err := client.Post(ctx, safeguard.Core, "Users", map[string]any{
		"Name": userName,
		"PrimaryAuthenticationProvider": map[string]any{
			"Id":       -2,
			"Identity": thumbprint,
		},
	})
	if err != nil {
		_, _ = client.Delete(ctx, safeguard.Core, "TrustedCertificates/"+thumbprint)
		tb.Fatalf("create certificate user: %v", err)
	}
	var user struct {
		ID int `json:"Id"`
	}
	if err := json.Unmarshal(created.Body, &user); err != nil {
		tb.Fatalf("decode created certificate user: %v", err)
	}

	cleanup = func() {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = client.Delete(rctx, safeguard.Core, fmt.Sprintf("Users/%d", user.ID))
		_, _ = client.Delete(rctx, safeguard.Core, "TrustedCertificates/"+thumbprint)
	}
	return userName, cleanup
}

// randomSuffix returns a short random hex string used to keep provisioned test
// object names unique across runs on a shared appliance.
func randomSuffix(tb testing.TB) string {
	tb.Helper()
	var b [6]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		tb.Fatalf("random suffix: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func grantValue(ctx context.Context, tb testing.TB, client *safeguard.Client, path string) string {
	tb.Helper()
	full, err := client.Get(ctx, safeguard.Core, path)
	if err != nil {
		tb.Fatalf("get grant setting: %v", err)
	}
	var setting struct{ Value string }
	if err := json.Unmarshal(full.Body, &setting); err != nil {
		tb.Fatalf("decode grant setting: %v", err)
	}
	return setting.Value
}

// putGrantValue PUTs value as the grant setting.
func putGrantValue(ctx context.Context, tb testing.TB, client *safeguard.Client, path, value string) {
	tb.Helper()
	if _, err := client.Put(ctx, safeguard.Core, path, map[string]any{"Name": grantSettingName, "Value": value}); err != nil {
		tb.Fatalf("put grant setting %q: %v", value, err)
	}
}

// applyGrant returns the grant list with grant added or removed. The result
// keeps the appliance's comma-and-space separator.
func applyGrant(list, grant string, enabled bool) string {
	kept := make([]string, 0)
	present := false
	for _, g := range splitGrants(list) {
		if strings.EqualFold(g, grant) {
			present = true
			if !enabled {
				continue
			}
		}
		kept = append(kept, g)
	}
	if enabled && !present {
		kept = append(kept, grant)
	}
	return strings.Join(kept, ", ")
}

// splitGrants splits a grant list on commas and trims surrounding space, dropping
// empty entries.
func splitGrants(list string) []string {
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// LeafCertPEM fetches the appliance leaf certificate over a throwaway TLS dial
// and returns it PEM-encoded, so a live test can pin trust to exactly the
// certificate the appliance presents.
func LeafCertPEM(tb testing.TB, host string) []byte {
	tb.Helper()
	dialAddr, serverName := dialAddress(tb, host)
	dialer := &net.Dialer{Timeout: dialTimeout}
	// #nosec G402 -- this intentionally fetches the appliance leaf certificate before trusting it in live tests.
	conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err != nil {
		tb.Fatalf("dial appliance TLS: %v", err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		tb.Fatal("appliance returned no peer certificates")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
}

// TrustedHTTPClient returns an *http.Client that trusts the appliance at host
// using the same TLS policy as Options: an explicit CA bundle, insecure
// skip-verify, or a pin to the appliance leaf certificate. It is used by add-on
// live tests that must drive the appliance directly (for example the browser
// add-on's headless opener).
func TrustedHTTPClient(tb testing.TB, host string) *http.Client {
	tb.Helper()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case strings.TrimSpace(os.Getenv("SPP_CA_BUNDLE")) != "":
		// #nosec G304 -- live tests intentionally read the caller-provided CA bundle path.
		pemBytes, err := os.ReadFile(strings.TrimSpace(os.Getenv("SPP_CA_BUNDLE")))
		if err != nil {
			tb.Fatalf("read SPP_CA_BUNDLE: %v", err)
		}
		tlsConfig.RootCAs = poolFor(tb, pemBytes)
	case truthy(os.Getenv("SPP_INSECURE")):
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- opt-in via SPP_INSECURE for dev/test only.
	default:
		tlsConfig.RootCAs = poolFor(tb, LeafCertPEM(tb, host))
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
}

// poolFor builds a certificate pool containing the given PEM certificates.
func poolFor(tb testing.TB, pemBytes []byte) *x509.CertPool {
	tb.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		tb.Fatal("append appliance certificate to pool")
	}
	return pool
}

// dialAddress resolves host into a dial target and TLS server name, defaulting
// the port to 443.
func dialAddress(tb testing.TB, host string) (string, string) {
	tb.Helper()
	rawHost := strings.TrimSpace(host)
	if !strings.Contains(rawHost, "://") {
		rawHost = "https://" + rawHost
	}
	parsed, err := url.Parse(rawHost)
	if err != nil {
		tb.Fatalf("parse SPP_HOST: %v", err)
	}
	hostName := parsed.Hostname()
	if hostName == "" {
		tb.Fatalf("SPP_HOST %q has no hostname", host)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(hostName, port), hostName
}

// envOr returns the trimmed value of the environment variable named key, or
// fallback when it is unset or blank.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// truthy reports whether value is an affirmative flag string.
func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
