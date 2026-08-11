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
// name, its object ID, and a cleanup function that deletes the user and the
// trusted certificate; call the cleanup with defer.
func ProvisionCertificateUser(ctx context.Context, tb testing.TB, client *safeguard.Client, certPEM []byte) (userName string, userID int, cleanup func()) {
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
	return userName, user.ID, cleanup
}

// A2AEnv describes the A2A environment provisioned by ProvisionA2A: the object
// IDs created on the appliance, the known password stored on the account, and the
// API key that authorizes A2A password retrieval for that account.
type A2AEnv struct {
	// CertUserName is the name of the certificate user the registration is bound
	// to.
	CertUserName string
	// RegistrationID is the A2A registration's object ID.
	RegistrationID int
	// AssetID is the manually-managed asset's object ID.
	AssetID int
	// AccountID is the asset account's object ID.
	AccountID int
	// AccountName is the asset account's name.
	AccountName string
	// Password is the password stored on the account, for round-trip assertions.
	Password string
	// PasswordAPIKey authorizes A2A retrieval of the account password.
	PasswordAPIKey string
	// PrivateKeyAPIKey authorizes A2A retrieval of the account's SSH private key.
	PrivateKeyAPIKey string
	// APIKeyAPIKey authorizes A2A retrieval of the account's API key secret.
	APIKeyAPIKey string
	// APIKeyClientID is the client identifier stored on the account API key, for
	// round-trip assertions.
	APIKeyClientID string
	// APIKeyClientSecret is the client secret stored on the account API key, for
	// round-trip assertions.
	APIKeyClientSecret string
}

// ProvisionA2A stands up a complete A2A environment for host so a live test can
// retrieve a password over the A2A service with the client certificate in
// certPEM. It enables the A2A service, provisions a certificate user to bind the
// registration to, and -- because the bootstrap admin is deliberately not an
// Asset or Policy admin -- creates a temporary local admin user granted only the
// AssetAdmin and PolicyAdmin roles and performs the privileged provisioning as
// that user: a manually-managed asset (PlatformId 501, "Other Managed") and
// account, a known password stored on the account, an appliance-generated SSH key
// and an account API key with a known client secret, an A2A registration bound to
// the certificate user, and the account added as Password-, PrivateKey-, and
// ApiKey-retrievable entries whose generated API keys are read back. The flow
// mirrors PySafeguard's A2A integration test (tests/integration/test_a2a.py). The
// returned cleanup deletes everything -- registration, account, asset (as the temp
// admin), then the temp admin, certificate user, and trusted certificate (as the
// bootstrap admin) -- in dependency order; call it with defer.
func ProvisionA2A(ctx context.Context, tb testing.TB, client *safeguard.Client, certPEM []byte) (env A2AEnv, cleanup func()) {
	tb.Helper()
	host := Host(tb)

	// The A2A service is disabled by default on a Safeguard appliance and must be
	// enabled before any retrieval works; the call is idempotent.
	if _, err := client.Post(ctx, safeguard.Appliance, "A2AService/Enable", nil); err != nil {
		tb.Fatalf("enable A2A service: %v", err)
	}

	certUserName, certUserID, certCleanup := ProvisionCertificateUser(ctx, tb, client, certPEM)
	env.CertUserName = certUserName

	suffix := randomSuffix(tb)

	// The bootstrap admin can manage users but not assets or A2A registrations, so
	// provision those as a throwaway local admin granted just the two roles the
	// job needs. It authenticates with PKCE, which works even when the Resource
	// Owner Grant is disabled.
	adminName := "SgGo_A2AAdmin_" + suffix
	adminPass := "SgGo-A2AAdm-" + suffix + "!1"
	adminCreated := postJSON(ctx, tb, client, "Users", map[string]any{
		"Name":                          adminName,
		"PrimaryAuthenticationProvider": map[string]any{"Id": -1, "Identity": adminName},
		"AdminRoles":                    []string{"AssetAdmin", "PolicyAdmin"},
	}, "create temp A2A admin user")
	adminID := idOf(tb, adminCreated, "temp admin user")
	if _, err := client.Put(ctx, safeguard.Core, fmt.Sprintf("Users/%d/Password", adminID), jsonString(adminPass)); err != nil {
		_, _ = client.Delete(ctx, safeguard.Core, fmt.Sprintf("Users/%d", adminID))
		certCleanup()
		tb.Fatalf("set temp admin password: %v", err)
	}

	provAdmin, err := safeguard.Connect(ctx, host,
		safeguard.PKCEHeadless("", adminName, safeguard.NewSecretString(adminPass)),
		Options(tb, host)...,
	)
	if err != nil {
		_, _ = client.Delete(ctx, safeguard.Core, fmt.Sprintf("Users/%d", adminID))
		certCleanup()
		tb.Fatalf("connect temp A2A admin: %v", err)
	}

	// Track created objects so a failure partway through still tears down. Assets,
	// accounts, and registrations are removed by the temp admin that owns the
	// roles; the certificate user, trusted certificate, and temp admin are removed
	// by the bootstrap admin.
	cleanup = func() {
		rctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if env.RegistrationID != 0 {
			_, _ = provAdmin.Delete(rctx, safeguard.Core, fmt.Sprintf("A2ARegistrations/%d", env.RegistrationID))
		}
		if env.AccountID != 0 {
			_, _ = provAdmin.Delete(rctx, safeguard.Core, fmt.Sprintf("AssetAccounts/%d", env.AccountID))
		}
		if env.AssetID != 0 {
			_, _ = provAdmin.Delete(rctx, safeguard.Core, fmt.Sprintf("Assets/%d", env.AssetID))
		}
		_ = provAdmin.Close()
		certCleanup()
		_, _ = client.Delete(rctx, safeguard.Core, fmt.Sprintf("Users/%d", adminID))
	}
	// Ensure teardown runs if a later provisioning step fails this test.
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

	asset := postJSON(ctx, tb, provAdmin, "Assets", map[string]any{
		"Name":             "SgGo_A2AAsset_" + suffix,
		"NetworkAddress":   "127.0.0.1",
		"PlatformId":       501,
		"AssetPartitionId": -1,
	}, "create A2A asset")
	env.AssetID = idOf(tb, asset, "asset")

	env.AccountName = "SgGo_A2AAccount_" + suffix
	account := postJSON(ctx, tb, provAdmin, "AssetAccounts", map[string]any{
		"Name":  env.AccountName,
		"Asset": map[string]any{"Id": env.AssetID},
	}, "create A2A account")
	env.AccountID = idOf(tb, account, "account")

	env.Password = "SgGo-A2A-" + suffix + "!1"
	if _, err := provAdmin.Put(ctx, safeguard.Core, fmt.Sprintf("AssetAccounts/%d/Password", env.AccountID), jsonString(env.Password)); err != nil {
		tb.Fatalf("store account password: %v", err)
	}

	// Store an SSH key on the account so a PrivateKey credential can be retrieved.
	// Providing no PrivateKey has the appliance generate one, which is sufficient
	// to prove retrieval and avoids embedding key material in the test.
	if _, err := provAdmin.Put(ctx, safeguard.Core, fmt.Sprintf("AssetAccounts/%d/SshKey?keyFormat=OpenSsh", env.AccountID), map[string]any{
		"KeyType":   "RSA",
		"KeyLength": 2048,
	}); err != nil {
		tb.Fatalf("store account ssh key: %v", err)
	}

	// Create an account API key and set a known client id/secret on it so an
	// ApiKey credential can be retrieved and its secret asserted.
	env.APIKeyClientID = "sggo-a2a-client-" + suffix
	env.APIKeyClientSecret = "sggo-a2a-secret-" + suffix
	apiKey := postJSON(ctx, tb, provAdmin, fmt.Sprintf("AssetAccounts/%d/ApiKeys", env.AccountID), map[string]any{
		"Name": "SgGo_A2AKey_" + suffix,
	}, "create account API key")
	apiKeyID := idOf(tb, apiKey, "account API key")
	if _, err := provAdmin.Put(ctx, safeguard.Core, fmt.Sprintf("AssetAccounts/%d/ApiKeys/%d/ClientSecret", env.AccountID, apiKeyID), map[string]any{
		"ClientId":     env.APIKeyClientID,
		"ClientSecret": env.APIKeyClientSecret,
	}); err != nil {
		tb.Fatalf("set account API key secret: %v", err)
	}

	registration := postJSON(ctx, tb, provAdmin, "A2ARegistrations", map[string]any{
		"AppName":                   "SgGo_A2AReg_" + suffix,
		"CertificateUserId":         certUserID,
		"VisibleToCertificateUsers": true,
		"BidirectionalEnabled":      true,
	}, "create A2A registration")
	env.RegistrationID = idOf(tb, registration, "registration")

	env.PasswordAPIKey = addRetrievable(ctx, tb, provAdmin, env.RegistrationID, env.AccountID, "Password")
	env.PrivateKeyAPIKey = addRetrievable(ctx, tb, provAdmin, env.RegistrationID, env.AccountID, "PrivateKey")
	env.APIKeyAPIKey = addRetrievable(ctx, tb, provAdmin, env.RegistrationID, env.AccountID, "ApiKey")

	ok = true
	return env, cleanup
}

// addRetrievable adds accountID to the registration as a retrievable account of
// the given credential type and returns the generated per-credential API key.
func addRetrievable(ctx context.Context, tb testing.TB, client *safeguard.Client, registrationID, accountID int, credType string) string {
	tb.Helper()
	body := postJSON(ctx, tb, client, fmt.Sprintf("A2ARegistrations/%d/RetrievableAccounts", registrationID), map[string]any{
		"AccountId": accountID,
		"Type":      credType,
	}, "add "+credType+" retrievable account")
	var ra struct {
		APIKey string `json:"ApiKey"`
	}
	if err := json.Unmarshal(body, &ra); err != nil {
		tb.Fatalf("decode %s retrievable account: %v", credType, err)
	}
	if ra.APIKey == "" {
		tb.Fatalf("%s retrievable account returned an empty ApiKey", credType)
	}
	return ra.APIKey
}

// jsonString returns s encoded as a JSON string value. Safeguard endpoints such
// as the user and account password setters take a bare JSON string body (for
// example "secret"), which is distinct from sending the raw characters.
func jsonString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return json.RawMessage(b)
}

// postJSON POSTs body to the Core service path and returns the response body,
// failing the test on error.
func postJSON(ctx context.Context, tb testing.TB, client *safeguard.Client, path string, body any, what string) []byte {
	tb.Helper()
	full, err := client.Post(ctx, safeguard.Core, path, body)
	if err != nil {
		tb.Fatalf("%s: %v", what, err)
	}
	return full.Body
}

// idOf decodes the "Id" field from a created-object response body.
func idOf(tb testing.TB, body []byte, what string) int {
	tb.Helper()
	var obj struct {
		ID int `json:"Id"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		tb.Fatalf("decode created %s: %v", what, err)
	}
	if obj.ID == 0 {
		tb.Fatalf("created %s has no Id", what)
	}
	return obj.ID
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
