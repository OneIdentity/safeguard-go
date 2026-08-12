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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestA2AContext builds an A2AContext wired to an httptest TLS server, trusting
// the server's certificate and presenting a freshly generated client certificate.
func newTestA2AContext(t *testing.T, handler http.Handler) (*A2AContext, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	a2a, err := NewA2AContext(
		testHost(server),
		generateClientCertPEM(t),
		Secret{},
		WithA2AConnectionOptions(WithCABundle(testServerCertPEM(t, server))),
	)
	if err != nil {
		server.Close()
		t.Fatalf("NewA2AContext: %v", err)
	}
	return a2a, server
}

func closeA2A(t *testing.T, a *A2AContext) {
	t.Helper()
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestA2ARetrievePassword(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotAuth string
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `"s3cr3t"`)
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	apiKey := NewSecretString("api-key-123")
	defer apiKey.Zero()

	pw, err := a2a.RetrievePassword(context.Background(), apiKey)
	if err != nil {
		t.Fatalf("RetrievePassword: %v", err)
	}
	defer pw.Zero()

	if pw.ExposeString() != "s3cr3t" {
		t.Fatalf("password = %q, want %q", pw.ExposeString(), "s3cr3t")
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/service/a2a/v4/Credentials" {
		t.Fatalf("path = %q, want /service/a2a/v4/Credentials", gotPath)
	}
	if gotQuery != "type=Password" {
		t.Fatalf("query = %q, want type=Password", gotQuery)
	}
	if gotAuth != "A2A api-key-123" {
		t.Fatalf("auth = %q, want %q", gotAuth, "A2A api-key-123")
	}
}

func TestA2ARetrievePrivateKeyFormat(t *testing.T) {
	var gotQuery string
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, `"-----BEGIN OPENSSH PRIVATE KEY-----"`)
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	apiKey := NewSecretString("k")
	defer apiKey.Zero()

	// An empty format must default to OpenSSH.
	if _, err := a2a.RetrievePrivateKey(context.Background(), apiKey, ""); err != nil {
		t.Fatalf("RetrievePrivateKey: %v", err)
	}
	if gotQuery != "keyFormat=OpenSsh&type=PrivateKey" {
		t.Fatalf("query = %q, want keyFormat=OpenSsh&type=PrivateKey", gotQuery)
	}

	if _, err := a2a.RetrievePrivateKey(context.Background(), apiKey, KeyFormatPuTTY); err != nil {
		t.Fatalf("RetrievePrivateKey: %v", err)
	}
	if gotQuery != "keyFormat=Putty&type=PrivateKey" {
		t.Fatalf("query = %q, want keyFormat=Putty&type=PrivateKey", gotQuery)
	}
}

func TestA2ARetrieveAPIKeySecret(t *testing.T) {
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "type=ApiKey" {
			t.Errorf("query = %q, want type=ApiKey", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"Id":7,"Name":"key","ClientId":"cid","ClientSecret":"shh","ClientSecretId":"csid"}]`)
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	apiKey := NewSecretString("k")
	defer apiKey.Zero()

	keys, err := a2a.RetrieveAPIKeySecret(context.Background(), apiKey)
	if err != nil {
		t.Fatalf("RetrieveAPIKeySecret: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	if keys[0].ID != 7 || keys[0].ClientID != "cid" {
		t.Fatalf("key = %+v, want ID 7 / ClientID cid", keys[0])
	}
	if got := keys[0].ClientSecret.ExposeString(); got != "shh" {
		t.Fatalf("ClientSecret = %q, want shh", got)
	}
}

func TestA2ASetPassword(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody []byte
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	apiKey := NewSecretString("brokerkey")
	defer apiKey.Zero()
	newPassword := NewSecretString("n3wp@ss")
	defer newPassword.Zero()

	if err := a2a.SetPassword(context.Background(), apiKey, newPassword); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/service/a2a/v4/Credentials/Password" {
		t.Fatalf("path = %q, want /service/a2a/v4/Credentials/Password", gotPath)
	}
	if gotAuth != "A2A brokerkey" {
		t.Fatalf("auth = %q, want A2A brokerkey", gotAuth)
	}
	// The body is the bare JSON string form the appliance expects.
	if string(gotBody) != `"n3wp@ss"` {
		t.Fatalf("body = %q, want %q", string(gotBody), `"n3wp@ss"`)
	}
}

func TestA2AGetRetrievableAccounts(t *testing.T) {
	var sawFilter bool
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/service/core/v4/A2ARegistrations":
			_, _ = io.WriteString(w, `[{"Id":1,"AppName":"app-a","Disabled":false},{"Id":2,"AppName":"app-b","Disabled":true}]`)
		case "/service/core/v4/A2ARegistrations/1/RetrievableAccounts":
			if r.URL.Query().Get("filter") == "AssetName eq 'db'" {
				sawFilter = true
			}
			_, _ = io.WriteString(w, `[{"ApiKey":"key1","AssetName":"db","AccountName":"sa","AccountType":"Other","AccountDisabled":0}]`)
		case "/service/core/v4/A2ARegistrations/2/RetrievableAccounts":
			_, _ = io.WriteString(w, `[{"ApiKey":"key2","AssetName":"web","AccountName":"root","AccountDisabled":0}]`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	accounts, err := a2a.GetRetrievableAccounts(context.Background(), "AssetName eq 'db'")
	if err != nil {
		t.Fatalf("GetRetrievableAccounts: %v", err)
	}
	if !sawFilter {
		t.Fatal("filter was not forwarded to the RetrievableAccounts call")
	}
	if len(accounts) != 2 {
		t.Fatalf("len(accounts) = %d, want 2", len(accounts))
	}
	if accounts[0].APIKey.ExposeString() != "key1" || accounts[0].AssetName != "db" {
		t.Fatalf("accounts[0] = %+v, want APIKey key1 / AssetName db", accounts[0])
	}
	// The second registration is disabled, so its account is reported disabled
	// even though the account's own AccountDisabled flag is 0.
	if !accounts[1].Disabled {
		t.Fatalf("accounts[1].Disabled = false, want true (registration disabled)")
	}
}

func TestA2AErrorMapping(t *testing.T) {
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"Code":60638,"Message":"Access denied."}`)
	}))
	defer server.Close()
	defer closeA2A(t, a2a)

	apiKey := NewSecretString("k")
	defer apiKey.Zero()

	_, err := a2a.RetrievePassword(context.Background(), apiKey)
	var forbidden *AuthorizationError
	if !errors.As(err, &forbidden) {
		t.Fatalf("err = %v, want AuthorizationError", err)
	}
}

func TestA2AClosedContext(t *testing.T) {
	a2a, server := newTestA2AContext(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := a2a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent.
	if err := a2a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	apiKey := NewSecretString("k")
	defer apiKey.Zero()
	if _, err := a2a.RetrievePassword(context.Background(), apiKey); !errors.Is(err, ErrClosed) {
		t.Fatalf("RetrievePassword after Close = %v, want ErrClosed", err)
	}
}
