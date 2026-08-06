package safeguard

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEncodeBody(t *testing.T) {
	type payload struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	cases := []struct {
		name            string
		body            any
		wantContentType string
		wantBody        string
		wantNilReader   bool
	}{
		{name: "nil", body: nil, wantNilReader: true},
		{name: "empty string", body: "", wantNilReader: true},
		{name: "string", body: "abc", wantContentType: "application/json", wantBody: "abc"},
		{name: "bytes", body: []byte("abc"), wantContentType: "application/octet-stream", wantBody: "abc"},
		{name: "empty bytes", body: []byte{}, wantNilReader: true},
		{name: "raw json", body: json.RawMessage(`{"x":1}`), wantContentType: "application/json", wantBody: `{"x":1}`},
		{name: "struct", body: payload{A: "x", B: 2}, wantContentType: "application/json", wantBody: `{"a":"x","b":2}`},
		{name: "reader", body: strings.NewReader("stream"), wantContentType: "application/octet-stream", wantBody: "stream"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader, contentType, err := encodeBody(tc.body)
			if err != nil {
				t.Fatalf("encodeBody: %v", err)
			}
			if contentType != tc.wantContentType {
				t.Fatalf("contentType = %q, want %q", contentType, tc.wantContentType)
			}
			if tc.wantNilReader {
				if reader != nil {
					t.Fatalf("reader = %T, want nil", reader)
				}
				return
			}
			if reader == nil {
				t.Fatal("reader = nil, want non-nil")
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != tc.wantBody {
				t.Fatalf("body = %q, want %q", string(got), tc.wantBody)
			}
		})
	}
}

func TestJoinURL(t *testing.T) {
	params := url.Values{}
	params.Set("k", "v")

	cases := []struct {
		name   string
		base   string
		rel    string
		params url.Values
		want   string
	}{
		{name: "relative no slash", base: "https://h/service/core/v4/", rel: "Users", want: "https://h/service/core/v4/Users"},
		{name: "relative leading slash", base: "https://h/service/core/v4/", rel: "/Users", want: "https://h/service/core/v4/Users"},
		{name: "query", base: "https://h/service/core/v4/", rel: "Users", params: params, want: "https://h/service/core/v4/Users?k=v"},
		{name: "existing query", base: "https://h/service/core/v4/Users?existing=1", rel: "", params: params, want: "https://h/service/core/v4/Users?existing=1&k=v"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinURL(tc.base, tc.rel, tc.params); got != tc.want {
				t.Fatalf("joinURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInvokeSurfacesRedirectWithoutFollowing(t *testing.T) {
	var redirectHit atomic.Bool
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-target" {
			redirectHit.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))
	defer server.Close()
	defer closeClient(t, client)

	full, err := client.Get(context.Background(), Notification, "Status")
	if err == nil {
		t.Fatal("Get redirect error = nil, want APIError")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Get redirect error = %v, want APIError", err)
	}
	if got, want := full.StatusCode, http.StatusFound; got != want {
		t.Fatalf("StatusCode = %d, want %d", got, want)
	}
	if redirectHit.Load() {
		t.Fatal("redirect target was hit")
	}
}

func TestInvokeErrorMapping(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"Code":60155,"Message":"Missing 'StsAccessToken' parameter."}`))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	_, err := client.Post(context.Background(), Core, "Token/LoginResponse", map[string]any{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Post error = %v, want APIError", err)
	}
	if got, want := apiErr.Code, 60155; got != want {
		t.Fatalf("Code = %d, want %d", got, want)
	}
}

func TestInvokeTypedDecodesJSON(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"name":"ok"}`))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	got, err := InvokeTyped[struct {
		Name string `json:"name"`
	}](context.Background(), client, MethodGet, Notification, "Status", nil)
	if err != nil {
		t.Fatalf("InvokeTyped: %v", err)
	}
	if got.Name != "ok" {
		t.Fatalf("Name = %q, want ok", got.Name)
	}
}

func TestVerbHelpersHitMethodAndPath(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.Method + " " + r.URL.Path))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	cases := []struct {
		name string
		call func() (FullResponse, error)
		want string
	}{
		{name: "get", call: func() (FullResponse, error) { return client.Get(context.Background(), Core, "Thing") }, want: "GET /service/core/v4/Thing"},
		{name: "post", call: func() (FullResponse, error) { return client.Post(context.Background(), Core, "Thing", "body") }, want: "POST /service/core/v4/Thing"},
		{name: "put", call: func() (FullResponse, error) { return client.Put(context.Background(), Core, "Thing", "body") }, want: "PUT /service/core/v4/Thing"},
		{name: "delete", call: func() (FullResponse, error) { return client.Delete(context.Background(), Core, "Thing") }, want: "DELETE /service/core/v4/Thing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full, err := tc.call()
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if got := full.String(); got != tc.want {
				t.Fatalf("response = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInvokeContentType(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.Header.Get("Content-Type")))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	full, err := client.Post(context.Background(), Core, "Thing", "body")
	if err != nil {
		t.Fatalf("Post default content type: %v", err)
	}
	if got, want := full.String(), "application/json"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}

	full, err = client.Post(context.Background(), Core, "Thing", "body", WithHeader("Content-Type", "text/csv"))
	if err != nil {
		t.Fatalf("Post override content type: %v", err)
	}
	if got, want := full.String(), "text/csv"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
}

func TestInvokeQueryAndAPIVersionOverride(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.URL.Path + "?" + r.URL.RawQuery))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	full, err := client.Get(context.Background(), Core, "Thing", WithQueryParam("k", "v"), WithAPIVersionOverride("v3"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := full.String(), "/service/core/v3/Thing?k=v"; got != want {
		t.Fatalf("path/query = %q, want %q", got, want)
	}
}

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	client, err := newClient(testHost(server), WithCABundle(testServerCertPEM(t, server)))
	if err != nil {
		server.Close()
		t.Fatalf("newClient: %v", err)
	}
	return client, server
}

func testHost(server *httptest.Server) string {
	return strings.TrimPrefix(server.URL, "https://")
}

func testServerCertPEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	cert := server.Certificate()
	if cert == nil {
		t.Fatal("server certificate is nil")
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemBytes := pem.EncodeToMemory(block)
	if len(bytes.TrimSpace(pemBytes)) == 0 {
		t.Fatal("PEM-encoded server certificate is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if parsed.SerialNumber == nil {
		t.Fatal("parsed certificate missing serial")
	}
	return pemBytes
}

func closeClient(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
