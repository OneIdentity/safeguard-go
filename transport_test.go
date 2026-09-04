package safeguard

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestAuthorizationHeaderValue(t *testing.T) {
	cases := []struct {
		name string
		auth authorization
		want string
	}{
		{name: "none", auth: noAuth(), want: ""},
		{name: "user token", auth: userTokenAuth(NewSecretString("tok")), want: "Bearer tok"},
		{name: "a2a", auth: a2aAuth(NewSecretString("key")), want: "A2A key"},
		{name: "zero user token", auth: userTokenAuth(Secret{}), want: ""},
		{name: "zero a2a key", auth: a2aAuth(Secret{}), want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.auth.headerValue(); got != tc.want {
				t.Fatalf("headerValue = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildHTTPRequest(t *testing.T) {
	req, err := buildHTTPRequest(context.Background(), MethodGet, "https://example.test", nil, noAuth(), "", nil)
	if err != nil {
		t.Fatalf("buildHTTPRequest default accept: %v", err)
	}
	if got, want := req.Header.Get("Accept"), "application/json"; got != want {
		t.Fatalf("Accept = %q, want %q", got, want)
	}

	headers := http.Header{}
	headers.Set("Authorization", "caller")
	headers.Set("X-Test", "value")
	req, err = buildHTTPRequest(
		context.Background(),
		MethodPost,
		"https://example.test",
		nil,
		userTokenAuth(NewSecretString("tok")),
		"text/csv",
		headers,
	)
	if err != nil {
		t.Fatalf("buildHTTPRequest custom: %v", err)
	}
	if got, want := req.Header.Get("Accept"), "text/csv"; got != want {
		t.Fatalf("Accept = %q, want %q", got, want)
	}
	if got, want := req.Header.Get("Authorization"), "Bearer tok"; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
	if got, want := req.Header.Get("X-Test"), "value"; got != want {
		t.Fatalf("X-Test = %q, want %q", got, want)
	}
}

func TestTransportSetClientAxesAndClose(t *testing.T) {
	ts := newTransportSet(&tls.Config{MinVersion: tls.VersionTLS12}, Timeouts{}, 0)
	_, err := ts.client(clientCert)
	if !errors.Is(err, errNoClientCert) {
		t.Fatalf("client(clientCert) error = %v, want errNoClientCert", err)
	}

	client, err := ts.client(serverTrust)
	if err != nil {
		t.Fatalf("client(serverTrust): %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.test", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want http.ErrUseLastResponse", err)
	}

	ts.Close()
	ts.Close()
	_, err = ts.client(serverTrust)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("client after Close error = %v, want ErrClosed", err)
	}
}

func TestBuildHTTPRequestRejectsBadURL(t *testing.T) {
	_, err := buildHTTPRequest(context.Background(), MethodGet, "\n", io.Reader(nil), noAuth(), "", nil)
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("buildHTTPRequest bad URL error = %v, want TransportError", err)
	}
}
