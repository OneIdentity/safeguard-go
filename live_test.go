package safeguard

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveNotificationStatus(t *testing.T) {
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	full, err := client.Get(ctx, Notification, "Status")
	if err != nil {
		t.Fatalf("Get Notification Status: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}

	ctx, cancel = liveContext(t)
	defer cancel()
	status, err := InvokeTyped[struct {
		ApplianceVersion      string
		ApplianceCurrentState string
	}](ctx, client, MethodGet, Notification, "Status", nil)
	if err != nil {
		t.Fatalf("InvokeTyped Notification Status: %v", err)
	}
	if status.ApplianceVersion == "" {
		t.Fatal("ApplianceVersion is empty")
	}
}

func TestLiveApplianceSystemTime(t *testing.T) {
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	full, err := client.Get(ctx, Appliance, "SystemTime")
	if err != nil {
		t.Fatalf("Get Appliance SystemTime: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
	if !bytes.Contains(full.Body, []byte("CurrentTime")) {
		t.Fatalf("SystemTime body does not contain CurrentTime: %s", full.Body)
	}
}

func TestLiveCoreVersionNotFound(t *testing.T) {
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	_, err := client.Get(ctx, Core, "Version")
	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("Get Core Version error = %v, want NotFoundError", err)
	}
}

func TestLiveLoginResponseTypedError(t *testing.T) {
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	full, err := client.Post(ctx, Core, "Token/LoginResponse", map[string]any{})
	if full.StatusCode != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusBadRequest)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Post LoginResponse error = %v, want APIError", err)
	}
	if got, want := apiErr.Code, 60155; got != want {
		t.Fatalf("Code = %d, want %d", got, want)
	}
	if apiErr.Message == "" {
		t.Fatal("APIError Message is empty")
	}
}

func TestLiveHostOverride(t *testing.T) {
	host := liveHost(t)
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	full, err := client.Get(ctx, Notification, "Status", WithHost(host))
	if err != nil {
		t.Fatalf("Get Notification Status with host override: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
}

func TestLiveDownloadStatus(t *testing.T) {
	client := liveClient(t)
	defer closeClient(t, client)

	ctx, cancel := liveContext(t)
	defer cancel()

	var buf bytes.Buffer
	full, err := client.Download(ctx, Notification, "Status", &buf)
	if err != nil {
		t.Fatalf("Download Notification Status: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
	if !strings.Contains(buf.String(), "ApplianceCurrentState") {
		t.Fatalf("download body does not contain ApplianceCurrentState: %s", buf.String())
	}
}

func TestLiveTLSModes(t *testing.T) {
	host := liveHost(t)
	pemBytes := applianceCertPEM(t, host)

	t.Run("ca bundle", func(t *testing.T) {
		client := liveClient(t, WithCABundle(pemBytes))
		defer closeClient(t, client)
		assertLiveStatusOK(t, client)
	})

	t.Run("insecure", func(t *testing.T) {
		client := liveClient(t, WithInsecureTLS())
		defer closeClient(t, client)
		assertLiveStatusOK(t, client)
	})

	t.Run("default system trust", func(t *testing.T) {
		// With no CA bundle, insecure override, or validator, the client verifies
		// the appliance certificate against the operating system trust store. The
		// correct outcome depends on whether that store trusts the appliance chain,
		// which varies by host: an appliance whose certificate chains to an
		// enterprise CA installed on this machine is trusted, while a self-signed
		// appliance is not. Assert against the same verdict the OS itself reaches
		// for this appliance rather than assuming the certificate is untrusted, so
		// the test proves the SDK connects when the chain is trusted and fails
		// closed with a transport error when it is not.
		trusted := appliancePassesDefaultTrust(t, host)

		client, err := newClient(host)
		if err != nil {
			t.Fatalf("newClient default TLS: %v", err)
		}
		defer closeClient(t, client)

		ctx, cancel := liveContext(t)
		defer cancel()
		_, err = client.Get(ctx, Notification, "Status")

		if trusted {
			if err != nil {
				t.Fatalf("Get with default system trust error = %v, want success (the appliance chain is trusted by this host's system store)", err)
			}
			return
		}

		if err == nil {
			t.Fatal("Get with default system trust error = nil, want error (the appliance chain is not trusted by this host's system store)")
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			t.Fatalf("Get with default system trust error = %v, want non-API error", err)
		}
		var transportErr *TransportError
		if !errors.As(err, &transportErr) {
			t.Fatalf("Get with default system trust error = %v, want TransportError", err)
		}
	})

	t.Run("validator rejects", func(t *testing.T) {
		sentinel := errors.New("validator rejected certificate")
		client := liveClient(t,
			WithCABundle(pemBytes),
			WithServerCertValidator(func(_ *x509.Certificate, _ [][]*x509.Certificate) error {
				return sentinel
			}),
		)
		defer closeClient(t, client)

		ctx, cancel := liveContext(t)
		defer cancel()
		_, err := client.Get(ctx, Notification, "Status")
		if err == nil {
			t.Fatal("Get with rejecting validator error = nil, want error")
		}
		if !errors.Is(err, sentinel) && !strings.Contains(err.Error(), sentinel.Error()) {
			t.Fatalf("Get with rejecting validator error = %v, want sentinel", err)
		}
		var transportErr *TransportError
		if !errors.As(err, &transportErr) {
			t.Fatalf("Get with rejecting validator error = %v, want TransportError", err)
		}
	})

	t.Run("validator accepts", func(t *testing.T) {
		client := liveClient(t,
			WithCABundle(pemBytes),
			WithServerCertValidator(func(_ *x509.Certificate, _ [][]*x509.Certificate) error {
				return nil
			}),
		)
		defer closeClient(t, client)
		assertLiveStatusOK(t, client)
	})
}

func assertLiveStatusOK(t *testing.T, client *Client) {
	t.Helper()

	ctx, cancel := liveContext(t)
	defer cancel()
	full, err := client.Get(ctx, Notification, "Status")
	if err != nil {
		t.Fatalf("Get Notification Status: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
	var status struct {
		ApplianceVersion string
	}
	if err := json.Unmarshal(full.Body, &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status.ApplianceVersion == "" {
		t.Fatal("ApplianceVersion is empty")
	}
}

func liveContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	requireLive(t)
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// TestLivePKCEConnect proves the full public Connect path with the PKCE headless
// credential against the appliance named by SPP_HOST: it authenticates, calls an
// authenticated endpoint, and confirms the session is not refreshable. This is
// the authoritative automation entry point because it works when the Resource
// Owner Grant is disabled. It is skipped when SPP_HOST is unset and expects a
// non-MFA bootstrap account.
func TestLivePKCEConnect(t *testing.T) {
	host := liveHost(t)

	username := envOr("SPP_USERNAME", "admin")
	password := envOr("SPP_PASSWORD", "Admin123")
	provider := strings.TrimSpace(os.Getenv("SPP_PROVIDER"))

	opts := []Option{}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := Connect(ctx, host,
		PKCEHeadless(provider, username, NewSecretString(password)),
		opts...,
	)
	if err != nil {
		t.Fatalf("Connect PKCE against %s: %v", host, err)
	}
	defer closeClient(t, client)

	if _, err := client.Get(ctx, Core, "Me"); err != nil {
		t.Fatalf("authenticated Get Me: %v", err)
	}
	if err := client.RefreshToken(ctx); !errors.Is(err, ErrNotRefreshable) {
		t.Errorf("RefreshToken on PKCE session = %v, want ErrNotRefreshable", err)
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
