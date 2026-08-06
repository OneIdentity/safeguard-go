package safeguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStreamSuccess(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("stream body"))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	reader, full, err := client.Stream(context.Background(), MethodGet, Notification, "Status", nil)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
	if full.Body != nil {
		t.Fatalf("FullResponse.Body = %q, want nil", string(full.Body))
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("reader.Close: %v", err)
	}
	if got, want := string(body), "stream body"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestStreamNon2xx(t *testing.T) {
	body := strings.Repeat("x", maxStoredErrorBody+100)
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(body))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	reader, full, err := client.Stream(context.Background(), MethodGet, Notification, "Status", nil)
	if reader != nil {
		t.Fatalf("reader = %T, want nil", reader)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Stream error = %v, want APIError", err)
	}
	if full.StatusCode != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusBadRequest)
	}
	if got, wantLen := len(full.Body), maxStoredErrorBody+1; got != wantLen {
		t.Fatalf("FullResponse.Body length = %d, want %d", got, wantLen)
	}
	if got, wantLen := len(apiErr.RawBody()), maxStoredErrorBody; got != wantLen {
		t.Fatalf("RawBody length = %d, want %d", got, wantLen)
	}
}

func TestUploadPostsOctetStream(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Errorf("method = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Content-Type"), "application/octet-stream"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err = fmt.Fprintf(w, "%d:%s", len(body), body); err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	full, err := client.Upload(context.Background(), Core, "Upload", bytes.NewBufferString("abc"))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got, want := full.String(), "3:abc"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestDownloadSuccess(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("download body"))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	var buf bytes.Buffer
	full, err := client.Download(context.Background(), Notification, "Status", &buf)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if full.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusOK)
	}
	if full.Body != nil {
		t.Fatalf("FullResponse.Body = %q, want nil", string(full.Body))
	}
	if got, want := buf.String(), "download body"; got != want {
		t.Fatalf("downloaded body = %q, want %q", got, want)
	}
}

func TestDownloadNon2xx(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"Code":1,"Message":"bad"}`))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	var buf bytes.Buffer
	full, err := client.Download(context.Background(), Notification, "Status", &buf)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Download error = %v, want APIError", err)
	}
	if full.StatusCode != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", full.StatusCode, http.StatusBadRequest)
	}
	if got, want := string(full.Body), `{"Code":1,"Message":"bad"}`; got != want {
		t.Fatalf("FullResponse.Body = %q, want %q", got, want)
	}
	if buf.Len() != 0 {
		t.Fatalf("download buffer length = %d, want 0", buf.Len())
	}
}
