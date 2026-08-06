package safeguard

import (
	"errors"
	"testing"
	"time"
)

func TestWithHeader(t *testing.T) {
	for _, name := range []string{"Authorization", "authorization"} {
		t.Run("reserved "+name, func(t *testing.T) {
			_, err := applyReqOptions(WithHeader(name, "x"))
			if !errors.Is(err, ErrReservedHeader) {
				t.Fatalf("WithHeader(%q) error = %v, want ErrReservedHeader", name, err)
			}
		})
	}

	rc, err := applyReqOptions(WithHeader("X-Test", "value"))
	if err != nil {
		t.Fatalf("WithHeader normal: %v", err)
	}
	if got, want := rc.headers.Get("X-Test"), "value"; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestRequestOptions(t *testing.T) {
	timeout := 5 * time.Second
	rc, err := applyReqOptions(
		WithQueryParam("k", "v1"),
		WithQueryParam("k", "v2"),
		WithQueryParams(map[string]string{"a": "b"}),
		WithAPIVersionOverride("v3"),
		WithHost("  appliance.example  "),
		WithRequestTimeout(timeout),
		WithAccept(" text/csv "),
	)
	if err != nil {
		t.Fatalf("applyReqOptions: %v", err)
	}
	if got := rc.params["k"]; len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
		t.Fatalf("query k = %v, want [v1 v2]", got)
	}
	if got, want := rc.params.Get("a"), "b"; got != want {
		t.Fatalf("query a = %q, want %q", got, want)
	}
	if got, want := rc.apiVersion, "v3"; got != want {
		t.Fatalf("apiVersion = %q, want %q", got, want)
	}
	if got, want := rc.host, "appliance.example"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got := rc.timeout; got != timeout {
		t.Fatalf("timeout = %v, want %v", got, timeout)
	}
	if got, want := rc.accept, "text/csv"; got != want {
		t.Fatalf("accept = %q, want %q", got, want)
	}

	_, err = applyReqOptions(WithAPIVersionOverride(""))
	if !errors.Is(err, errEmptyAPIVersion) {
		t.Fatalf("WithAPIVersionOverride empty error = %v, want errEmptyAPIVersion", err)
	}
}

func TestTimeoutsOrDefaultAndWithHTTPTimeouts(t *testing.T) {
	input := Timeouts{Dial: time.Second}
	got := input.orDefault()
	if got.Dial != time.Second {
		t.Fatalf("Dial = %v, want %v", got.Dial, time.Second)
	}
	if got.TLSHandshake != defaultTimeouts.TLSHandshake {
		t.Fatalf("TLSHandshake = %v, want %v", got.TLSHandshake, defaultTimeouts.TLSHandshake)
	}
	if got.ResponseHeader != defaultTimeouts.ResponseHeader {
		t.Fatalf("ResponseHeader = %v, want %v", got.ResponseHeader, defaultTimeouts.ResponseHeader)
	}

	cfg := defaultClientConfig()
	err := cfg.apply(WithHTTPTimeouts(Timeouts{
		Dial:           2 * time.Second,
		TLSHandshake:   3 * time.Second,
		ResponseHeader: 4 * time.Second,
	}))
	if err != nil {
		t.Fatalf("WithHTTPTimeouts: %v", err)
	}
	want := Timeouts{Dial: 2 * time.Second, TLSHandshake: 3 * time.Second, ResponseHeader: 4 * time.Second}
	if cfg.timeouts != want {
		t.Fatalf("timeouts = %+v, want %+v", cfg.timeouts, want)
	}

	rc := newRequestConfig()
	if rc.headers == nil || rc.params == nil {
		t.Fatal("newRequestConfig did not initialize maps")
	}
	rc.headers.Set("X-Test", "value")
}
