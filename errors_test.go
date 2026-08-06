package safeguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestNewAPIErrorStatusSpecializations(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		assertType func(t *testing.T, err error)
	}{
		{
			name:       "401 authentication",
			statusCode: http.StatusUnauthorized,
			assertType: func(t *testing.T, err error) {
				t.Helper()
				var target *AuthenticationError
				if !errors.As(err, &target) {
					t.Fatalf("errors.As AuthenticationError failed for %T", err)
				}
			},
		},
		{
			name:       "403 authorization",
			statusCode: http.StatusForbidden,
			assertType: func(t *testing.T, err error) {
				t.Helper()
				var target *AuthorizationError
				if !errors.As(err, &target) {
					t.Fatalf("errors.As AuthorizationError failed for %T", err)
				}
			},
		},
		{
			name:       "404 not found",
			statusCode: http.StatusNotFound,
			assertType: func(t *testing.T, err error) {
				t.Helper()
				var target *NotFoundError
				if !errors.As(err, &target) {
					t.Fatalf("errors.As NotFoundError failed for %T", err)
				}
			},
		},
		{
			name:       "400 api",
			statusCode: http.StatusBadRequest,
			assertType: assertAPIErrorType,
		},
		{
			name:       "500 api",
			statusCode: http.StatusInternalServerError,
			assertType: assertAPIErrorType,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := newAPIError(tc.statusCode, nil, nil)
			tc.assertType(t, err)
			assertAPIErrorType(t, err)
		})
	}
}

func TestNewAPIErrorParsesSafeguardBody(t *testing.T) {
	body := []byte(`{"Code":60155,"Message":"Missing 'StsAccessToken' parameter."}`)
	err := newAPIError(http.StatusBadRequest, body, http.Header{"X-Request-Id": []string{"req-1"}})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As APIError failed for %T", err)
	}
	if got, want := apiErr.Code, 60155; got != want {
		t.Fatalf("Code = %d, want %d", got, want)
	}
	if got, want := apiErr.Message, "Missing 'StsAccessToken' parameter."; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
	if got, want := apiErr.RequestID, "req-1"; got != want {
		t.Fatalf("RequestID = %q, want %q", got, want)
	}
}

func TestAPIErrorStringAndRawBody(t *testing.T) {
	rawSecret := "do-not-log"
	body := []byte(`{"Code":60155,"Message":"Missing token.","Extra":"` + rawSecret + `"}`)
	err := newAPIError(http.StatusBadRequest, body, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As APIError failed for %T", err)
	}
	errText := apiErr.Error()
	for _, want := range []string{"HTTP 400", "Code 60155", "Missing token."} {
		if !strings.Contains(errText, want) {
			t.Fatalf("Error() = %q, want to contain %q", errText, want)
		}
	}
	if strings.Contains(errText, rawSecret) || strings.Contains(errText, "Extra") {
		t.Fatalf("Error() leaked raw body content: %q", errText)
	}

	raw := apiErr.RawBody()
	if string(raw) != string(body) {
		t.Fatalf("RawBody = %q, want %q", string(raw), string(body))
	}
	raw[0] = 'X'
	if string(apiErr.RawBody()) != string(body) {
		t.Fatal("RawBody did not return a copy")
	}

	largeBody := make([]byte, maxStoredErrorBody+100)
	for i := range largeBody {
		largeBody[i] = 'a'
	}
	largeErr := newAPIError(http.StatusInternalServerError, largeBody, nil)
	var largeAPIError *APIError
	if !errors.As(largeErr, &largeAPIError) {
		t.Fatalf("errors.As APIError failed for %T", largeErr)
	}
	if got, want := len(largeAPIError.RawBody()), maxStoredErrorBody; got != want {
		t.Fatalf("capped RawBody length = %d, want %d", got, want)
	}
}

func TestSentinelErrors(t *testing.T) {
	cases := []error{
		ErrReservedHeader,
		ErrClosed,
		ErrNotAuthenticated,
		ErrNotRefreshable,
	}
	for _, sentinel := range cases {
		t.Run(sentinel.Error(), func(t *testing.T) {
			if !errors.Is(sentinel, sentinel) {
				t.Fatalf("errors.Is failed for %v", sentinel)
			}
		})
	}
}

func TestTransportErrorWrapsCause(t *testing.T) {
	cause := errors.New("network failed")
	err := &TransportError{Op: "request", Err: cause}

	if got := err.Error(); !strings.Contains(got, "request") || !strings.Contains(got, cause.Error()) {
		t.Fatalf("Error() = %q, want op and cause", got)
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is did not reach wrapped cause")
	}
	if got := err.Unwrap(); !errors.Is(got, cause) {
		t.Fatalf("Unwrap() = %v, want %v", got, cause)
	}
}

func assertAPIErrorType(t *testing.T, err error) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As APIError failed for %T", err)
	}
}
