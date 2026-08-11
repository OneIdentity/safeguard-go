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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// maxStoredErrorBody caps how many bytes of a response body an APIError retains
// for diagnostics. Bodies can contain returned credentials, so the stored copy is
// bounded and is never included in Error().
const maxStoredErrorBody = 4096

// Sentinel errors returned by the SDK. Compare with errors.Is.
var (
	// ErrNotAuthenticated indicates an operation requires a session that has not
	// been established (or has been ended by Logout/Close).
	ErrNotAuthenticated = errors.New("safeguard: not authenticated")
	// ErrNotRefreshable indicates the current credential cannot be refreshed (for
	// example a bare user token supplied via Token).
	ErrNotRefreshable = errors.New("safeguard: token is not refreshable")
	// ErrReservedHeader indicates a request option attempted to set a reserved
	// header (Authorization) that the transport controls exclusively.
	ErrReservedHeader = errors.New("safeguard: Authorization is a reserved header and cannot be set on a request")
	// ErrClosed indicates the client has been closed and can no longer be used.
	ErrClosed = errors.New("safeguard: client is closed")
	// ErrAlreadyStarted indicates an event listener's Start was called more than
	// once. Create a new listener instead of restarting a stopped one.
	ErrAlreadyStarted = errors.New("safeguard: event listener already started")
)

// errEmptyAPIVersion is returned when an empty API version is supplied.
var errEmptyAPIVersion = errors.New("safeguard: API version must not be empty")

// errEmptyHost is returned when a client is created without a host.
var errEmptyHost = errors.New("safeguard: host must not be empty")

// errNoClientCert is returned when a client-certificate transport is requested
// but no client certificate has been configured (populated in Phase 2/3).
var errNoClientCert = errors.New("safeguard: no client certificate configured")

// errNilCredential is returned when Connect is called without a credential.
var errNilCredential = errors.New("safeguard: a credential is required to connect")

// errEmptyToken is returned when Token is used with an empty user token.
var errEmptyToken = errors.New("safeguard: user token must not be empty")

// errNilLoginFunc is returned when AuthorizedSession is used without a login
// function. The browser and devicecode add-on packages always supply one.
var errNilLoginFunc = errors.New("safeguard: AuthorizedSession requires a login function")

// errPKCS12Unsupported is returned when Certificate is given PKCS#12 (.pfx/.p12)
// material. Like PySafeguard, this SDK takes PEM certificate material only;
// convert a PKCS#12 file with, for example,
// `openssl pkcs12 -in cert.pfx -nodes -out cert.pem` and pass the PEM bytes.
var errPKCS12Unsupported = errors.New("safeguard: PKCS#12 (.pfx/.p12) certificate input is not supported; convert to PEM (e.g. `openssl pkcs12 -in cert.pfx -nodes -out cert.pem`) and supply the PEM material")

// errNoCertificateInPEM is returned when certificate material contains no
// CERTIFICATE block.
var errNoCertificateInPEM = errors.New("safeguard: no certificate found in PEM material")

// errNoPrivateKeyInPEM is returned when certificate material contains no private
// key block.
var errNoPrivateKeyInPEM = errors.New("safeguard: no private key found in PEM material")

// errEncryptedKeyNoPassword is returned when an encrypted PEM private key is
// supplied without a password to decrypt it.
var errEncryptedKeyNoPassword = errors.New("safeguard: encrypted private key requires a password")

// APIError is returned when a Safeguard API call completes with a non-2xx HTTP
// status. It carries the HTTP status, the Safeguard error Code and Message when
// the body was a recognizable Safeguard error object, and the appliance request
// identifier when present.
//
// Error never includes the raw response body, which may contain returned
// credentials; use RawBody for a bounded, explicit diagnostic copy.
type APIError struct {
	// StatusCode is the HTTP status code returned by the appliance.
	StatusCode int
	// Code is the Safeguard error code from the response body, or 0 if absent.
	Code int
	// Message is the Safeguard error message from the response body, if any.
	Message string
	// RequestID is the appliance request/correlation id, or empty if absent.
	RequestID string

	rawBody []byte
}

// Error implements error. It deliberately omits the raw response body.
func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	s := fmt.Sprintf("safeguard: API error: HTTP %d", e.StatusCode)
	if e.Code != 0 {
		s += fmt.Sprintf(", Code %d", e.Code)
	}
	if msg != "" {
		s += ": " + msg
	}
	if e.RequestID != "" {
		s += fmt.Sprintf(" (requestId=%s)", e.RequestID)
	}
	return s
}

// RawBody returns a copy of the bounded raw response body retained for
// diagnostics. It may contain sensitive data and is never logged automatically.
func (e *APIError) RawBody() []byte {
	if len(e.rawBody) == 0 {
		return nil
	}
	cp := make([]byte, len(e.rawBody))
	copy(cp, e.rawBody)
	return cp
}

// AuthenticationError is an APIError for an HTTP 401 response. Detect it with
// errors.As; errors.As(&APIError) also matches via Unwrap.
type AuthenticationError struct{ *APIError }

// Unwrap returns the embedded *APIError.
func (e *AuthenticationError) Unwrap() error { return e.APIError }

// AuthorizationError is an APIError for an HTTP 403 response.
type AuthorizationError struct{ *APIError }

// Unwrap returns the embedded *APIError.
func (e *AuthorizationError) Unwrap() error { return e.APIError }

// NotFoundError is an APIError for an HTTP 404 response.
type NotFoundError struct{ *APIError }

// Unwrap returns the embedded *APIError.
func (e *NotFoundError) Unwrap() error { return e.APIError }

// TransportError wraps a network, TLS, or protocol failure that occurred before a
// usable HTTP response was received.
type TransportError struct {
	// Op is a short description of the operation that failed (for example "dial"
	// or "request").
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements error.
func (e *TransportError) Error() string {
	return fmt.Sprintf("safeguard: transport error during %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error so errors.Is/As reach the cause.
func (e *TransportError) Unwrap() error { return e.Err }

// newAPIError builds the most specific error type for a non-2xx response. It
// parses a Safeguard error body ({"Code":...,"Message":...}) when possible and
// retains a bounded copy of the body for diagnostics.
func newAPIError(status int, body []byte, header http.Header) error {
	stored := body
	if len(stored) > maxStoredErrorBody {
		stored = stored[:maxStoredErrorBody]
	}
	base := &APIError{
		StatusCode: status,
		RequestID:  extractRequestID(header),
		rawBody:    append([]byte(nil), stored...),
	}
	var parsed struct {
		Code    int    `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		base.Code = parsed.Code
		base.Message = parsed.Message
	}
	switch status {
	case http.StatusUnauthorized:
		return &AuthenticationError{base}
	case http.StatusForbidden:
		return &AuthorizationError{base}
	case http.StatusNotFound:
		return &NotFoundError{base}
	default:
		return base
	}
}
