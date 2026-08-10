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

package auth

import (
	"errors"
	"fmt"
	"net/http"
)

// maxErrorBody bounds how much of a failed response body the broker retains for
// diagnostics. RSTS and Core error bodies are small; the cap prevents a hostile
// or malformed response from ballooning memory, and the body is never logged.
const maxErrorBody = 8192

// ErrLoginResponseFailed indicates the Core Token/LoginResponse exchange did not
// return a success status. Compare with errors.Is.
var ErrLoginResponseFailed = errors.New("safeguard/auth: login response was not successful")

// ErrMissingToken indicates a login step returned a success status but no token
// where one was expected.
var ErrMissingToken = errors.New("safeguard/auth: authentication response contained no token")

// errNilHTTPClient indicates the caller passed a Config without the transport a flow
// requires (for example certificate login with no CertHTTPClient).
var errNilHTTPClient = errors.New("safeguard/auth: no HTTP transport provided for this login flow")

// ErrSecondaryFactorRequired indicates a PKCE login reached a secondary
// (multi-factor) authentication step but the caller supplied no secondary factor
// provider. Compare with errors.Is.
var ErrSecondaryFactorRequired = errors.New("safeguard/auth: multi-factor authentication is required but no secondary factor was provided")

// ErrSecondaryFactorFailed indicates the appliance rejected the supplied
// secondary (multi-factor) authentication code. Compare with errors.Is.
var ErrSecondaryFactorFailed = errors.New("safeguard/auth: multi-factor authentication failed")

// ErrDeviceCodeExpired indicates a device-code login was not completed before
// the user code expired, either because the polling deadline elapsed or because
// the appliance reported expired_token. Compare with errors.Is.
var ErrDeviceCodeExpired = errors.New("safeguard/auth: device code expired before authorization completed")

// ErrDeviceCodeDenied indicates the user denied the device-code authorization
// request; the appliance reported access_denied. Compare with errors.Is.
var ErrDeviceCodeDenied = errors.New("safeguard/auth: device code authorization was denied")

// RequestError is returned when an authentication HTTP call fails, either
// because the transport failed or because the appliance returned a non-success
// status. The root package inspects StatusCode to map the failure onto its
// public error hierarchy (for example a 401 to AuthenticationError). The stored
// body is bounded and available only through Body; it is never included in
// Error because RSTS and login payloads can echo sensitive material.
type RequestError struct {
	// Op names the failing step, for example "rsts grant" or "login response".
	Op string
	// StatusCode is the HTTP status, or 0 when no response was received.
	StatusCode int
	// Err is the underlying transport error, if any.
	Err error

	body []byte
}

// Error implements error. It deliberately omits the response body.
func (e *RequestError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("safeguard/auth: %s failed: %v", e.Op, e.Err)
	}
	msg := http.StatusText(e.StatusCode)
	if msg == "" {
		return fmt.Sprintf("safeguard/auth: %s failed: HTTP %d", e.Op, e.StatusCode)
	}
	return fmt.Sprintf("safeguard/auth: %s failed: HTTP %d %s", e.Op, e.StatusCode, msg)
}

// Unwrap returns the underlying transport error so errors.Is/As reach the cause.
func (e *RequestError) Unwrap() error { return e.Err }

// Body returns a copy of the bounded response body retained for diagnostics. It
// may contain sensitive data and is never logged automatically.
func (e *RequestError) Body() []byte {
	if len(e.body) == 0 {
		return nil
	}
	cp := make([]byte, len(e.body))
	copy(cp, e.body)
	return cp
}
