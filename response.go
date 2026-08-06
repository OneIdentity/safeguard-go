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
	"net/http"
	"strings"
)

// requestIDHeaders lists the response header names, in priority order, that
// Safeguard appliances use to carry a correlation/request identifier. Extraction
// is best-effort: anonymous endpoints often omit it entirely.
var requestIDHeaders = []string{"X-Request-Id", "X-Request-ID", "Request-Id"}

// FullResponse is the complete result of an Invoke-style call: the HTTP status,
// the response headers, the fully read (non-streaming) body, and the appliance
// request identifier when one is present.
//
// For streaming calls the body is delivered separately and Body is nil; the
// headers and RequestID still describe the response.
type FullResponse struct {
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Headers holds the response headers. Multi-value headers are preserved.
	Headers http.Header
	// Body is the fully buffered response body for non-streaming calls; it is nil
	// for streaming responses.
	Body []byte
	// RequestID is the appliance request/correlation identifier, or empty when the
	// response did not include one.
	RequestID string
}

// IsSuccess reports whether the status code is in the 2xx range.
func (r FullResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// String returns the response body as a string. It is a convenience for callers
// that expect a textual (JSON/CSV) body.
func (r FullResponse) String() string {
	return string(r.Body)
}

// extractRequestID returns the first request-id header value found in h, or the
// empty string if none of the known headers are present.
func extractRequestID(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, name := range requestIDHeaders {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return v
		}
	}
	return ""
}
