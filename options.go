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
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Timeouts configures the granular transport timeouts. None of these is a global
// request deadline: a global timeout would break long-lived streams and event
// connections. Per-request deadlines are set through context and WithRequestTimeout.
type Timeouts struct {
	// Dial bounds establishing the TCP connection.
	Dial time.Duration
	// TLSHandshake bounds completing the TLS handshake.
	TLSHandshake time.Duration
	// ResponseHeader bounds waiting for the first response header byte after the
	// request is written. It does not bound reading the response body.
	ResponseHeader time.Duration
}

// defaultTimeouts are the transport timeout defaults.
var defaultTimeouts = Timeouts{
	Dial:           30 * time.Second,
	TLSHandshake:   10 * time.Second,
	ResponseHeader: 100 * time.Second,
}

// orDefault returns t with any zero field replaced by the corresponding default.
func (t Timeouts) orDefault() Timeouts {
	if t.Dial == 0 {
		t.Dial = defaultTimeouts.Dial
	}
	if t.TLSHandshake == 0 {
		t.TLSHandshake = defaultTimeouts.TLSHandshake
	}
	if t.ResponseHeader == 0 {
		t.ResponseHeader = defaultTimeouts.ResponseHeader
	}
	return t
}

// clientConfig is the resolved connection configuration produced by applying the
// connection Options. It is not exported; callers configure a client through
// Options.
type clientConfig struct {
	apiVersion string
	logger     *slog.Logger
	timeouts   Timeouts

	// TLS configuration (see tls.go).
	caBundle      []byte
	certValidator ServerCertValidator
	insecure      bool
}

// defaultClientConfig returns a clientConfig populated with defaults.
func defaultClientConfig() *clientConfig {
	return &clientConfig{
		apiVersion: DefaultAPIVersion,
		timeouts:   defaultTimeouts,
	}
}

// Option configures a client connection. Options are applied in order and may
// return an error to reject an invalid configuration.
type Option func(*clientConfig) error

// apply runs each option against the config in order.
func (cfg *clientConfig) apply(opts ...Option) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return err
		}
	}
	return nil
}

// WithAPIVersion overrides the default Safeguard API version for every request.
func WithAPIVersion(version string) Option {
	return func(cfg *clientConfig) error {
		v := strings.TrimSpace(version)
		if v == "" {
			return errEmptyAPIVersion
		}
		cfg.apiVersion = v
		return nil
	}
}

// WithLogger attaches a structured logger. Nothing is logged by default and no
// global logger is used; secrets never appear in logs.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *clientConfig) error {
		cfg.logger = logger
		return nil
	}
}

// WithHTTPTimeouts overrides the granular transport timeouts. Zero-valued fields
// keep their defaults.
func WithHTTPTimeouts(t Timeouts) Option {
	return func(cfg *clientConfig) error {
		cfg.timeouts = t.orDefault()
		return nil
	}
}

// requestConfig is the resolved per-request configuration produced by applying
// ReqOptions.
type requestConfig struct {
	params     url.Values
	headers    http.Header
	apiVersion string
	host       string
	timeout    time.Duration
	accept     string
}

// newRequestConfig returns an empty requestConfig with initialized maps.
func newRequestConfig() *requestConfig {
	return &requestConfig{
		params:  url.Values{},
		headers: http.Header{},
	}
}

// ReqOption configures a single request. Options are applied in order and may
// return an error to reject an invalid request configuration.
type ReqOption func(*requestConfig) error

// applyReqOptions builds a requestConfig from opts.
func applyReqOptions(opts ...ReqOption) (*requestConfig, error) {
	rc := newRequestConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(rc); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

// WithQueryParam adds a single query parameter to the request.
func WithQueryParam(key, value string) ReqOption {
	return func(rc *requestConfig) error {
		rc.params.Add(key, value)
		return nil
	}
}

// WithQueryParams adds multiple query parameters to the request.
func WithQueryParams(params map[string]string) ReqOption {
	return func(rc *requestConfig) error {
		for k, v := range params {
			rc.params.Add(k, v)
		}
		return nil
	}
}

// WithHeader sets an additional request header. Setting the reserved
// Authorization header is rejected with ErrReservedHeader: authorization is
// controlled exclusively by the transport axis and must never ride the wrong
// transport.
func WithHeader(key, value string) ReqOption {
	return func(rc *requestConfig) error {
		if textproto.CanonicalMIMEHeaderKey(key) == "Authorization" {
			return ErrReservedHeader
		}
		rc.headers.Set(key, value)
		return nil
	}
}

// WithAPIVersionOverride overrides the API version for this request only.
func WithAPIVersionOverride(version string) ReqOption {
	return func(rc *requestConfig) error {
		v := strings.TrimSpace(version)
		if v == "" {
			return errEmptyAPIVersion
		}
		rc.apiVersion = v
		return nil
	}
}

// WithHost overrides the target host for this request only (parity with
// PySafeguard host_override). The alternate host uses the same TLS configuration.
func WithHost(host string) ReqOption {
	return func(rc *requestConfig) error {
		rc.host = strings.TrimSpace(host)
		return nil
	}
}

// WithRequestTimeout applies a timeout to this request by deriving a context
// deadline. It does not set a global client timeout and is safe for non-stream
// calls; streaming callers should manage cancellation through their own context.
func WithRequestTimeout(d time.Duration) ReqOption {
	return func(rc *requestConfig) error {
		rc.timeout = d
		return nil
	}
}

// WithAccept overrides the Accept header (for example "text/csv" for CSV report
// endpoints). The default is application/json.
func WithAccept(mediaType string) ReqOption {
	return func(rc *requestConfig) error {
		rc.accept = strings.TrimSpace(mediaType)
		return nil
	}
}
