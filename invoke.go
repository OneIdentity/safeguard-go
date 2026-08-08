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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HTTPMethod is an HTTP verb used with the Invoke surface.
type HTTPMethod string

// Supported HTTP methods.
const (
	// MethodGet is the HTTP GET method.
	MethodGet HTTPMethod = http.MethodGet
	// MethodPost is the HTTP POST method.
	MethodPost HTTPMethod = http.MethodPost
	// MethodPut is the HTTP PUT method.
	MethodPut HTTPMethod = http.MethodPut
	// MethodDelete is the HTTP DELETE method.
	MethodDelete HTTPMethod = http.MethodDelete
)

// Invoke performs a Safeguard API call and returns the FullResponse. The body is
// encoded by type: nil is an empty body; string and json.RawMessage are sent as
// application/json; []byte and io.Reader are sent as application/octet-stream;
// any other value is JSON-marshaled. A caller may override the content type with
// WithHeader. On a non-2xx status Invoke returns the populated FullResponse along
// with a typed *APIError (or its 401/403/404 specializations). The response body
// is always read and closed.
func (c *Client) Invoke(ctx context.Context, m HTTPMethod, s Service, relURL string, body any, opts ...ReqOption) (FullResponse, error) {
	if c.isClosed() {
		return FullResponse{}, ErrClosed
	}
	rc, err := applyReqOptions(opts...)
	if err != nil {
		return FullResponse{}, err
	}
	if rc.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, rc.timeout)
		defer cancel()
	}
	newReq := func() (*http.Request, error) {
		reader, contentType, err := encodeBody(body)
		if err != nil {
			return nil, err
		}
		return c.prepareRequest(ctx, m, s, relURL, reader, contentType, rc)
	}
	resp, err := c.send(ctx, serverTrust, newReq, bodyReplayable(body))
	if err != nil {
		return FullResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return FullResponse{}, &TransportError{Op: "read-body", Err: sanitizeError(err)}
	}
	full := FullResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       data,
		RequestID:  extractRequestID(resp.Header),
	}
	if !full.IsSuccess() {
		return full, newAPIError(resp.StatusCode, data, resp.Header)
	}
	return full, nil
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, s Service, relURL string, opts ...ReqOption) (FullResponse, error) {
	return c.Invoke(ctx, MethodGet, s, relURL, nil, opts...)
}

// Post performs a POST request with the given body.
func (c *Client) Post(ctx context.Context, s Service, relURL string, body any, opts ...ReqOption) (FullResponse, error) {
	return c.Invoke(ctx, MethodPost, s, relURL, body, opts...)
}

// Put performs a PUT request with the given body.
func (c *Client) Put(ctx context.Context, s Service, relURL string, body any, opts ...ReqOption) (FullResponse, error) {
	return c.Invoke(ctx, MethodPut, s, relURL, body, opts...)
}

// Delete performs a DELETE request.
func (c *Client) Delete(ctx context.Context, s Service, relURL string, opts ...ReqOption) (FullResponse, error) {
	return c.Invoke(ctx, MethodDelete, s, relURL, nil, opts...)
}

// InvokeTyped performs an Invoke and JSON-decodes a successful response body into
// a value of type T. An empty body yields the zero value of T with no error.
func InvokeTyped[T any](ctx context.Context, c *Client, m HTTPMethod, s Service, relURL string, body any, opts ...ReqOption) (T, error) {
	var out T
	full, err := c.Invoke(ctx, m, s, relURL, body, opts...)
	if err != nil {
		return out, err
	}
	if len(bytes.TrimSpace(full.Body)) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(full.Body, &out); err != nil {
		return out, &TransportError{Op: "decode", Err: err}
	}
	return out, nil
}

// prepareRequest resolves the URL (honoring host and api-version overrides),
// applies the authorization axis and headers, and sets the content type when the
// caller did not supply one.
func (c *Client) prepareRequest(ctx context.Context, m HTTPMethod, s Service, relURL string, bodyReader io.Reader, contentType string, rc *requestConfig) (*http.Request, error) {
	host := c.host
	if rc.host != "" {
		host = rc.host
	}
	apiVersion := c.apiVersion
	if rc.apiVersion != "" {
		apiVersion = rc.apiVersion
	}
	base, err := s.baseURL(host, apiVersion)
	if err != nil {
		return nil, err
	}
	urlStr := joinURL(base, relURL, rc.params)
	req, err := buildHTTPRequest(ctx, m, urlStr, bodyReader, c.currentAuthorization(), rc.accept, rc.headers)
	if err != nil {
		return nil, err
	}
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

// encodeBody turns an Invoke body argument into a reader and its content type.
func encodeBody(body any) (io.Reader, string, error) {
	switch b := body.(type) {
	case nil:
		return nil, "", nil
	case json.RawMessage:
		if len(b) == 0 {
			return nil, "", nil
		}
		return bytes.NewReader(b), "application/json", nil
	case []byte:
		if len(b) == 0 {
			return nil, "", nil
		}
		return bytes.NewReader(b), "application/octet-stream", nil
	case string:
		if b == "" {
			return nil, "", nil
		}
		return strings.NewReader(b), "application/json", nil
	case io.Reader:
		return b, "application/octet-stream", nil
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return nil, "", &TransportError{Op: "encode", Err: err}
		}
		return bytes.NewReader(data), "application/json", nil
	}
}

// joinURL appends the relative URL and encoded query parameters to a base URL
// that already ends with a slash.
func joinURL(base, rel string, params url.Values) string {
	u := base + strings.TrimLeft(rel, "/")
	if len(params) == 0 {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + params.Encode()
}
