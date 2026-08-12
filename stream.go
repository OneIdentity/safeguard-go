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
	"context"
	"io"
	"net/http"
)

// Stream performs a request and returns the response body as an io.ReadCloser
// that the caller must Close. The body is not buffered and is never retried, so a
// consumed stream cannot be replayed. On a non-2xx status Stream closes the body,
// returns a nil reader, and reports a typed *APIError along with a Response
// whose Body holds the (bounded) error payload. Unlike Invoke, Stream does not
// apply WithRequestTimeout; a streaming caller controls cancellation through ctx.
func (c *Client) Stream(ctx context.Context, m HTTPMethod, s Service, relURL string, body any, opts ...ReqOption) (io.ReadCloser, Response, error) {
	if c.isClosed() {
		return nil, Response{}, ErrClosed
	}
	rc, err := applyReqOptions(opts...)
	if err != nil {
		return nil, Response{}, err
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
		return nil, Response{}, err
	}
	full := Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		RequestID:  extractRequestID(resp.Header),
	}
	if !full.IsSuccess() {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxStoredErrorBody+1))
		_ = resp.Body.Close()
		full.Body = data
		return nil, full, newAPIError(resp.StatusCode, data, resp.Header)
	}
	return resp.Body, full, nil
}

// Upload sends the contents of r as an application/octet-stream POST body without
// buffering it, and returns the (fully read) response. The content type may be
// overridden with WithHeader.
func (c *Client) Upload(ctx context.Context, s Service, relURL string, r io.Reader, opts ...ReqOption) (Response, error) {
	if c.isClosed() {
		return Response{}, ErrClosed
	}
	rc, err := applyReqOptions(opts...)
	if err != nil {
		return Response{}, err
	}
	if rc.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, rc.timeout)
		defer cancel()
	}
	newReq := func() (*http.Request, error) {
		return c.prepareRequest(ctx, MethodPost, s, relURL, r, "application/octet-stream", rc)
	}
	resp, err := c.send(ctx, serverTrust, newReq, false)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, &TransportError{Op: "read-body", Err: sanitizeError(err)}
	}
	full := Response{
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

// Download performs a GET and streams the response body to w, returning a
// Response that carries the status, headers, and request id but a nil Body
// (the payload went to w). On a non-2xx status the bounded error payload is read
// into Response.Body and returned with a typed *APIError. The default Accept
// is application/octet-stream; override it with WithAccept.
func (c *Client) Download(ctx context.Context, s Service, relURL string, w io.Writer, opts ...ReqOption) (Response, error) {
	if c.isClosed() {
		return Response{}, ErrClosed
	}
	rc, err := applyReqOptions(opts...)
	if err != nil {
		return Response{}, err
	}
	if rc.accept == "" {
		rc.accept = "application/octet-stream"
	}
	newReq := func() (*http.Request, error) {
		return c.prepareRequest(ctx, MethodGet, s, relURL, nil, "", rc)
	}
	resp, err := c.send(ctx, serverTrust, newReq, true)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	full := Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		RequestID:  extractRequestID(resp.Header),
	}
	if !full.IsSuccess() {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxStoredErrorBody+1))
		full.Body = data
		return full, newAPIError(resp.StatusCode, data, resp.Header)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return full, &TransportError{Op: "download", Err: sanitizeError(err)}
	}
	return full, nil
}
