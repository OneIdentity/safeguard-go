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

// Package browser provides an interactive Safeguard login that opens the user's
// system web browser to complete OAuth authorization (the authorization-code
// flow with PKCE). It is an optional add-on: importing it pulls in the machinery
// to launch a browser and run a loopback HTTP listener, so headless and server
// consumers that never need an interactive login are not forced to compile it in.
//
// The resulting session is not refreshable, matching SafeguardDotNet and
// PySafeguard, which treat browser logins as existing-token connections. To
// obtain a new token, call Connect again.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/auth"
)

// ErrNoAuthorizationCode indicates the loopback listener received the browser
// redirect but it carried no authorization code. Compare with errors.Is.
var ErrNoAuthorizationCode = errors.New("browser: redirect carried no authorization code")

// Option configures a browser login.
type Option func(*config)

// config is the resolved browser-login configuration.
type config struct {
	port      int
	loginHint string
	open      func(url string) error
	sgOpts    []safeguard.Option
}

// WithPort binds the loopback redirect listener to a fixed TCP port on
// 127.0.0.1. The default is 0, which lets the operating system choose a free
// ephemeral port; the chosen port is passed to the appliance in the redirect URI.
// Set a fixed port only when a firewall or the appliance requires one.
func WithPort(port int) Option {
	return func(c *config) { c.port = port }
}

// WithLoginHint pre-fills the appliance login form with username by passing it as
// the OAuth login_hint. It is a convenience only; the user still authenticates in
// the browser.
func WithLoginHint(username string) Option {
	return func(c *config) { c.loginHint = username }
}

// WithBrowserOpener overrides how the authorization URL is opened. The default
// launches the operating system's default browser. Supply a custom opener to
// integrate with an embedded browser, to log the URL for a remote user, or to
// drive tests.
func WithBrowserOpener(open func(url string) error) Option {
	return func(c *config) {
		if open != nil {
			c.open = open
		}
	}
}

// WithConnectionOptions forwards standard connection options (TLS trust, API
// version, timeouts, logger) to the underlying safeguard.Connect call.
func WithConnectionOptions(opts ...safeguard.Option) Option {
	return func(c *config) { c.sgOpts = append(c.sgOpts, opts...) }
}

// Connect authenticates to the Safeguard appliance at host by opening the
// system browser for OAuth authorization and returns a ready client. It runs a
// loopback HTTP listener on 127.0.0.1 to capture the authorization code the
// appliance redirects back, exchanges it for a Safeguard user token, and hands
// that token to the SDK. The call blocks until the user completes authentication,
// the context is canceled, or an error occurs.
func Connect(ctx context.Context, host string, opts ...Option) (*safeguard.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := config{open: openSystemBrowser}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}

	login := func(ctx context.Context, t safeguard.LoginTransport) (safeguard.Secret, error) {
		authCfg := auth.Config{Host: t.Host(), APIVersion: t.APIVersion(), HTTPClient: t}

		pair, err := auth.NewPKCEPair()
		if err != nil {
			return safeguard.Secret{}, err
		}

		listener, err := newCapture(cfg.port)
		if err != nil {
			return safeguard.Secret{}, err
		}
		defer listener.Close()

		authURL := auth.BrowserAuthorizeURL(authCfg, pair.Challenge, listener.Port(), cfg.loginHint)
		if err := cfg.open(authURL); err != nil {
			return safeguard.Secret{}, fmt.Errorf("browser: open system browser: %w", err)
		}

		code, err := listener.wait(ctx)
		if err != nil {
			return safeguard.Secret{}, err
		}

		userToken, err := auth.RedeemBrowserCode(ctx, authCfg, t, code, pair.Verifier)
		if err != nil {
			return safeguard.Secret{}, err
		}
		defer zero(userToken)
		return safeguard.NewSecret(userToken), nil
	}

	return safeguard.Connect(ctx, host, safeguard.AuthorizedSession(login), cfg.sgOpts...)
}

// capturePageHTML is served to the browser after the redirect is captured.
const capturePageHTML = `<!DOCTYPE html><html><head><title>Safeguard</title></head>` +
	`<body style="font-family:sans-serif"><h2>Authentication complete.</h2>` +
	`<p>You may close this window and return to the application.</p></body></html>`

// capture is a one-shot loopback HTTP listener that captures the authorization
// code the appliance redirects to after the user authenticates.
type capture struct {
	ln     net.Listener
	srv    *http.Server
	codeCh chan string
	errCh  chan error
}

// newCapture starts a loopback listener on 127.0.0.1 at port (0 for an ephemeral
// port) and begins serving. It returns once the listener is bound so the caller
// can read the chosen port before opening the browser.
func newCapture(port int) (*capture, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("browser: start loopback listener: %w", err)
	}
	c := &capture{
		ln:     ln,
		codeCh: make(chan string, 1),
		errCh:  make(chan error, 1),
	}
	c.srv = &http.Server{
		Handler:           http.HandlerFunc(c.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := c.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case c.errCh <- err:
			default:
			}
		}
	}()
	return c, nil
}

// handle records the first redirect that carries an authorization code and
// serves a success page. The appliance returns the code in the oauth query
// parameter (not the standard code parameter).
func (c *capture) handle(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("oauth")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		select {
		case c.errCh <- ErrNoAuthorizationCode:
		default:
		}
		return
	}
	_, _ = w.Write([]byte(capturePageHTML))
	select {
	case c.codeCh <- code:
	default:
	}
}

// Port returns the loopback TCP port the listener is bound to.
func (c *capture) Port() int { return c.ln.Addr().(*net.TCPAddr).Port }

// wait blocks until an authorization code arrives, the listener fails, or ctx is
// canceled.
func (c *capture) wait(ctx context.Context) (string, error) {
	select {
	case code := <-c.codeCh:
		return code, nil
	case err := <-c.errCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close shuts down the listener and HTTP server.
func (c *capture) Close() {
	_ = c.srv.Close()
}

// openSystemBrowser opens url in the operating system's default browser.
func openSystemBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// zero best-effort wipes a byte slice holding sensitive material.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
