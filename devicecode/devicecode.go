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

// Package devicecode provides an interactive Safeguard login using the OAuth
// device authorization grant: the appliance issues a short user code and a
// verification URL, the user visits the URL on any device and enters the code,
// and the SDK polls until authorization completes. It suits headless or
// input-constrained hosts (a shell over SSH, a TV, a CLI on a machine with no
// browser) where the browser add-on's loopback redirect cannot be used.
//
// It is an optional add-on with a one-way import of the root package. The
// resulting session is not refreshable, matching SafeguardDotNet and
// PySafeguard; to obtain a new token, call Connect again.
package devicecode

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/internal/auth"
)

// ErrNoPrompt indicates Connect was called without a prompt to display the user
// code. Compare with errors.Is.
var ErrNoPrompt = errors.New("devicecode: a prompt function is required to display the user code")

// ErrExpired indicates the user did not complete the device-code login before it
// expired. Compare with errors.Is.
var ErrExpired = auth.ErrDeviceCodeExpired

// ErrDenied indicates the user denied the device-code authorization request.
// Compare with errors.Is.
var ErrDenied = auth.ErrDeviceCodeDenied

// Prompt carries the details a user needs to complete a device-code login. A
// PromptFunc presents these to the user: the user visits VerificationURI and
// enters UserCode, or opens VerificationURIComplete which has the code embedded.
type Prompt struct {
	// UserCode is the short code the user enters at the verification URI.
	UserCode string
	// VerificationURI is the URL the user visits to enter the user code.
	VerificationURI string
	// VerificationURIComplete is the verification URL with the user code already
	// embedded, suitable for a link or QR code. It may be empty.
	VerificationURIComplete string
	// ExpiresIn is how long the user has to complete authentication.
	ExpiresIn time.Duration
}

// PromptFunc presents a Prompt to the user. It is called once, before polling
// begins. Returning an error aborts the login.
type PromptFunc func(ctx context.Context, p Prompt) error

// Option configures a device-code login.
type Option func(*config)

// config is the resolved device-code configuration.
type config struct {
	interval time.Duration
	sgOpts   []safeguard.Option
}

// WithPollInterval overrides how long to wait between polls of the token
// endpoint. The default follows the appliance's guidance (and backs off when the
// appliance asks the client to slow down). Setting a value below the appliance's
// minimum may cause it to return slow_down responses.
func WithPollInterval(d time.Duration) Option {
	return func(c *config) { c.interval = d }
}

// WithConnectionOptions forwards standard connection options (TLS trust, API
// version, timeouts, logger) to the underlying safeguard.Connect call.
func WithConnectionOptions(opts ...safeguard.Option) Option {
	return func(c *config) { c.sgOpts = append(c.sgOpts, opts...) }
}

// Connect authenticates to the Safeguard appliance at host using the device
// authorization grant and returns a ready client. It starts a device
// authorization, calls prompt once so the user can be shown the user code and
// verification URL, then polls until the user completes authentication, the code
// expires (ErrExpired), the user denies the request (ErrDenied), or the context
// is canceled.
func Connect(ctx context.Context, host string, prompt PromptFunc, opts ...Option) (*safeguard.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if prompt == nil {
		return nil, ErrNoPrompt
	}
	cfg := config{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}

	login := func(ctx context.Context, t safeguard.LoginTransport) (safeguard.Secret, error) {
		authCfg := auth.Config{Host: t.Host(), APIVersion: t.APIVersion(), HTTPClient: t}

		ch, err := auth.StartDeviceCode(ctx, authCfg, t)
		if err != nil {
			return safeguard.Secret{}, err
		}

		if err := prompt(ctx, Prompt{
			UserCode:                ch.UserCode,
			VerificationURI:         ch.VerificationURI,
			VerificationURIComplete: ch.VerificationURIComplete,
			ExpiresIn:               ch.ExpiresIn,
		}); err != nil {
			return safeguard.Secret{}, fmt.Errorf("devicecode: prompt: %w", err)
		}

		interval := ch.Interval
		if cfg.interval > 0 {
			interval = cfg.interval
		}

		userToken, err := auth.PollDeviceCode(ctx, authCfg, t, ch.DeviceCode, interval, ch.ExpiresIn)
		if err != nil {
			return safeguard.Secret{}, err
		}
		defer zero(userToken)
		return safeguard.NewSecret(userToken), nil
	}

	return safeguard.Connect(ctx, host, safeguard.AuthorizedSession(login), cfg.sgOpts...)
}

// zero best-effort wipes a byte slice holding sensitive material.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
