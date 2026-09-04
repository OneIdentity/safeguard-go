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
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// errInsecureWithValidator is returned when WithInsecureTLS is combined with
// WithServerCertValidator: disabling verification and adding an additive
// validator are contradictory.
var errInsecureWithValidator = errors.New(
	"safeguard: WithInsecureTLS cannot be combined with WithServerCertValidator")

// errInvalidCABundle is returned when a supplied CA bundle contains no usable
// PEM certificates.
var errInvalidCABundle = errors.New("safeguard: CA bundle contained no valid certificates")

// errTLSVersionRange is returned when the configured maximum TLS version is
// lower than the configured (or default) minimum.
var errTLSVersionRange = errors.New("safeguard: maximum TLS version is lower than the minimum TLS version")

// ServerCertValidator is an additive server-certificate check. It runs only
// after the normal chain and hostname verification succeeds and can therefore
// only further restrict trust, never relax it (parity with the .NET
// RemoteCertificateValidationCallback). Returning a non-nil error fails the
// handshake. leaf is the server's leaf certificate; verifiedChains are the
// chains the standard verifier accepted.
type ServerCertValidator func(leaf *x509.Certificate, verifiedChains [][]*x509.Certificate) error

// WithCABundle trusts the certificates in pemBytes (an internal PKI/appliance CA)
// for server verification, replacing the system trust store rather than adding to
// it: once a bundle is set, only the certificates it contains are trusted to
// verify the appliance's certificate chain. It is the secure way to trust a
// self-signed or privately issued appliance certificate.
func WithCABundle(pemBytes []byte) Option {
	return func(cfg *clientConfig) error {
		cp := make([]byte, len(pemBytes))
		copy(cp, pemBytes)
		cfg.caBundle = cp
		return nil
	}
}

// WithServerCertValidator adds an additive validation callback that runs after
// normal chain and hostname verification. It cannot be combined with
// WithInsecureTLS.
func WithServerCertValidator(v ServerCertValidator) Option {
	return func(cfg *clientConfig) error {
		cfg.certValidator = v
		return nil
	}
}

// WithInsecureTLS disables TLS chain and hostname verification on every
// transport, including the event WebSocket. It exists only for bootstrapping
// self-signed appliances in development and test; it is loud and dangerous and
// must never be used in production. It cannot be combined with
// WithServerCertValidator, and it never enables HTTP redirect following.
func WithInsecureTLS() Option {
	return func(cfg *clientConfig) error {
		cfg.insecure = true
		return nil
	}
}

// WithMinTLSVersion sets the minimum TLS protocol version the client will
// negotiate on every transport. Pass a crypto/tls version constant, for example
// tls.VersionTLS13 to require TLS 1.3. The value is written straight through to
// tls.Config.MinVersion, so protocol versions added to crypto/tls in the future
// are supported without an SDK change.
//
// The default minimum is TLS 1.2. Lowering it below TLS 1.2 is an explicit,
// discouraged escape hatch for interoperating with legacy endpoints; it weakens
// transport security and should never be used in production.
func WithMinTLSVersion(v uint16) Option {
	return func(cfg *clientConfig) error {
		cfg.minTLS = v
		return nil
	}
}

// WithMaxTLSVersion sets the maximum TLS protocol version the client will
// negotiate on every transport. Pass a crypto/tls version constant, for example
// tls.VersionTLS12 to pin negotiation to TLS 1.2. The value is written straight
// through to tls.Config.MaxVersion, so future protocol versions are supported
// without an SDK change.
//
// The default (an unset maximum) uses the crypto/tls default maximum. Pinning
// the maximum to TLS 1.2 keeps client-certificate authentication working against
// appliances that request the certificate after the handshake, because Go's TLS
// stack supports that renegotiation only at TLS 1.2, not the TLS 1.3
// post-handshake equivalent.
func WithMaxTLSVersion(v uint16) Option {
	return func(cfg *clientConfig) error {
		cfg.maxTLS = v
		return nil
	}
}

// clientCertMaxTLS returns the maximum TLS version the clientCert transport
// (certificate login, A2A) should be capped to, or 0 for no additional cap.
//
// Certificate authentication requires presenting the client certificate in
// response to a request the appliance makes after the handshake; Go's TLS stack
// supports that only at TLS 1.2 (renegotiation), not the TLS 1.3 post-handshake
// equivalent. So when the caller expresses no explicit TLS version preference,
// the clientCert transport defaults to a TLS 1.2 ceiling to keep certificate and
// A2A auth working on the appliance Standard binding, while the serverTrust
// transport (password/token/PKCE) is free to negotiate TLS 1.3. Any explicit
// WithMinTLSVersion/WithMaxTLSVersion disables the cap, letting a caller opt into
// TLS 1.3 certificate auth against the appliance Cert SNI hostname (where the
// certificate is requested in-handshake).
func (cfg *clientConfig) clientCertMaxTLS() uint16 {
	if cfg.minTLS != 0 || cfg.maxTLS != 0 {
		return 0
	}
	return tls.VersionTLS12
}

// buildTLSConfig produces the *tls.Config shared by all transports from the
// resolved connection configuration. It enforces the secure-by-default and
// mutual-exclusion rules for the TLS options.
func (cfg *clientConfig) buildTLSConfig() (*tls.Config, error) {
	if cfg.insecure && cfg.certValidator != nil {
		return nil, errInsecureWithValidator
	}

	// Resolve the negotiated version window. An unset minimum defaults to the
	// secure-by-default TLS 1.2 floor; an unset maximum (0) lets crypto/tls pick
	// its own default maximum. Values are passed straight through so future
	// protocol versions need no SDK change.
	minVer := cfg.minTLS
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}
	if cfg.maxTLS != 0 && cfg.maxTLS < minVer {
		return nil, errTLSVersionRange
	}

	// #nosec G402 -- MinVersion defaults to TLS 1.2; WithMinTLSVersion may lower
	// it as an explicit, documented escape hatch for legacy interoperability.
	tc := &tls.Config{
		MinVersion: minVer,
		MaxVersion: cfg.maxTLS,
		// Renegotiation is left at the default (RenegotiateNever) here so the
		// server-trust transports shared by every standard call never permit it.
		// Free client renegotiation is enabled only on the client-certificate
		// transport, where the legacy A2A/RSTS endpoints require it; see the
		// clientCert branches in transportSet.client and transportSet.websocketClient.
	}

	if cfg.insecure {
		// #nosec G402 -- WithInsecureTLS is an explicit, documented bootstrap-only
		// override for self-signed appliances; it is never the default.
		tc.InsecureSkipVerify = true
		return tc, nil
	}

	if len(cfg.caBundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.caBundle) {
			return nil, errInvalidCABundle
		}
		tc.RootCAs = pool
	}

	if cfg.certValidator != nil {
		validator := cfg.certValidator
		// VerifyConnection runs after the standard verification (chain + hostname),
		// so the callback can only further restrict trust.
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			var leaf *x509.Certificate
			if len(cs.PeerCertificates) > 0 {
				leaf = cs.PeerCertificates[0]
			}
			return validator(leaf, cs.VerifiedChains)
		}
	}

	return tc, nil
}
