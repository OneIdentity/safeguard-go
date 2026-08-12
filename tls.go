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

// buildTLSConfig produces the *tls.Config shared by all transports from the
// resolved connection configuration. It enforces the secure-by-default and
// mutual-exclusion rules for the TLS options.
func (cfg *clientConfig) buildTLSConfig() (*tls.Config, error) {
	if cfg.insecure && cfg.certValidator != nil {
		return nil, errInsecureWithValidator
	}

	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
