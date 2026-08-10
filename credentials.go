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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/OneIdentity/safeguard-go/internal/auth"
)

// Credential is a sealed Safeguard authentication strategy produced by one of
// this package's credential constructors: UsernamePassword, Certificate,
// PKCEHeadless, Token, Anonymous, or AuthorizedSession (the seam the browser and
// devicecode add-on packages use). Its only method is unexported, so the set of
// credentials is closed and callers cannot implement their own. Pass a Credential
// to Connect.
type Credential interface {
	// establish runs the credential's login against c's transports and returns
	// the resulting session. It is unexported to seal the interface.
	establish(ctx context.Context, c *Client) (*session, error)
}

// session is the immutable result of a successful login, ready to be published
// onto a client via installSession.
type session struct {
	token       Secret
	expiry      time.Time
	anonymous   bool
	refreshable bool
}

// UsernamePassword returns a credential that authenticates with the Resource
// Owner Grant (username and password). An empty provider selects the default
// local provider. The resulting session is refreshable. The password is copied
// into the credential; the caller retains ownership of the supplied Secret.
func UsernamePassword(provider, username string, password Secret) Credential {
	return &passwordCredential{provider: provider, username: username, password: cloneSecret(password)}
}

// Certificate returns a credential that authenticates with a client certificate
// over mutual TLS. certPEM is a concatenated PEM byte slice carrying the leaf
// certificate, any intermediate chain, and the private key; supply the key
// separately with WithPrivateKeyPEM when it lives in its own PEM input. password
// decrypts an encrypted PEM private key. Like PySafeguard, this SDK accepts PEM
// material only: PKCS#12 (.pfx/.p12) input is rejected with a clear error, so
// convert it first (for example, `openssl pkcs12 -in cert.pfx -nodes -out
// cert.pem`). The certificate material is parsed and validated at Connect time,
// so a bad certificate or password surfaces as a Connect error rather than a
// panic. The resulting session is refreshable.
func Certificate(certPEM []byte, password Secret, opts ...CertOption) Credential {
	cred := &certificateCredential{material: append([]byte(nil), certPEM...), password: cloneSecret(password)}
	for _, opt := range opts {
		if opt != nil {
			cred.opts = append(cred.opts, opt)
		}
	}
	return cred
}

// CertOption configures certificate login.
type CertOption func(*certConfig) error

// certConfig is the resolved certificate configuration.
type certConfig struct {
	provider string
	keyPEM   []byte
}

// WithPrivateKeyPEM supplies the private key as a separate PEM input when it is
// not concatenated with the certificate in the primary Certificate argument.
func WithPrivateKeyPEM(keyPEM []byte) CertOption {
	return func(cc *certConfig) error {
		cc.keyPEM = append([]byte(nil), keyPEM...)
		return nil
	}
}

// WithCertificateProvider overrides the authentication provider used for
// certificate login. The default is the built-in certificate provider.
func WithCertificateProvider(provider string) CertOption {
	return func(cc *certConfig) error {
		cc.provider = provider
		return nil
	}
}

// Token returns a credential that uses an existing Safeguard user token
// directly, skipping the RSTS/LoginResponse exchange. Such a session is
// intentionally not refreshable: the SDK has no credential with which to mint a
// replacement, so RefreshToken reports ErrNotRefreshable. The token is copied
// into the credential.
func Token(userToken Secret) Credential {
	return &tokenCredential{token: cloneSecret(userToken)}
}

// Anonymous returns a credential that establishes a session carrying no user
// token, sufficient for the Notification service and other anonymous endpoints.
func Anonymous() Credential {
	return anonymousCredential{}
}

// PKCEHeadless returns a credential that authenticates with the PKCE
// non-interactive ("headless") OAuth flow: the SDK drives the appliance's RSTS
// form controller directly, with no browser. An empty provider selects the
// default local provider; a non-default provider may be given as its display
// name, its RSTS provider id, or a unique substring of that id, and is resolved
// against the appliance's authentication providers the same way SafeguardDotNet
// and safeguard-ps resolve it. The resulting session is intentionally not
// refreshable, matching the reference SDKs' treatment of OAuth authorization-code
// flows, so RefreshToken reports ErrNotRefreshable and a 401 is surfaced rather
// than silently retried. Supply WithSecondaryFactor to satisfy multi-factor
// authentication. The password is copied into the credential; the caller retains
// ownership of the supplied Secret.
//
// PKCEHeadless is the recommended flow for test automation because it does not
// depend on the Resource Owner Grant, which appliances commonly disable.
func PKCEHeadless(provider, username string, password Secret, opts ...PKCEOption) Credential {
	cred := &pkceCredential{provider: provider, username: username, password: cloneSecret(password)}
	for _, opt := range opts {
		if opt != nil {
			cred.opts = append(cred.opts, opt)
		}
	}
	return cred
}

// PKCEOption configures a PKCE headless login.
type PKCEOption func(*pkceConfig)

// pkceConfig is the resolved PKCE configuration.
type pkceConfig struct {
	secondary SecondaryFactorFunc
}

// SecondaryFactorFunc supplies a multi-factor one-time code given the appliance's
// prompt. It is invoked only when the primary login step reports that a secondary
// factor is required. Returning an error aborts the login.
type SecondaryFactorFunc func(ctx context.Context, prompt string) (Secret, error)

// WithSecondaryFactor supplies the callback used to satisfy multi-factor
// authentication during a PKCE headless login. Without it, a login that reaches a
// secondary factor fails with ErrSecondaryFactorRequired.
func WithSecondaryFactor(fn SecondaryFactorFunc) PKCEOption {
	return func(pc *pkceConfig) {
		pc.secondary = fn
	}
}

// ErrSecondaryFactorRequired indicates a PKCE headless login reached a secondary
// (multi-factor) authentication step but no secondary factor provider was
// supplied. Provide WithSecondaryFactor. Compare with errors.Is.
var ErrSecondaryFactorRequired = auth.ErrSecondaryFactorRequired

// ErrSecondaryFactorFailed indicates the appliance rejected the supplied
// secondary (multi-factor) authentication code. Compare with errors.Is.
var ErrSecondaryFactorFailed = auth.ErrSecondaryFactorFailed

// passwordCredential implements the Resource Owner Grant.
type passwordCredential struct {
	provider string
	username string
	password Secret
}

func (p *passwordCredential) establish(ctx context.Context, c *Client) (*session, error) {
	httpClient, err := c.transports.client(serverTrust)
	if err != nil {
		return nil, err
	}
	pw := p.password.Expose()
	defer zeroBytes(pw)

	token, err := auth.LoginPassword(ctx, c.authConfig(httpClient, nil), p.provider, p.username, pw)
	if err != nil {
		return nil, translateAuthError(err)
	}
	defer zeroBytes(token)
	return &session{token: NewSecret(token), refreshable: true}, nil
}

// certificateCredential implements certificate (client-credentials) login.
type certificateCredential struct {
	material []byte
	password Secret
	opts     []CertOption
}

func (cc *certificateCredential) establish(ctx context.Context, c *Client) (*session, error) {
	cfg := &certConfig{}
	for _, opt := range cc.opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	cert, err := parseClientCertificate(cc.material, cc.password, cfg.keyPEM)
	if err != nil {
		return nil, err
	}

	c.transports.setClientCerts([]tls.Certificate{cert})
	serverHTTPClient, err := c.transports.client(serverTrust)
	if err != nil {
		return nil, err
	}
	certHTTPClient, err := c.transports.client(clientCert)
	if err != nil {
		return nil, err
	}

	token, err := auth.LoginCertificate(ctx, c.authConfig(serverHTTPClient, certHTTPClient), cfg.provider)
	if err != nil {
		return nil, translateAuthError(err)
	}
	defer zeroBytes(token)
	return &session{token: NewSecret(token), refreshable: true}, nil
}

// tokenCredential uses a caller-supplied user token unchanged.
type tokenCredential struct {
	token Secret
}

func (t *tokenCredential) establish(_ context.Context, _ *Client) (*session, error) {
	if t.token.IsZero() {
		return nil, errEmptyToken
	}
	return &session{token: NewSecret(t.token.Expose()), refreshable: false}, nil
}

// anonymousCredential establishes a token-less session.
type anonymousCredential struct{}

func (anonymousCredential) establish(_ context.Context, _ *Client) (*session, error) {
	return &session{anonymous: true}, nil
}

// pkceCredential implements the PKCE non-interactive (headless) login.
type pkceCredential struct {
	provider string
	username string
	password Secret
	opts     []PKCEOption
}

func (p *pkceCredential) establish(ctx context.Context, c *Client) (*session, error) {
	cfg := &pkceConfig{}
	for _, opt := range p.opts {
		opt(cfg)
	}

	httpClient, err := c.transports.client(serverTrust)
	if err != nil {
		return nil, err
	}
	pw := p.password.Expose()
	defer zeroBytes(pw)

	var secondary auth.SecondaryFactorProvider
	if cfg.secondary != nil {
		secondary = func(ctx context.Context, prompt string) ([]byte, error) {
			code, err := cfg.secondary(ctx, prompt)
			if err != nil {
				return nil, err
			}
			return code.Expose(), nil
		}
	}

	token, err := auth.LoginPKCE(ctx, c.authConfig(httpClient, nil), p.provider, p.username, pw, secondary)
	if err != nil {
		return nil, translateAuthError(err)
	}
	defer zeroBytes(token)
	return &session{token: NewSecret(token), refreshable: false}, nil
}

// authConfig builds the internal broker configuration for this client using the
// given server-trust and (optional) client-certificate transports.
func (c *Client) authConfig(serverHTTPClient, certHTTPClient auth.HTTPClient) auth.Config {
	return auth.Config{
		Host:           c.host,
		APIVersion:     c.apiVersion,
		HTTPClient:     serverHTTPClient,
		CertHTTPClient: certHTTPClient,
	}
}

// parseClientCertificate builds a tls.Certificate from PEM material. The private
// key may be concatenated with the certificate in certPEM or supplied separately
// in keyPEM. An encrypted PEM key is decrypted with password. PKCS#12 (.pfx/.p12)
// input is rejected with errPKCS12Unsupported; convert it to PEM first.
func parseClientCertificate(certPEM []byte, password Secret, keyPEM []byte) (tls.Certificate, error) {
	if looksLikePKCS12(certPEM) {
		return tls.Certificate{}, errPKCS12Unsupported
	}

	var certBlocks [][]byte
	var keyDER []byte
	var keyType string

	collect := func(src []byte) error {
		rest := src
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil
			}
			switch {
			case block.Type == "CERTIFICATE":
				certBlocks = append(certBlocks, block.Bytes)
			case isPrivateKeyBlock(block.Type):
				der, err := decodeKeyBlock(block, password)
				if err != nil {
					return err
				}
				keyDER = der
				keyType = block.Type
			}
		}
	}

	if err := collect(certPEM); err != nil {
		return tls.Certificate{}, err
	}
	if len(keyPEM) > 0 {
		if err := collect(keyPEM); err != nil {
			return tls.Certificate{}, err
		}
	}

	if len(certBlocks) == 0 {
		return tls.Certificate{}, errNoCertificateInPEM
	}
	if len(keyDER) == 0 {
		return tls.Certificate{}, errNoPrivateKeyInPEM
	}

	key, err := parsePrivateKeyDER(keyType, keyDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{Certificate: certBlocks, PrivateKey: key}
	leaf, err := x509.ParseCertificate(certBlocks[0])
	if err != nil {
		return tls.Certificate{}, &TransportError{Op: "parse-certificate", Err: err}
	}
	cert.Leaf = leaf
	return cert, nil
}

// isPrivateKeyBlock reports whether a PEM block type names a private key.
func isPrivateKeyBlock(blockType string) bool {
	switch blockType {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	default:
		return false
	}
}

// decodeKeyBlock returns the DER bytes of a PEM key block, decrypting a legacy
// encrypted PEM block with password when present.
func decodeKeyBlock(block *pem.Block, password Secret) ([]byte, error) {
	//nolint:staticcheck // x509.IsEncryptedPEMBlock/DecryptPEMBlock are the only
	// stdlib path for legacy DEK-Info encrypted PEM keys still found in the wild.
	if x509.IsEncryptedPEMBlock(block) {
		if password.IsZero() {
			return nil, errEncryptedKeyNoPassword
		}
		pw := password.Expose()
		defer zeroBytes(pw)
		//nolint:staticcheck // see above.
		der, err := x509.DecryptPEMBlock(block, pw)
		if err != nil {
			return nil, &TransportError{Op: "decrypt-private-key", Err: err}
		}
		return der, nil
	}
	return block.Bytes, nil
}

// parsePrivateKeyDER parses a private key from DER, honoring the PEM block type
// for the legacy single-algorithm encodings and falling back to PKCS#8.
func parsePrivateKeyDER(blockType string, der []byte) (any, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, &TransportError{Op: "parse-private-key", Err: err}
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, &TransportError{Op: "parse-private-key", Err: err}
		}
		return key, nil
	default:
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, &TransportError{Op: "parse-private-key", Err: err}
		}
		return key, nil
	}
}

// looksLikePKCS12 reports whether material appears to be a PKCS#12 blob rather
// than PEM text. PEM always begins with an ASCII armor header; a DER PKCS#12
// container begins with an ASN.1 SEQUENCE tag (0x30).
func looksLikePKCS12(material []byte) bool {
	for _, b := range material {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '-':
			return false // PEM armor
		default:
			return b == 0x30
		}
	}
	return false
}

// translateAuthError maps an internal broker error onto the public error
// hierarchy: an HTTP status becomes an APIError (and its 401/403/404
// specializations), a transport failure becomes a TransportError, and the
// login-response and multi-factor sentinels pass through for errors.Is.
func translateAuthError(err error) error {
	if errors.Is(err, auth.ErrSecondaryFactorRequired) || errors.Is(err, auth.ErrSecondaryFactorFailed) {
		return err
	}
	if errors.Is(err, auth.ErrDeviceCodeDenied) || errors.Is(err, auth.ErrDeviceCodeExpired) {
		return err
	}
	var re *auth.RequestError
	if errors.As(err, &re) {
		switch {
		case re.StatusCode >= 400:
			return newAPIError(re.StatusCode, re.Body(), nil)
		case re.Err != nil && re.StatusCode == 0:
			return &TransportError{Op: "authenticate", Err: re.Err}
		}
	}
	return err
}

// zeroBytes best-effort wipes a byte slice holding sensitive material.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// cloneSecret returns an independent copy of s so a caller zeroing its own
// Secret cannot later disturb material the SDK still needs (for example a
// password retained for refresh).
func cloneSecret(s Secret) Secret {
	if s.IsZero() {
		return Secret{}
	}
	b := s.Expose()
	defer zeroBytes(b)
	return NewSecret(b)
}
