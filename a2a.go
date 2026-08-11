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
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

// A2AContext retrieves credentials with the Safeguard Application-to-Application
// (A2A) service. Unlike Client, it is not a token session: it authenticates with
// a client certificate over mutual TLS on every call, and each retrieval is
// authorized by a per-account API key passed as an argument. The API key
// identifies which registered account the call targets; the certificate proves
// the calling application's identity.
//
// A2AContext is created with NewA2AContext, which parses the certificate in
// memory without contacting the appliance; networked and certificate-dependent
// state is validated on the first retrieval. It is safe for concurrent use, and
// its transports must be released with Close.
type A2AContext struct {
	host       string
	apiVersion string
	transports *transportSet
	logger     *slog.Logger

	closed atomic.Bool
}

// a2aConfig is the resolved configuration produced by applying A2AOptions.
type a2aConfig struct {
	conn   *clientConfig
	keyPEM []byte
}

// A2AOption configures an A2AContext. Options are applied in order and may return
// an error to reject an invalid configuration.
type A2AOption func(*a2aConfig) error

// WithA2APrivateKeyPEM supplies the client certificate's private key as a
// separate PEM input when it is not concatenated with the certificate in the
// primary NewA2AContext argument, mirroring Certificate's WithPrivateKeyPEM.
func WithA2APrivateKeyPEM(keyPEM []byte) A2AOption {
	return func(cfg *a2aConfig) error {
		cfg.keyPEM = append([]byte(nil), keyPEM...)
		return nil
	}
}

// WithA2AConnectionOptions applies standard connection Options (TLS trust, API
// version, timeouts, logger) to the A2A context. It reuses the same Option set as
// Connect so A2A callers configure their connection exactly like everyone else,
// for example WithCABundle, WithInsecureTLS, or WithAPIVersion.
func WithA2AConnectionOptions(opts ...Option) A2AOption {
	return func(cfg *a2aConfig) error {
		return cfg.conn.apply(opts...)
	}
}

// NewA2AContext builds an A2AContext for host that authenticates with the client
// certificate in certPEM over mutual TLS. certPEM is concatenated PEM carrying
// the leaf certificate, any intermediate chain, and the private key; supply the
// key separately with WithA2APrivateKeyPEM when it lives in its own PEM input.
// password decrypts an encrypted PEM private key. Like the Certificate
// credential, only PEM material is accepted: PKCS#12 (.pfx/.p12) input is
// rejected with a clear error, so convert it first (for example, `openssl pkcs12
// -in cert.pfx -nodes -out cert.pem`).
//
// The certificate is parsed and validated here, so a bad certificate or password
// surfaces immediately; no network call is made until the first retrieval.
func NewA2AContext(host string, certPEM []byte, password Secret, opts ...A2AOption) (*A2AContext, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errEmptyHost
	}
	cfg := &a2aConfig{conn: defaultClientConfig()}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	tlsConfig, err := cfg.conn.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	cert, err := parseClientCertificate(certPEM, password, cfg.keyPEM)
	if err != nil {
		return nil, err
	}
	ts := newTransportSet(tlsConfig, cfg.conn.timeouts)
	ts.setClientCerts([]tls.Certificate{cert})
	return &A2AContext{
		host:       host,
		apiVersion: cfg.conn.apiVersion,
		transports: ts,
		logger:     cfg.conn.logger,
	}, nil
}

// Host returns the appliance host the context is bound to.
func (a *A2AContext) Host() string { return a.host }

// APIVersion returns the default API version the context uses.
func (a *A2AContext) APIVersion() string { return a.apiVersion }

// Close is terminal: it releases the transport pools. After Close the context
// cannot be used. Close is idempotent.
func (a *A2AContext) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	a.transports.Close()
	return nil
}

// KeyFormat selects the encoding of an SSH private key returned by
// RetrievePrivateKey. The values match the Safeguard API's PascalCase names.
type KeyFormat string

const (
	// KeyFormatOpenSSH requests the OpenSSH private-key format. It is the default
	// when RetrievePrivateKey is given an empty KeyFormat.
	KeyFormatOpenSSH KeyFormat = "OpenSsh"
	// KeyFormatSSH2 requests the SSH2 (RFC 4716) private-key format.
	KeyFormatSSH2 KeyFormat = "Ssh2"
	// KeyFormatPuTTY requests the PuTTY private-key format.
	KeyFormatPuTTY KeyFormat = "Putty"
)

// APIKeySecret is one API key credential retrieved for a registered account. The
// ClientSecret is wrapped in a Secret; the surrounding metadata is not sensitive.
type APIKeySecret struct {
	// ID is the API key's object identifier.
	ID int
	// Name is the API key's name.
	Name string
	// Description is the API key's description.
	Description string
	// ClientID is the OAuth client identifier.
	ClientID string
	// ClientSecret is the OAuth client secret. It is empty when the appliance
	// does not return the secret value for this key.
	ClientSecret Secret
	// ClientSecretID identifies the client secret.
	ClientSecretID string
}

// RetrievePassword retrieves the password of the account identified by apiKey.
// The returned Secret holds the password; it is empty when the account has no
// stored password.
func (a *A2AContext) RetrievePassword(ctx context.Context, apiKey Secret) (Secret, error) {
	full, err := a.a2aDo(ctx, MethodGet, "Credentials", nil, a2aAuth(apiKey), url.Values{"type": {"Password"}})
	if err != nil {
		return Secret{}, err
	}
	return decodeSecretString(full.Body)
}

// RetrievePrivateKey retrieves the SSH private key of the account identified by
// apiKey, encoded in the requested KeyFormat. An empty format selects
// KeyFormatOpenSSH. The returned Secret holds the private key.
func (a *A2AContext) RetrievePrivateKey(ctx context.Context, apiKey Secret, format KeyFormat) (Secret, error) {
	if format == "" {
		format = KeyFormatOpenSSH
	}
	params := url.Values{"type": {"PrivateKey"}, "keyFormat": {string(format)}}
	full, err := a.a2aDo(ctx, MethodGet, "Credentials", nil, a2aAuth(apiKey), params)
	if err != nil {
		return Secret{}, err
	}
	return decodeSecretString(full.Body)
}

// RetrieveAPIKeySecret retrieves the API key credentials of the account
// identified by apiKey. The appliance returns one entry per configured API key.
func (a *A2AContext) RetrieveAPIKeySecret(ctx context.Context, apiKey Secret) ([]APIKeySecret, error) {
	full, err := a.a2aDo(ctx, MethodGet, "Credentials", nil, a2aAuth(apiKey), url.Values{"type": {"ApiKey"}})
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(full.Body)) == 0 {
		return nil, nil
	}
	var raw []struct {
		ID             int    `json:"Id"`
		Name           string `json:"Name"`
		Description    string `json:"Description"`
		ClientID       string `json:"ClientId"`
		ClientSecret   string `json:"ClientSecret"`
		ClientSecretID string `json:"ClientSecretId"`
	}
	if err := json.Unmarshal(full.Body, &raw); err != nil {
		return nil, &TransportError{Op: "decode", Err: err}
	}
	out := make([]APIKeySecret, len(raw))
	for i, r := range raw {
		out[i] = APIKeySecret{
			ID:             r.ID,
			Name:           r.Name,
			Description:    r.Description,
			ClientID:       r.ClientID,
			ClientSecret:   NewSecretString(r.ClientSecret),
			ClientSecretID: r.ClientSecretID,
		}
	}
	return out, nil
}

// A2ARetrievableAccount describes one account that the context's client
// certificate is registered to retrieve credentials for. The APIKey authorizes
// retrieval of that account's credential and is wrapped in a Secret; the
// surrounding metadata is not sensitive. The same account may appear more than
// once -- once per credential type it is registered for -- each with a distinct
// APIKey; the response does not record which credential type an entry is for.
type A2ARetrievableAccount struct {
	// ApplicationName is the AppName of the registration this account belongs to.
	ApplicationName string
	// Description is the registration's description.
	Description string
	// Disabled reports whether the account or its registration is disabled.
	Disabled bool
	// APIKey is the A2A API key that authorizes retrieval of this account's
	// credential. Pass it to a Retrieve method.
	APIKey Secret
	// AssetID is the object ID of the account's asset.
	AssetID int
	// AssetName is the name of the account's asset.
	AssetName string
	// AssetNetworkAddress is the network address of the account's asset.
	AssetNetworkAddress string
	// AssetDescription is the description of the account's asset.
	AssetDescription string
	// AccountID is the account's object ID.
	AccountID int
	// AccountName is the account's name.
	AccountName string
	// DomainName is the account's domain, when it is a directory account.
	DomainName string
	// AccountType identifies the kind of account.
	AccountType string
	// AccountDescription is the account's description.
	AccountDescription string
}

// GetRetrievableAccounts lists the accounts the context's client certificate is
// registered to retrieve credentials for, across every A2A registration bound to
// the certificate. Unlike the Retrieve methods it is authorized by the client
// certificate alone -- no per-account API key -- because it enumerates all
// registrations for the certificate user. The optional filter is an OData filter
// expression applied to each registration's accounts; pass "" for no filter.
//
// The returned entries carry the per-account APIKey, so a caller can discover an
// account here and pass its APIKey straight to RetrievePassword,
// RetrievePrivateKey, or RetrieveAPIKeySecret. Because an entry does not record
// which credential type it was registered for, a caller that registered an
// account for more than one type must track that mapping itself.
func (a *A2AContext) GetRetrievableAccounts(ctx context.Context, filter string) ([]A2ARetrievableAccount, error) {
	full, err := a.doService(ctx, Core, MethodGet, "A2ARegistrations", nil, noAuth(), nil)
	if err != nil {
		return nil, err
	}
	var registrations []struct {
		ID          int    `json:"Id"`
		AppName     string `json:"AppName"`
		Description string `json:"Description"`
		Disabled    bool   `json:"Disabled"`
	}
	if err := json.Unmarshal(full.Body, &registrations); err != nil {
		return nil, &TransportError{Op: "decode", Err: err}
	}

	var params url.Values
	if filter != "" {
		params = url.Values{"filter": {filter}}
	}

	var out []A2ARetrievableAccount
	for _, reg := range registrations {
		full, err := a.doService(ctx, Core, MethodGet, "A2ARegistrations/"+strconv.Itoa(reg.ID)+"/RetrievableAccounts", nil, noAuth(), params)
		if err != nil {
			return nil, err
		}
		var raw []struct {
			AccountDisabled    int    `json:"AccountDisabled"`
			APIKey             string `json:"ApiKey"`
			AssetID            int    `json:"AssetId"`
			AssetName          string `json:"AssetName"`
			NetworkAddress     string `json:"NetworkAddress"`
			AssetDescription   string `json:"AssetDescription"`
			AccountID          int    `json:"AccountId"`
			AccountName        string `json:"AccountName"`
			DomainName         string `json:"DomainName"`
			AccountType        string `json:"AccountType"`
			AccountDescription string `json:"AccountDescription"`
		}
		if len(bytes.TrimSpace(full.Body)) == 0 {
			continue
		}
		if err := json.Unmarshal(full.Body, &raw); err != nil {
			return nil, &TransportError{Op: "decode", Err: err}
		}
		for _, r := range raw {
			out = append(out, A2ARetrievableAccount{
				ApplicationName:     reg.AppName,
				Description:         reg.Description,
				Disabled:            reg.Disabled || r.AccountDisabled != 0,
				APIKey:              NewSecretString(r.APIKey),
				AssetID:             r.AssetID,
				AssetName:           r.AssetName,
				AssetNetworkAddress: r.NetworkAddress,
				AssetDescription:    r.AssetDescription,
				AccountID:           r.AccountID,
				AccountName:         r.AccountName,
				DomainName:          r.DomainName,
				AccountType:         r.AccountType,
				AccountDescription:  r.AccountDescription,
			})
		}
	}
	return out, nil
}

// SetPassword stores newPassword as the password of the account identified by
// apiKey, writing it back to Safeguard over the A2A service. The account's A2A
// registration must have bidirectional (write-back) access enabled, or the
// appliance rejects the call.
func (a *A2AContext) SetPassword(ctx context.Context, apiKey Secret, newPassword Secret) error {
	body, err := jsonSecretBody(newPassword)
	if err != nil {
		return err
	}
	_, err = a.a2aDo(ctx, MethodPut, "Credentials/Password", body, a2aAuth(apiKey), nil)
	return err
}

// SetPrivateKey stores privateKeyPEM as the SSH private key of the account
// identified by apiKey. privateKeyPEM is the private key in PEM form and format
// declares its encoding; an empty format selects KeyFormatOpenSSH. passphrase
// decrypts an encrypted key and may be an empty Secret for an unencrypted key.
// Like SetPassword, the account's registration must have bidirectional access
// enabled.
func (a *A2AContext) SetPrivateKey(ctx context.Context, apiKey Secret, privateKeyPEM Secret, passphrase Secret, format KeyFormat) error {
	if format == "" {
		format = KeyFormatOpenSSH
	}
	body := map[string]string{
		"Passphrase": passphrase.ExposeString(),
		"PrivateKey": privateKeyPEM.ExposeString(),
	}
	_, err := a.a2aDo(ctx, MethodPut, "Credentials/SshKey", body, a2aAuth(apiKey), url.Values{"keyFormat": {string(format)}})
	return err
}

// jsonSecretBody encodes a Secret's value as a JSON string body, the bare-string
// form the appliance's password setters expect (for example "newpass").
func jsonSecretBody(s Secret) (json.RawMessage, error) {
	b, err := json.Marshal(s.ExposeString())
	if err != nil {
		return nil, &TransportError{Op: "encode", Err: err}
	}
	return json.RawMessage(b), nil
}

// a2aDo sends a single request to the A2A service over the client-certificate
// transport with the given authorization and returns the fully read
// FullResponse.
func (a *A2AContext) a2aDo(ctx context.Context, m HTTPMethod, relURL string, body any, auth authorization, params url.Values) (FullResponse, error) {
	return a.doService(ctx, A2A, m, relURL, body, auth, params)
}

// doService sends a single request to the given service over the
// client-certificate transport with the given authorization and returns the
// fully read FullResponse. Unlike the Client Invoke path it never refreshes or
// replays: an A2A API key is static, so there is nothing to refresh, and the
// certificate identity is fixed for the context.
func (a *A2AContext) doService(ctx context.Context, service Service, m HTTPMethod, relURL string, body any, auth authorization, params url.Values) (FullResponse, error) {
	if a.closed.Load() {
		return FullResponse{}, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	base, err := service.baseURL(a.host, a.apiVersion)
	if err != nil {
		return FullResponse{}, err
	}
	reader, contentType, err := encodeBody(body)
	if err != nil {
		return FullResponse{}, err
	}
	req, err := buildHTTPRequest(ctx, m, joinURL(base, relURL, params), reader, auth, "", nil)
	if err != nil {
		return FullResponse{}, err
	}
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := a.transports.do(clientCert, req)
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

// decodeSecretString decodes a JSON string response body into a Secret. An empty
// body yields an empty Secret.
func decodeSecretString(body []byte) (Secret, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Secret{}, nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return Secret{}, &TransportError{Op: "decode", Err: err}
	}
	return NewSecretString(s), nil
}
