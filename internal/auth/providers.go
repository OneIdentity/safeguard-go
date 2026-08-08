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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// provider is one entry from the Core AuthenticationProviders list.
type provider struct {
	Name              string `json:"Name"`
	RstsProviderID    string `json:"RstsProviderId"`
	RstsProviderScope string `json:"RstsProviderScope"`
}

// ResolveProviderScope maps a caller-supplied provider identifier to the RSTS
// scope string used in a grant. An empty provider yields the default scope
// (rsts:sts:primaryproviderid:<defaultProviderID>). A non-empty provider is
// matched against the appliance's authentication providers; if no provider is
// found the identifier is used to build the scope directly, matching the
// behavior of the reference SDKs.
func ResolveProviderScope(ctx context.Context, cfg Config, provider, defaultProviderID string) (string, error) {
	return resolveScope(ensureCtx(ctx), cfg, cfg.HTTPClient, provider, defaultProviderID)
}

// resolveScope implements ResolveProviderScope over an explicit transport.
func resolveScope(ctx context.Context, cfg Config, httpClient HTTPClient, providerID, defaultProviderID string) (string, error) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return scopeFor(defaultProviderID), nil
	}

	providers, err := listProviders(ctx, cfg, httpClient)
	if err != nil {
		// The reference SDKs tolerate a failed provider lookup and fall back to
		// treating the caller's identifier as the scope seed. Preserve that so a
		// locked-down appliance that hides the list can still authenticate with an
		// explicit provider id.
		return scopeFor(providerID), nil
	}
	if scope, ok := matchProvider(providers, providerID); ok {
		return scope, nil
	}
	return scopeFor(providerID), nil
}

// matchProvider selects a provider scope for id using the reference match order:
// exact RstsProviderId, then exact Name, then a substring of RstsProviderId, all
// case-insensitive.
func matchProvider(providers []provider, id string) (string, bool) {
	for _, p := range providers {
		if strings.EqualFold(p.RstsProviderID, id) {
			return p.RstsProviderScope, true
		}
	}
	for _, p := range providers {
		if strings.EqualFold(p.Name, id) {
			return p.RstsProviderScope, true
		}
	}
	lower := strings.ToLower(id)
	for _, p := range providers {
		if strings.Contains(strings.ToLower(p.RstsProviderID), lower) {
			return p.RstsProviderScope, true
		}
	}
	return "", false
}

// scopeFor builds the RSTS primary-provider scope string for a provider id.
func scopeFor(providerID string) string {
	return "rsts:sts:primaryproviderid:" + providerID
}

// listProviders fetches the anonymous AuthenticationProviders list from Core.
func listProviders(ctx context.Context, cfg Config, httpClient HTTPClient) ([]provider, error) {
	if httpClient == nil {
		return nil, errNilHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.coreURL(providersPath), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Op: "provider lookup", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, &RequestError{Op: "provider lookup", StatusCode: resp.StatusCode, Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RequestError{Op: "provider lookup", StatusCode: resp.StatusCode, body: bound(body)}
	}

	var providers []provider
	if err := json.Unmarshal(body, &providers); err != nil {
		return nil, &RequestError{Op: "provider lookup", StatusCode: resp.StatusCode, Err: fmt.Errorf("decode providers: %w", err), body: bound(body)}
	}
	return providers, nil
}
