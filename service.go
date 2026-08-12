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
	"fmt"
	"strings"
)

// Service identifies a Safeguard API service that a request is routed to.
//
// Authorization is never inferred from the Service or the URL; the service only
// selects the base URL path. See the package overview's "Transport and
// authorization" section for how TLS identity and authorization are chosen
// independently of the service.
type Service string

// The Safeguard API services.
const (
	// Core is the primary Safeguard for Privileged Passwords API service.
	Core Service = "core"
	// Appliance is the appliance-management API service.
	Appliance Service = "appliance"
	// Notification is the anonymous/notification API service (no token required).
	Notification Service = "notification"
	// A2A is the Application-to-Application credential-retrieval service.
	A2A Service = "a2a"
	// Event is the SignalR event service.
	Event Service = "event"
	// RSTS is the embedded secure token service; it has no version path segment.
	RSTS Service = "rsts"
	// Management is the appliance management service.
	Management Service = "management"
)

// DefaultAPIVersion is the Safeguard API version used when a caller does not
// override it. Safeguard's current default major version is v4.
const DefaultAPIVersion = "v4"

// valid reports whether s is a recognized Safeguard service.
func (s Service) valid() bool {
	switch s {
	case Core, Appliance, Notification, A2A, Event, RSTS, Management:
		return true
	default:
		return false
	}
}

// pathPrefix returns the URL path prefix for the service, without leading or
// trailing slashes. Every service except RSTS is served under
// "service/<name>/<apiVersion>"; RSTS is served under a bare "RSTS" path with no
// version segment (parity with SafeguardDotNet/PySafeguard).
func (s Service) pathPrefix(apiVersion string) (string, error) {
	if !s.valid() {
		return "", fmt.Errorf("safeguard: unknown service %q", string(s))
	}
	if s == RSTS {
		return "RSTS", nil
	}
	v := strings.Trim(apiVersion, "/")
	if v == "" {
		v = DefaultAPIVersion
	}
	return fmt.Sprintf("service/%s/%s", string(s), v), nil
}

// validateHostScheme rejects a host that carries a scheme other than https.
// Safeguard appliances are https-only, so an http:// (or any non-https) host is
// always a misconfiguration. A bare host without a scheme is accepted; https is
// assumed for it when URLs are built. The comparison is case-insensitive.
func validateHostScheme(host string) error {
	h := strings.TrimSpace(host)
	if i := strings.Index(h, "://"); i >= 0 {
		if !strings.EqualFold(h[:i], "https") {
			return errInsecureHostScheme
		}
	}
	return nil
}

// baseURL builds the absolute base URL, with a trailing slash, for the service on
// host using apiVersion. host may include an https scheme; if it does not, https
// is assumed. A non-https scheme is rejected. host must not be empty.
func (s Service) baseURL(host, apiVersion string) (string, error) {
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("safeguard: empty host")
	}
	if err := validateHostScheme(host); err != nil {
		return "", err
	}
	prefix, err := s.pathPrefix(apiVersion)
	if err != nil {
		return "", err
	}
	scheme := "https://"
	h := host
	if i := strings.Index(h, "://"); i >= 0 {
		scheme = h[:i+3]
		h = h[i+3:]
	}
	h = strings.Trim(h, "/")
	return fmt.Sprintf("%s%s/%s/", scheme, h, prefix), nil
}
