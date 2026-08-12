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

// Package safeguard is the One Identity Safeguard SDK for Go.
//
// It provides a Go-idiomatic client for the Safeguard for Privileged Passwords
// Web API: authentication, Invoke-style API calls, Application-to-Application
// (A2A) credential retrieval, and event listeners.
//
// # Authentication
//
// [Connect] establishes an authenticated [Client] from a [Credential]. Build a
// credential with [UsernamePassword], [Certificate], [PKCEHeadless], [Token], or
// [Anonymous]. PKCEHeadless is the recommended flow for automation because it
// does not depend on the Resource Owner Grant, which appliances commonly disable.
// Interactive browser and device-code logins live in the browser and devicecode
// subpackages so headless consumers keep a lean dependency graph. A client with
// no credential starts in an anonymous session, sufficient for the Notification
// service.
//
// # Making requests
//
// [Client.Invoke] issues a call against a [Service] and returns a [Response];
// [Client.Get], [Client.Post], [Client.Put], and [Client.Delete] are shorthands.
// [InvokeTyped] decodes a JSON response straight into a Go value. [Client.Stream],
// [Client.Download], and [Client.Upload] move large payloads without buffering.
// Per-request behavior is set with [ReqOption] values such as [WithQueryParam],
// [WithHeader], [WithAccept], and [WithRequestTimeout].
//
// # Transport and authorization
//
// A call's TLS identity and its authorization are chosen independently of the
// service: a [Service] only selects the base URL path and never implies which
// credential authorizes the request. Authorization is owned by the transport, so
// the reserved Authorization header cannot be set on a request; it is rejected
// with [ErrReservedHeader].
//
// # Secrets
//
// [Secret] holds sensitive bytes -- passwords, tokens, API keys, retrieved
// credentials -- and makes reading them a deliberate act: it redacts itself in
// fmt, JSON, and structured logs, so a credential is not disclosed by accident.
// Obtain the bytes only through [Secret.Expose] or [Secret.ExposeString].
//
// # TLS trust
//
// TLS verification is on by default. Trust a privately issued appliance
// certificate with [WithCABundle]. [WithInsecureTLS] disables verification and
// exists only for bootstrapping development appliances; it must never be used in
// production.
//
// # A2A and events
//
// [NewA2AContext] builds an [A2AContext] that retrieves credentials over the A2A
// service using a client certificate and per-account API keys, with no user
// session. [Client.NewEventListener] and [Client.NewPersistentEventListener]
// (and their A2AContext counterparts) deliver Safeguard events over a
// SignalR-over-WebSocket connection.
package safeguard
