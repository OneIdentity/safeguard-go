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

import "context"

// Connect authenticates to the Safeguard appliance at host using cred and
// returns a ready client bound to a fresh session. Connection options (TLS
// trust, API version, timeouts, logger) are applied before authentication runs,
// so certificate parsing and the login exchange happen under the caller's TLS
// policy. On any failure Connect releases the client it built and returns the
// error; on success the returned client owns transports and an in-memory token
// that must be released with Close.
//
// Connect is the only way to obtain an authenticated client. Reconnecting means
// calling Connect again for a new client with a new session epoch; there is no
// in-place reconnect.
func Connect(ctx context.Context, host string, cred Credential, opts ...Option) (*Client, error) {
	if cred == nil {
		return nil, errNilCredential
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c, err := newClient(host, opts...)
	if err != nil {
		return nil, err
	}
	c.credential = cred

	sess, err := cred.establish(ctx, c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.installSession(sess)
	return c, nil
}
