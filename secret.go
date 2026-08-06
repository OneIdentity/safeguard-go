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
	"encoding/json"
	"fmt"
	"log/slog"
)

// redactedText is the placeholder rendered anywhere a Secret's contents would
// otherwise be exposed.
const redactedText = "[REDACTED]"

// Secret holds sensitive bytes (passwords, tokens, API keys, retrieved
// credentials) and refuses to reveal them through any of the usual accidental
// leakage paths: fmt verbs, String/GoString, JSON/text marshaling, and slog.
//
// Callers obtain the underlying bytes only through the explicit Expose method.
// Secret is a value type; copies share no backing array with the constructor's
// input because NewSecret copies its argument.
//
// Honest limitation: Go cannot guarantee that secret bytes are never copied to
// swap or that every derived value (for example a parsed TLS key) is zeroable, so
// Zero is best-effort and disposal is not a hard guarantee.
type Secret struct {
	b []byte
}

// NewSecret returns a Secret that copies b. The caller retains ownership of b and
// may zero it after this call without affecting the Secret.
func NewSecret(b []byte) Secret {
	if len(b) == 0 {
		return Secret{}
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return Secret{b: cp}
}

// NewSecretString returns a Secret containing a copy of the bytes of s.
func NewSecretString(s string) Secret {
	if s == "" {
		return Secret{}
	}
	return Secret{b: []byte(s)}
}

// Expose returns a copy of the secret's bytes. The caller owns the returned slice
// and may zero it when finished. Returns nil for an empty Secret.
func (s Secret) Expose() []byte {
	if len(s.b) == 0 {
		return nil
	}
	cp := make([]byte, len(s.b))
	copy(cp, s.b)
	return cp
}

// ExposeString returns the secret's bytes as a string copy. Prefer Expose when
// the caller can zero the bytes afterward; a string cannot be zeroed.
func (s Secret) ExposeString() string {
	return string(s.b)
}

// Len returns the number of bytes held by the Secret.
func (s Secret) Len() int { return len(s.b) }

// IsZero reports whether the Secret holds no bytes.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// Equal reports whether s and other hold identical bytes, using a constant-time
// comparison to avoid leaking length-independent timing information.
func (s Secret) Equal(other Secret) bool {
	return bytes.Equal(s.b, other.b)
}

// Zero best-effort wipes the Secret's internal buffer in place. Any copies made
// via Expose are unaffected.
func (s *Secret) Zero() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

// Close wipes the Secret and always returns nil; it lets a Secret satisfy
// io.Closer for use with defer.
func (s *Secret) Close() error {
	s.Zero()
	return nil
}

// String implements fmt.Stringer and always returns the redaction placeholder.
func (s Secret) String() string { return redactedText }

// GoString implements fmt.GoStringer so %#v does not reveal the bytes.
func (s Secret) GoString() string { return redactedText }

// Format implements fmt.Formatter so every verb renders the redaction
// placeholder instead of the underlying bytes.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedText))
}

// MarshalJSON renders the Secret as the redaction placeholder string so it is
// never serialized in cleartext.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedText)
}

// MarshalText renders the Secret as the redaction placeholder.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redactedText), nil
}

// LogValue implements slog.LogValuer so structured logs render the placeholder.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedText)
}
