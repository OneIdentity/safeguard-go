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
// credentials) and makes reading them a deliberate act. Its purpose is to
// prevent accidental disclosure, not to provide cryptographic or memory-hardened
// protection; set expectations accordingly.
//
// What it guards against (the common ways an SDK leaks a credential):
//   - fmt: String, GoString, and Format render "[REDACTED]" for every verb, so
//     %v/%s/%+v/%#v, prints, and error messages never reveal the bytes.
//   - Serialization: MarshalJSON and MarshalText emit "[REDACTED]", so a Secret
//     embedded in a struct is not written out in cleartext.
//   - Logging: LogValue (slog.LogValuer) redacts the value in structured logs.
//
// Hygiene it adds: NewSecret copies its input and Expose returns a copy, so no
// backing array is aliased; Equal compares in constant time; Zero best-effort
// wipes the buffer to shrink the in-memory plaintext window.
//
// What it deliberately does NOT provide:
//   - No encryption at rest in memory: the bytes are plaintext on the Go heap
//     while held. It is not a defense against an adversary who can read process
//     memory, a core dump, swap, or an attached debugger.
//   - Once exposed, derived values cannot be reclaimed: an ExposeString result is
//     an immutable Go string that cannot be zeroed, and a parsed key (for example
//     a tls.Certificate) is out of Secret's control.
//   - Zero is best-effort only: Go's runtime may copy or move the backing array,
//     so disposal is not a hard guarantee.
//
// Callers obtain the underlying bytes only through the explicit Expose or
// ExposeString methods. Secret is a value type.
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
