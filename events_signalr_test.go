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
	"encoding/json"
	"math/rand"
	"testing"
	"time"
)

func TestSplitRecords(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only-separator", "\x1e", nil},
		{"single", `{"a":1}` + "\x1e", []string{`{"a":1}`}},
		{"no-trailing-separator", `{"a":1}`, []string{`{"a":1}`}},
		{"coalesced", `{"a":1}` + "\x1e" + `{"b":2}` + "\x1e", []string{`{"a":1}`, `{"b":2}`}},
		{"coalesced-no-trailer", `{"a":1}` + "\x1e" + `{"b":2}`, []string{`{"a":1}`, `{"b":2}`}},
		{"empty-fragments-dropped", "\x1e\x1e" + `{"a":1}` + "\x1e\x1e", []string{`{"a":1}`}},
		{"whitespace-only-dropped", "  \x1e" + `{"a":1}` + "\x1e", []string{`{"a":1}`}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := splitRecords([]byte(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("splitRecords(%q) len = %d, want %d (%q)", tt.in, len(got), len(tt.want), got)
			}
			for i := range got {
				if string(got[i]) != tt.want[i] {
					t.Errorf("record %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDecodeEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		arg      string
		wantName string
		wantOK   bool
		wantData string
	}{
		{
			name:     "plain",
			arg:      `{"Name":"AssetAccountPasswordUpdated","Data":{"AssetName":"srv"}}`,
			wantName: "AssetAccountPasswordUpdated",
			wantOK:   true,
			wantData: `{"AssetName":"srv"}`,
		},
		{
			name:     "numeric-name-object-data",
			arg:      `{"Name":"12345","Data":{"EventName":"AssetAccountPasswordUpdated","AssetName":"srv"}}`,
			wantName: "AssetAccountPasswordUpdated",
			wantOK:   true,
			wantData: `{"EventName":"AssetAccountPasswordUpdated","AssetName":"srv"}`,
		},
		{
			name:     "numeric-name-string-data",
			arg:      `{"Name":"999","Data":"{\"EventName\":\"MyEvent\"}"}`,
			wantName: "MyEvent",
			wantOK:   true,
			wantData: `"{\"EventName\":\"MyEvent\"}"`,
		},
		{
			name:     "numeric-name-no-inner-name",
			arg:      `{"Name":"42","Data":{"Foo":"bar"}}`,
			wantName: "42",
			wantOK:   true,
			wantData: `{"Foo":"bar"}`,
		},
		{
			name:   "malformed",
			arg:    `not json`,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev, ok := decodeEvent([]byte(tt.arg))
			if ok != tt.wantOK {
				t.Fatalf("decodeEvent ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ev.name != tt.wantName {
				t.Errorf("name = %q, want %q", ev.name, tt.wantName)
			}
			if tt.wantData != "" && string(ev.data) != tt.wantData {
				t.Errorf("data = %q, want %q", ev.data, tt.wantData)
			}
		})
	}
}

func TestEventRegistryDispatchCaseInsensitive(t *testing.T) {
	t.Parallel()
	reg := newEventRegistry(nil)
	var got []string
	reg.register("AssetAccountPasswordUpdated", func(name string, _ json.RawMessage) {
		got = append(got, name)
	})
	// Registered mixed-case, dispatched lowercase: still matches.
	reg.dispatch(decodedEvent{name: "assetaccountpasswordupdated", data: []byte(`{}`)})
	reg.dispatch(decodedEvent{name: "Unrelated", data: []byte(`{}`)})
	if len(got) != 1 || got[0] != "assetaccountpasswordupdated" {
		t.Fatalf("dispatch delivered %v, want one case-insensitive match", got)
	}
}

func TestEventRegistryDispatchMultipleHandlers(t *testing.T) {
	t.Parallel()
	reg := newEventRegistry(nil)
	calls := 0
	reg.register("E", func(string, json.RawMessage) { calls++ })
	reg.register("E", func(string, json.RawMessage) { calls++ })
	reg.dispatch(decodedEvent{name: "E", data: []byte(`{}`)})
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestEventRegistryDispatchRecoversPanic(t *testing.T) {
	t.Parallel()
	reg := newEventRegistry(nil)
	second := false
	reg.register("E", func(string, json.RawMessage) { panic("boom") })
	reg.register("E", func(string, json.RawMessage) { second = true })
	// Must not panic, and the second handler still runs.
	reg.dispatch(decodedEvent{name: "E", data: []byte(`{}`)})
	if !second {
		t.Fatal("second handler did not run after first panicked")
	}
}

func TestReconnectBackoff(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // G404 -- deterministic jitter for a test, not security sensitive.
	for attempt := 0; attempt < 12; attempt++ {
		d := reconnectBackoff(attempt, rng)
		if d <= 0 {
			t.Fatalf("attempt %d: backoff = %v, want > 0", attempt, d)
		}
		// Cap is 60s + 25% jitter.
		if d > 75*time.Second {
			t.Fatalf("attempt %d: backoff = %v, exceeds jittered cap", attempt, d)
		}
	}
}

func FuzzSplitRecords(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\x1e"))
	f.Add([]byte(`{"a":1}` + "\x1e"))
	f.Add([]byte(`{"a":1}` + "\x1e" + `{"b":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got := splitRecords(data)
		for _, rec := range got {
			if len(rec) == 0 {
				t.Fatalf("splitRecords returned an empty record for %q", data)
			}
			for _, b := range rec {
				if b == recordSeparator {
					t.Fatalf("record still contains the separator: %q", rec)
				}
			}
		}
	})
}

func FuzzDecodeEvent(f *testing.F) {
	f.Add([]byte(`{"Name":"X","Data":{}}`))
	f.Add([]byte(`{"Name":"1","Data":{"EventName":"Y"}}`))
	f.Add([]byte(`{"Name":"1","Data":"{\"EventName\":\"Y\"}"}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(_ *testing.T, arg []byte) {
		// Must never panic regardless of input.
		ev, ok := decodeEvent(arg)
		if ok && ev.name == "" {
			// An ok decode with an empty name is acceptable only when the source
			// had an empty name; just ensure no panic occurred (reached here).
			_ = ev
		}
	})
}
