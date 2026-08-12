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
	"errors"
	"testing"
	"time"
)

func TestIsTerminalSessionErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"not-authenticated", ErrNotAuthenticated, true},
		{"epoch-changed", errEpochChanged, true},
		{"closed", ErrClosed, true},
		{"wrapped-closed", &TransportError{Op: "x", Err: ErrClosed}, true},
		{"transient", &TransportError{Op: "dial", Err: errors.New("connection refused")}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isTerminalSessionErr(tc.err); got != tc.want {
				t.Fatalf("isTerminalSessionErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// terminalConn is an eventConn whose auth closure fails terminally, so connect
// returns before any network I/O. It stands in for a client that has been closed
// or has re-authenticated under a different identity.
func terminalConn() *eventConn {
	return &eventConn{
		auth: func() (authorization, error) { return authorization{}, ErrClosed },
	}
}

func TestEventListenerStateBeforeStart(t *testing.T) {
	t.Parallel()
	l := newEventListener(terminalConn())
	if l.Done() != nil {
		t.Fatal("Done() before Start = non-nil, want nil")
	}
	if l.Err() != nil {
		t.Fatalf("Err() before Start = %v, want nil", l.Err())
	}
	// Stop before Start must be a safe no-op.
	l.Stop()
}

func TestEventListenerStartSurfacesConnectError(t *testing.T) {
	t.Parallel()
	l := newEventListener(terminalConn())
	err := l.Start(context.Background())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Start = %v, want ErrClosed", err)
	}
	// A failed Start leaves the listener unstarted, so it can be retried.
	if err := l.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("second Start = %v, want ErrClosed", err)
	}
}

func TestPersistentListenerTerminalErrorStops(t *testing.T) {
	t.Parallel()
	l := newPersistentEventListener(terminalConn())
	if err := l.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// A terminal connect error must stop the reconnect loop rather than retry.
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("persistent listener did not stop on terminal error")
	}
	if !errors.Is(l.Err(), ErrClosed) {
		t.Fatalf("Err() = %v, want ErrClosed", l.Err())
	}
}

func TestPersistentListenerStartTwice(t *testing.T) {
	t.Parallel()
	// A connection that blocks lets the loop stay running while we test a second
	// Start. It never fails terminally, so Stop tears it down.
	blocked := make(chan struct{})
	conn := &eventConn{
		auth: func() (authorization, error) {
			<-blocked
			return authorization{}, errors.New("unblocked")
		},
	}
	l := newPersistentEventListener(conn)
	if err := l.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		close(blocked)
		l.Stop()
	}()

	if err := l.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

func TestPersistentListenerStopIsIdempotent(t *testing.T) {
	t.Parallel()
	l := newPersistentEventListener(terminalConn())
	if err := l.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	l.Stop()
	l.Stop() // second Stop must not panic or block
}
