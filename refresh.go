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
	"io"
	"net/http"
	"sync"
	"time"
)

// refreshTimeout bounds a single token refresh. The refresh runs on its own
// deadline rather than a caller's request context, so one caller cancelling can
// never fail the shared refresh for everyone else.
const refreshTimeout = 60 * time.Second

// refreshCoordinator serializes token refreshes so that concurrent callers that
// all observe the same stale token trigger exactly one network re-authentication
// (single flight). Waiters join the in-flight refresh instead of starting their
// own.
type refreshCoordinator struct {
	mu       sync.Mutex
	inflight *refreshOp
}

// refreshOp is one in-flight refresh that waiters can join. done is closed when
// the refresh completes; err holds its outcome and is read only after done is
// closed.
type refreshOp struct {
	done chan struct{}
	err  error
}

// refreshOnce performs a single-flight refresh for the token generation the
// caller observed. If a refresh is already running it joins that one; if the
// token has already advanced past the observed generation (someone else
// refreshed, or the epoch changed) it returns nil without re-authenticating. The
// caller's context only governs how long this caller waits, never the shared
// refresh itself.
func (c *Client) refreshOnce(reqCtx context.Context, observedEpoch, observedGen uint64) error {
	c.refresh.mu.Lock()
	if op := c.refresh.inflight; op != nil {
		c.refresh.mu.Unlock()
		select {
		case <-op.done:
			return op.err
		case <-reqCtx.Done():
			return reqCtx.Err()
		}
	}

	cur := c.token.Load()
	if cur == nil || cur.epoch != observedEpoch || cur.generation != observedGen {
		// The session was superseded (another refresh, a logout, or a close) or
		// already advanced. Nothing for this caller to do.
		c.refresh.mu.Unlock()
		return nil
	}

	op := &refreshOp{done: make(chan struct{})}
	c.refresh.inflight = op
	c.refresh.mu.Unlock()

	err := c.doRefresh(observedEpoch, observedGen)

	op.err = err
	c.refresh.mu.Lock()
	c.refresh.inflight = nil
	c.refresh.mu.Unlock()
	close(op.done)

	if reqCtx.Err() != nil {
		return reqCtx.Err()
	}
	return err
}

// doRefresh re-runs the credential's login on an independent, deadline-bound
// context and publishes the new token via a compare-and-swap on the observed
// (epoch, generation). A refresh whose epoch or generation was superseded before
// publication is discarded so a late refresh can never resurrect or clobber a
// newer session.
func (c *Client) doRefresh(observedEpoch, observedGen uint64) error {
	if c.credential == nil {
		return ErrNotRefreshable
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	sess, err := c.credential.establish(ctx, c)
	if err != nil {
		return err
	}

	for {
		prev := c.token.Load()
		if prev == nil || prev.epoch != observedEpoch || prev.generation != observedGen {
			// Superseded before we could publish; drop the freshly minted token.
			sess.token.Zero()
			return nil
		}
		next := &tokenState{
			epoch:       prev.epoch,
			generation:  prev.generation + 1,
			token:       sess.token,
			anonymous:   sess.anonymous,
			refreshable: sess.refreshable,
		}
		if c.token.CompareAndSwap(prev, next) {
			// The displaced token (prev.token) is not zeroed here: a concurrent
			// request may still be reading its bytes to build an Authorization
			// header, and zeroing an aliased backing array underneath a reader is
			// a data race. The superseded token is released to the garbage
			// collector instead. (Secret documents that zeroing is best-effort and
			// provides no in-memory hardening, so this does not weaken any
			// guarantee.)
			return nil
		}
	}
}

// replayAction is how send should react to a 401 for a request whose body is
// replayable.
type replayAction int

const (
	// replayNone surfaces the 401 to the caller without retrying.
	replayNone replayAction = iota
	// replayWithoutRefresh replays once with the current token because another
	// caller already refreshed past the generation this request used.
	replayWithoutRefresh
	// replayAfterRefresh refreshes the token (single flight) and then replays
	// once.
	replayAfterRefresh
)

// classify401 decides how to handle a 401 given the (epoch, generation) the
// request was sent under. A changed epoch or an anonymous/non-refreshable session
// surfaces the 401; an older generation replays with the newer token; the current
// refreshable generation triggers a refresh-then-replay.
func (c *Client) classify401(observedEpoch, observedGen uint64) replayAction {
	cur := c.token.Load()
	if cur == nil || cur.epoch != observedEpoch || cur.anonymous || cur.token.IsZero() {
		return replayNone
	}
	if cur.generation != observedGen {
		return replayWithoutRefresh
	}
	if !cur.refreshable {
		return replayNone
	}
	return replayAfterRefresh
}

// send issues a request built by newReq on the transport for id and applies the
// bounded 401-replay policy. When replayable is true and the appliance returns
// 401, send may refresh the token (single flight) and replay the request exactly
// once with a freshly built request that carries the current token. A request
// whose body cannot be rebuilt (an unbuffered io.Reader) is never replayed. At
// most one network replay ever happens, so a genuine authorization failure
// surfaces instead of looping.
func (c *Client) send(ctx context.Context, id tlsIdentity, newReq func() (*http.Request, error), replayable bool) (*http.Response, error) {
	ts := c.token.Load()
	var observedEpoch, observedGen uint64
	if ts != nil {
		observedEpoch, observedGen = ts.epoch, ts.generation
	}

	req, err := newReq()
	if err != nil {
		return nil, err
	}
	resp, err := c.transports.do(id, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || !replayable {
		return resp, nil
	}

	action := c.classify401(observedEpoch, observedGen)
	if action == replayNone {
		return resp, nil
	}

	// Drain and close the 401 body before replaying so the connection can be
	// reused and nothing leaks.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxStoredErrorBody))
	_ = resp.Body.Close()

	if action == replayAfterRefresh {
		if err := c.refreshOnce(ctx, observedEpoch, observedGen); err != nil {
			return nil, err
		}
	}

	req2, err := newReq()
	if err != nil {
		return nil, err
	}
	return c.transports.do(id, req2)
}

// bodyReplayable reports whether an Invoke/Stream body argument can be rebuilt
// for a 401 replay. Buffered forms (nil, string, []byte, json.RawMessage, and
// marshaled values) can be re-encoded; a caller-supplied io.Reader is consumed on
// first send and cannot be replayed.
func bodyReplayable(body any) bool {
	if _, ok := body.(io.Reader); ok {
		return false
	}
	return true
}
