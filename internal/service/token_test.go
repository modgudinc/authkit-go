// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

// drainLastUsedSlots blocks until every in-flight runBoundedLastUsedUpdate goroutine
// has released its slot (by acquiring all of them), then frees them so the package-
// global semaphore is left empty for the next test. Acquiring all slots is a barrier:
// it can only succeed once no background goroutine holds one.
func drainLastUsedSlots(t *testing.T) {
	t.Helper()
	for i := 0; i < maxConcurrentLastUsedUpdates; i++ {
		select {
		case lastUsedUpdateSlots <- struct{}{}:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out acquiring last_used slot %d/%d (a background update never released)", i+1, maxConcurrentLastUsedUpdates)
		}
	}
	for i := 0; i < maxConcurrentLastUsedUpdates; i++ {
		<-lastUsedUpdateSlots
	}
}

func TestRunBoundedLastUsedUpdateRunsFn(t *testing.T) {
	done := make(chan struct{})
	runBoundedLastUsedUpdate(context.Background(), nil, "test", func(context.Context) error {
		close(done)
		return nil
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fn was not invoked")
	}
	drainLastUsedSlots(t)
}

// TestRunBoundedLastUsedUpdateConcurrent drives the bounded fan-out from many
// goroutines at once so the unit job's -race covers the shared semaphore and the
// detached-goroutine lifecycle (the only concurrency primitive in non-test source).
func TestRunBoundedLastUsedUpdateConcurrent(t *testing.T) {
	var ran int64
	var launched sync.WaitGroup
	const callers = 256

	launched.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer launched.Done()
			runBoundedLastUsedUpdate(context.Background(), nil, "concurrent", func(context.Context) error {
				atomic.AddInt64(&ran, 1)
				return nil
			})
		}()
	}
	launched.Wait()       // every call returned; spawned background goroutines may still be running
	drainLastUsedSlots(t) // barrier: wait for all spawned goroutines to finish

	if atomic.LoadInt64(&ran) == 0 {
		t.Fatal("expected at least some last_used updates to run")
	}
	// Some calls are deliberately skipped when the cap is saturated — that is the
	// point of the bound, so we assert "> 0", not "== callers".
	t.Logf("%d/%d updates ran; the rest were skipped by the %d-slot cap", atomic.LoadInt64(&ran), callers, maxConcurrentLastUsedUpdates)
}

func TestRunBoundedLastUsedUpdateSkipsWhenFull(t *testing.T) {
	// Occupy every slot so the next call must take the skip path.
	for i := 0; i < maxConcurrentLastUsedUpdates; i++ {
		lastUsedUpdateSlots <- struct{}{}
	}
	called := make(chan struct{}, 1)
	runBoundedLastUsedUpdate(context.Background(), nil, "full", func(context.Context) error {
		called <- struct{}{}
		return nil
	})
	select {
	case <-called:
		t.Fatal("fn must be skipped when all slots are occupied")
	case <-time.After(150 * time.Millisecond):
		// expected: skipped without blocking
	}
	for i := 0; i < maxConcurrentLastUsedUpdates; i++ {
		<-lastUsedUpdateSlots
	}
}

func TestRunBoundedLastUsedUpdateRecoversPanic(t *testing.T) {
	// A panicking fn must be recovered (never crash the host) and must still release
	// its slot — otherwise the drain barrier below would time out.
	runBoundedLastUsedUpdate(context.Background(), nil, "panic", func(context.Context) error {
		panic("boom")
	})
	drainLastUsedSlots(t)
}

func TestIsUserLocked(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		user model.User
		want bool
	}{
		{"not locked", model.User{IsLocked: false}, false},
		{"locked indefinitely", model.User{IsLocked: true, LockedUntil: nil}, true},
		{"locked until future", model.User{IsLocked: true, LockedUntil: &future}, true},
		{"lock window elapsed", model.User{IsLocked: true, LockedUntil: &past}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := c.user
			if got := isUserLocked(&u); got != c.want {
				t.Fatalf("isUserLocked = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTokenServiceHashToken(t *testing.T) {
	s := &TokenService{refreshTokenHMACSecret: "unit-test-refresh-hmac-0123456789abcdef0123"} //nolint:gosec // G101 false positive: fixed test secret

	h := s.hashToken("a-refresh-token")
	if h != s.hashToken("a-refresh-token") {
		t.Fatal("hashToken must be deterministic for the same input")
	}
	if len(h) != 64 { // HMAC-SHA256 -> 32 bytes -> 64 hex chars
		t.Fatalf("expected 64-char hex hash, got %d", len(h))
	}
	if s.hashToken("a-different-token") == h {
		t.Fatal("distinct inputs must hash differently")
	}
	other := &TokenService{refreshTokenHMACSecret: "unit-test-refresh-hmac-ffffffffffffffffffff"} //nolint:gosec // G101 false positive: fixed test secret
	if other.hashToken("a-refresh-token") == h {
		t.Fatal("a different HMAC secret must produce a different hash (keyed)")
	}
}
