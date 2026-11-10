package pdns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Note: end-to-end coalescing of concurrent cache misses (m44) is covered
// deterministically by TestCachedRead_SingleFlightCoalescesConcurrentMisses in
// cached_test.go (it routes through the real cached client + an HTTP handler
// whose latency gives every caller time to pile up behind the leader). These
// unit tests target the singleFlight type's own contracts that are awkward to
// exercise through the cached client — chiefly panic recovery, which would
// otherwise deadlock followers on an unclosed done channel.

// TestSingleFlight_CoalescesRelaxed is a non-flaky coalescing check: with the
// leader held open, concurrent callers must produce strictly fewer fn
// invocations than callers (the thundering herd is mitigated). The exact-1
// guarantee is asserted by the cached-client test cited above.
func TestSingleFlight_CoalescesRelaxed(t *testing.T) {
	const N = 50
	var g singleFlight
	var calls atomic.Int64
	release := make(chan struct{})
	firstStarted := make(chan struct{})

	fn := func() (any, error) {
		if n := calls.Add(1); n == 1 {
			close(firstStarted)
			<-release
		}
		// A straggler that forms its own short flight returns immediately.
		return "shared", nil
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			g.Do(context.Background(), "k", fn)
		}()
	}
	close(start)
	<-firstStarted
	// Hold the leader long enough for the bulk of callers to pile up, then
	// release. Some may still straggle, so we only assert meaningful
	// coalescing (calls < N), not exactly 1.
	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got >= N {
		t.Fatalf("expected coalescing to reduce fn calls below %d, got %d", N, got)
	}
}

// TestSingleFlight_DistinctKeysDoNotCoalesce confirms two different keys each
// invoke fn once (the dedup is per-key, not global).
func TestSingleFlight_DistinctKeysDoNotCoalesce(t *testing.T) {
	var g singleFlight
	var calls atomic.Int64
	fn := func() (any, error) {
		calls.Add(1)
		return nil, nil
	}

	var wg sync.WaitGroup
	for _, key := range []string{"a", "b"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			g.Do(context.Background(), key, fn)
		}(key)
	}
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 calls for 2 distinct keys, got %d", got)
	}
}

// TestSingleFlight_PanicRecovered is the deadlock-regression guard for the
// recover in Do: a panic inside fn must be surfaced as an error to the leader
// AND all followers, and the done channel must still close so followers never
// block. Without the recover, followers would deadlock on an unclosed done.
func TestSingleFlight_PanicRecovered(t *testing.T) {
	var g singleFlight
	fn := func() (any, error) { panic("boom") }

	const N = 10
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := g.Do(context.Background(), "panic-key", fn)
			errs[i] = err
		}(i)
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("followers deadlocked: panic was not recovered (done channel never closed)")
	}

	for i := 0; i < N; i++ {
		if errs[i] == nil {
			t.Errorf("caller %d got nil error, want recovered-panic error", i)
		} else if !strings.Contains(errs[i].Error(), "recovered panic") {
			t.Errorf("caller %d error = %q, want it to contain 'recovered panic'", i, errs[i].Error())
		}
	}

	// A subsequent call with the same key must run fn again (the panicked call
	// was deregistered), proving the in-flight entry was cleaned up.
	ran := false
	_, err := g.Do(context.Background(), "panic-key", func() (any, error) {
		ran = true
		return "ok", nil
	})
	if err != nil {
		t.Errorf("call after panic: unexpected err %v", err)
	}
	if !ran {
		t.Error("fn should run again after a recovered panic (entry must be deregistered)")
	}
}

// TestSingleFlight_ErrorPropagated confirms a non-panic error from fn is
// returned verbatim to every caller sharing the key.
func TestSingleFlight_ErrorPropagated(t *testing.T) {
	var g singleFlight
	sentinel := errors.New("fetch failed")
	fn := func() (any, error) { return nil, sentinel }

	const N = 5
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := g.Do(context.Background(), "err-key", fn)
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < N; i++ {
		if !errors.Is(errs[i], sentinel) {
			t.Errorf("caller %d err = %v, want %v", i, errs[i], sentinel)
		}
	}
}

// TestSingleFlight_SequentialCallsReRun confirms singleFlight is dedup-only,
// not a cache: after a call completes (entry deregistered), the next call with
// the same key runs fn again.
func TestSingleFlight_SequentialCallsReRun(t *testing.T) {
	var g singleFlight
	var calls atomic.Int64
	fn := func() (any, error) { calls.Add(1); return calls.Load(), nil }

	v1, _ := g.Do(context.Background(), "k", fn)
	v2, _ := g.Do(context.Background(), "k", fn)
	if v1.(int64) != 1 || v2.(int64) != 2 {
		t.Errorf("sequential calls must each run fn; got v1=%v v2=%v", v1, v2)
	}
}

// TestSingleFlight_FollowerCanceledBeforeWait confirms a follower whose own
// context is already canceled returns its context error immediately instead of
// queueing behind a held-open leader.
func TestSingleFlight_FollowerCanceledBeforeWait(t *testing.T) {
	var g singleFlight
	release := make(chan struct{})
	leaderStarted := make(chan struct{})
	leaderDone := make(chan struct{})
	var leaderVal any
	var leaderErr error

	leaderFn := func() (any, error) {
		close(leaderStarted)
		<-release
		return "leader-value", nil
	}

	// Leader blocks on release in the background.
	go func() {
		leaderVal, leaderErr = g.Do(context.Background(), "held", leaderFn)
		close(leaderDone)
	}()
	<-leaderStarted

	// Follower with an already-canceled context must bail out without
	// waiting for the leader.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	type result struct {
		val any
		err error
	}
	res := make(chan result, 1)
	go func() {
		val, err := g.Do(ctx, "held", leaderFn)
		res <- result{val, err}
	}()

	select {
	case r := <-res:
		if !errors.Is(r.err, context.Canceled) {
			t.Errorf("follower err = %v, want context.Canceled", r.err)
		}
		if r.val != nil {
			t.Errorf("follower val = %v, want nil", r.val)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower with canceled context still waiting on the leader")
	}

	// Release the leader; it must complete with its own value.
	close(release)
	select {
	case <-leaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not complete after release")
	}
	if leaderErr != nil {
		t.Errorf("leader err = %v, want nil", leaderErr)
	}
	if leaderVal != "leader-value" {
		t.Errorf("leader val = %v, want leader-value", leaderVal)
	}

	// A fresh call with the same key must run fn again (the leader's defer
	// deregistered the entry).
	ran := false
	v, err := g.Do(context.Background(), "held", func() (any, error) {
		ran = true
		return "fresh", nil
	})
	if err != nil {
		t.Errorf("fresh call err = %v, want nil", err)
	}
	if !ran || v != "fresh" {
		t.Errorf("fresh call must rerun fn; ran=%v v=%v", ran, v)
	}
}

// TestSingleFlight_FollowerContextCanceledMidFlight confirms a follower that
// is already queued behind a leader returns its context error promptly when
// its own context is canceled mid-flight, while the leader still completes.
func TestSingleFlight_FollowerContextCanceledMidFlight(t *testing.T) {
	var g singleFlight
	release := make(chan struct{})
	leaderStarted := make(chan struct{})
	leaderDone := make(chan struct{})
	var leaderVal any
	var leaderErr error

	leaderFn := func() (any, error) {
		close(leaderStarted)
		<-release
		return "leader-value", nil
	}

	go func() {
		leaderVal, leaderErr = g.Do(context.Background(), "held", leaderFn)
		close(leaderDone)
	}()
	<-leaderStarted

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		val any
		err error
	}
	res := make(chan result, 1)
	go func() {
		val, err := g.Do(ctx, "held", leaderFn)
		res <- result{val, err}
	}()

	// Give the follower time to actually register behind the leader.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case r := <-res:
		if !errors.Is(r.err, context.Canceled) {
			t.Errorf("follower err = %v, want context.Canceled", r.err)
		}
		if r.val != nil {
			t.Errorf("follower val = %v, want nil", r.val)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower did not return promptly after context cancellation")
	}

	// The leader must still complete with its value once released.
	close(release)
	select {
	case <-leaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not complete after release")
	}
	if leaderErr != nil {
		t.Errorf("leader err = %v, want nil", leaderErr)
	}
	if leaderVal != "leader-value" {
		t.Errorf("leader val = %v, want leader-value", leaderVal)
	}
}
