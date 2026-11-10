package dnsops

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/models"
)

// fakeZoneLockBackend is an in-memory implementation of the shared-lock
// contract used to exercise ZoneLocks without a live MySQL/PostgreSQL server.
type fakeZoneLockBackend struct {
	mu   sync.Mutex
	held map[string]bool
	err  error
}

func newFakeZoneLockBackend() *fakeZoneLockBackend {
	return &fakeZoneLockBackend{held: make(map[string]bool)}
}

func (f *fakeZoneLockBackend) LockZone(ctx context.Context, zoneID string) (func(), error) {
	if f.err != nil {
		return nil, f.err
	}
	for {
		f.mu.Lock()
		if !f.held[zoneID] {
			f.held[zoneID] = true
			f.mu.Unlock()
			break
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		f.mu.Lock()
		delete(f.held, zoneID)
		f.mu.Unlock()
	}, nil
}

// TestZoneLocksSharedBackendSerializesIndependentLockers is the cross-instance
// contract at the locker level: two ZoneLocks values with independent local
// mutexes must still exclude each other when they share the same backend.
func TestZoneLocksSharedBackendSerializesIndependentLockers(t *testing.T) {
	backend := newFakeZoneLockBackend()
	a := &ZoneLocks{shared: backend}
	b := &ZoneLocks{shared: backend}
	ctx := context.Background()

	releaseA, err := a.Lock(ctx, "example.com.")
	if err != nil {
		t.Fatalf("Lock A: %v", err)
	}
	entered := make(chan struct{})
	go func() {
		releaseB, err := b.Lock(ctx, "example.com.")
		if err != nil {
			t.Errorf("Lock B: %v", err)
			close(entered)
			return
		}
		releaseB()
		close(entered)
	}()

	select {
	case <-entered:
		t.Fatal("independent lockers sharing a backend must exclude each other")
	case <-time.After(20 * time.Millisecond):
	}
	releaseA()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second locker did not enter after the first release")
	}
}

// TestZoneLocksSharedBackendFailureReleasesLocal verifies that a failed
// shared-lock acquisition does not leak this process's local semaphore and
// is not misclassified as contention.
func TestZoneLocksSharedBackendFailureReleasesLocal(t *testing.T) {
	lockErr := errors.New("shared lock unavailable")
	backend := newFakeZoneLockBackend()
	backend.err = lockErr
	z := &ZoneLocks{shared: backend}
	ctx := context.Background()

	if _, err := z.Lock(ctx, "example.com."); !errors.Is(err, lockErr) {
		t.Fatalf("Lock error = %v, want %v", err, lockErr)
	}
	if _, err := z.Lock(ctx, "example.com."); errors.Is(err, ErrZoneBusy) {
		t.Fatalf("plain backend error misclassified as ErrZoneBusy: %v", err)
	}
	backend.err = nil
	release, err := z.Lock(ctx, "example.com.")
	if err != nil {
		t.Fatalf("local lock remained held after shared-lock failure: %v", err)
	}
	release()
}

// TestServiceLockFailureUsesLockStage verifies that lock acquisition failures
// are distinguishable from PowerDNS fetch and PATCH failures.
func TestServiceLockFailureUsesLockStage(t *testing.T) {
	lockErr := errors.New("shared lock unavailable")
	s := New(nil, nil)
	s.locks.shared = &fakeZoneLockBackend{err: lockErr}

	err := s.CreateRecord(context.Background(), nil, "example.com.",
		models.RRSet{Name: "www.example.com.", Type: "A", TTL: 3600}, SourceAPI)
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageLock {
		t.Fatalf("CreateRecord error = %v, want StageError(StageLock)", err)
	}
}

// shortenZoneLockWaitBudget installs a small acquisition budget for the
// duration of one test and restores the original value on cleanup. The
// budget is package-global state: never call t.Parallel in a test that
// uses this helper.
func shortenZoneLockWaitBudget(t *testing.T, d time.Duration) {
	t.Helper()
	orig := zoneLockWaitBudget
	zoneLockWaitBudget = d
	t.Cleanup(func() { zoneLockWaitBudget = orig })
}

// TestZoneLocksLockBusyTimeout verifies that a second Lock on an already
// held zone fails with ErrZoneBusy once the acquisition budget elapses,
// instead of blocking forever, and that the local semaphore is not leaked
// by the failure.
func TestZoneLocksLockBusyTimeout(t *testing.T) {
	shortenZoneLockWaitBudget(t, 50*time.Millisecond)
	z := &ZoneLocks{} // zero value: local semaphore only, shared == nil
	ctx := context.Background()

	release, err := z.Lock(ctx, "z.example.")
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	type lockResult struct {
		release func()
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		r, err := z.Lock(ctx, "z.example.")
		result <- lockResult{release: r, err: err}
	}()

	select {
	case lr := <-result:
		if lr.err == nil {
			t.Fatal("second Lock on held zone succeeded, want ErrZoneBusy")
		}
		if !errors.Is(lr.err, ErrZoneBusy) {
			t.Fatalf("second Lock error = %v, want ErrZoneBusy", lr.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Lock blocked past the acquisition budget instead of returning ErrZoneBusy")
	}

	release()
	released = true
	releaseFresh, err := z.Lock(ctx, "z.example.")
	if err != nil {
		t.Fatalf("Lock after busy failure did not succeed (leaked semaphore token?): %v", err)
	}
	releaseFresh()
}

// TestZoneLocksLockParentCancel verifies that a canceled parent context
// surfaces context.Canceled — not ErrZoneBusy — even when the zone is
// already held.
func TestZoneLocksLockParentCancel(t *testing.T) {
	shortenZoneLockWaitBudget(t, 50*time.Millisecond)
	z := &ZoneLocks{}
	ctx := context.Background()

	release, err := z.Lock(ctx, "z.example.")
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	defer release()

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	type lockResult struct {
		release func()
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		r, err := z.Lock(canceledCtx, "z.example.")
		result <- lockResult{release: r, err: err}
	}()

	select {
	case lr := <-result:
		if lr.release != nil {
			lr.release()
		}
		if !errors.Is(lr.err, context.Canceled) {
			t.Fatalf("Lock with canceled parent error = %v, want context.Canceled", lr.err)
		}
		if errors.Is(lr.err, ErrZoneBusy) {
			t.Fatalf("Lock with canceled parent returned ErrZoneBusy: %v", lr.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock with canceled parent context blocked instead of returning promptly")
	}
}

// ctxBlockingZoneLockBackend blocks its first LockZone call until the
// passed context is done (then returns ctx.Err(), like a database advisory
// lock whose acquisition deadline expired) and succeeds on every
// subsequent call. When entered is non-nil it is closed when the first
// call starts blocking, so a test can synchronize on backend entry.
type ctxBlockingZoneLockBackend struct {
	entered chan struct{}
	calls   int
}

func (f *ctxBlockingZoneLockBackend) LockZone(ctx context.Context, _ string) (func(), error) {
	f.calls++
	if f.calls == 1 {
		if f.entered != nil {
			close(f.entered)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return func() {}, nil
}

// TestZoneLocksSharedDeadlineBecomesBusy verifies that an acquisition
// deadline expiring inside the shared backend is classified as
// ErrZoneBusy (not the raw context error) and that the local semaphore is
// released on that failure path. The parent carries a cancel backstop so a
// pre-change implementation that blocks forever fails at 5s instead of
// hanging the test binary.
func TestZoneLocksSharedDeadlineBecomesBusy(t *testing.T) {
	shortenZoneLockWaitBudget(t, 50*time.Millisecond)
	backend := &ctxBlockingZoneLockBackend{}
	z := &ZoneLocks{shared: backend}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	type lockResult struct {
		release func()
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		r, err := z.Lock(parent, "z.example.")
		result <- lockResult{release: r, err: err}
	}()

	select {
	case lr := <-result:
		if lr.release != nil {
			lr.release()
		}
		if !errors.Is(lr.err, ErrZoneBusy) {
			t.Fatalf("Lock error = %v, want ErrZoneBusy", lr.err)
		}
		if errors.Is(lr.err, context.DeadlineExceeded) {
			t.Fatalf("Lock leaked the raw deadline error instead of ErrZoneBusy: %v", lr.err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Lock with a blocking shared backend did not return after the acquisition budget")
	}

	release, err := z.Lock(parent, "z.example.")
	if err != nil {
		t.Fatalf("Lock after shared busy failure did not succeed (leaked semaphore token?): %v", err)
	}
	release()
}

// TestZoneLocksSharedParentCancel verifies that a parent cancellation with a
// live shared backend surfaces context.Canceled (not ErrZoneBusy) and
// releases the local semaphore.
func TestZoneLocksSharedParentCancel(t *testing.T) {
	backend := &ctxBlockingZoneLockBackend{entered: make(chan struct{})}
	z := &ZoneLocks{shared: backend}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	type lockResult struct {
		release func()
		err     error
	}
	result := make(chan lockResult, 1)
	go func() {
		r, err := z.Lock(parent, "z.example.")
		result <- lockResult{release: r, err: err}
	}()

	select {
	case <-backend.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("shared backend was never entered")
	}
	cancel()

	select {
	case lr := <-result:
		if lr.release != nil {
			lr.release()
		}
		if !errors.Is(lr.err, context.Canceled) {
			t.Fatalf("Lock error after parent cancel = %v, want context.Canceled", lr.err)
		}
		if errors.Is(lr.err, ErrZoneBusy) {
			t.Fatalf("parent cancellation misclassified as ErrZoneBusy: %v", lr.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock did not return promptly after parent cancellation")
	}

	// Reacquire with a FRESH context: the canceled parent must not taint the
	// semaphore.
	release, err := z.Lock(context.Background(), "z.example.")
	if err != nil {
		t.Fatalf("Lock after parent-cancel failure did not succeed (leaked semaphore token?): %v", err)
	}
	release()
}

// TestZoneLocksCollidingZonesSerializeLocally pins the hashed-pool contract:
// the zone names below collide on the same semaphore shard (FNV-1a 32 %
// 1024 = 78 for both, verified against zoneLockShardIndex below), so a Lock
// on one must exclude a Lock on the other even though they are distinct
// names. With a per-zone map the two acquire concurrently and this test
// fails. Timing tolerances are generous and all shared state is
// mutex-protected, so the test is race-detector safe.
func TestZoneLocksCollidingZonesSerializeLocally(t *testing.T) {
	z := &ZoneLocks{} // zero value: local semaphore only, shared == nil
	ctx := context.Background()
	const zoneA = "collision-18.example.com."
	const zoneB = "collision-164.example.com."

	if zoneLockShardIndex(zoneA) != zoneLockShardIndex(zoneB) {
		t.Fatalf("test premise broken: %s and %s no longer collide on a shard",
			zoneA, zoneB)
	}

	// Main goroutine holds zoneA's lock for the whole observation window.
	releaseA, err := z.Lock(ctx, zoneA)
	if err != nil {
		t.Fatalf("Lock %s: %v", zoneA, err)
	}

	var mu sync.Mutex
	aReleased := false
	overlap := false
	bEntered := make(chan struct{})

	go func() {
		defer close(bEntered)
		releaseB, err := z.Lock(ctx, zoneB)
		if err != nil {
			t.Errorf("Lock %s: %v", zoneB, err)
			return
		}
		defer releaseB()
		mu.Lock()
		if !aReleased {
			// Entered while zoneA was still held: same-shard zones ran
			// their critical sections concurrently.
			overlap = true
		}
		mu.Unlock()
		// Hold the lock briefly so a would-be overlap is observable.
		time.Sleep(50 * time.Millisecond)
	}()

	// Generous window in which a broken implementation lets B slip in
	// while A is still held.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	aReleased = true
	mu.Unlock()
	releaseA()

	select {
	case <-bEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("lock on colliding zone did not enter within 2s of the release")
	}

	mu.Lock()
	gotOverlap := overlap
	mu.Unlock()
	if gotOverlap {
		t.Fatal("zones hashing to the same shard acquired the local semaphore concurrently")
	}
}

// TestZoneLocksShardIndexStableAndBounded pins the properties the rest of
// the suite relies on: zoneLockShardIndex is deterministic across calls,
// spreads a handful of known names (no universal inequality is asserted —
// collisions are legitimate), and always lands inside the pool bounds.
func TestZoneLocksShardIndexStableAndBounded(t *testing.T) {
	if got := zoneLockShardIndex("example.com."); got != zoneLockShardIndex("example.com.") {
		t.Fatalf("zoneLockShardIndex not deterministic: %d vs %d",
			got, zoneLockShardIndex("example.com."))
	}

	if zoneLockShardIndex("collision-18.example.com.") == zoneLockShardIndex("example.com.") {
		t.Fatal("zoneLockShardIndex unexpectedly maps the collision pair and a plain name to one shard")
	}

	for _, name := range []string{
		"example.com.",
		"test.example.org.",
		"a.b.c.example.net.",
		"",
	} {
		if got := zoneLockShardIndex(name); got >= zoneLockShards {
			t.Fatalf("zoneLockShardIndex(%q) = %d, want < %d", name, got, zoneLockShards)
		}
	}
}

// TestZoneLocksDistinctZonesAcquireConcurrently is the regression guard for
// the hashed pool: 32 distinct names held simultaneously must all acquire
// without ErrZoneBusy. With only colliding shards contending, simultaneous
// acquisition proves the pool introduced no false exclusion. The derived
// names are deterministic; if they ever map to fewer than 8 distinct shards
// the concurrency assertion loses meaning and the test skips.
func TestZoneLocksDistinctZonesAcquireConcurrently(t *testing.T) {
	shortenZoneLockWaitBudget(t, 3*time.Second) // never call t.Parallel here
	z := &ZoneLocks{}                           // zero value: local semaphore only
	ctx := context.Background()

	// Derive 32 names on 32 distinct shards so simultaneous holding cannot
	// deadlock through a shard collision. The scan is deterministic (FNV-1a
	// is fixed), so the derived set is stable across runs. The skip check
	// below is kept as a guard against a future change to the pool making
	// the derivation degenerate.
	names := make([]string, 0, 32)
	seen := make(map[uint32]bool, 32)
	for i := 0; len(names) < 32 && i < 100000; i++ {
		name := fmt.Sprintf("pool-distinct-%d.example.", i)
		idx := zoneLockShardIndex(name)
		if seen[idx] {
			continue
		}
		seen[idx] = true
		names = append(names, name)
	}
	if len(names) < 32 {
		t.Skipf("could not derive 32 distinct-shard names (got %d)", len(names))
	}
	if len(seen) < 8 {
		t.Skipf("derived names map to only %d distinct shards; concurrency assertion not meaningful",
			len(seen))
	}

	start := make(chan struct{})
	releaseAll := make(chan struct{})
	var acquired sync.WaitGroup // counts goroutines past a successful Lock
	acquired.Add(len(names))
	var wg sync.WaitGroup
	errs := make([]error, len(names))
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			<-start
			release, err := z.Lock(ctx, name)
			if err != nil {
				errs[i] = fmt.Errorf("Lock %s: %w", name, err)
				acquired.Done()
				return
			}
			acquired.Done()
			// Hold the lock until every goroutine is in, then release.
			<-releaseAll
			release()
		}(i, name)
	}

	close(start)
	allIn := make(chan struct{})
	go func() {
		acquired.Wait()
		close(allIn)
	}()

	select {
	case <-allIn:
		// All 32 distinct-shard locks are held simultaneously: the pool
		// added no false exclusion beyond colliding shards.
	case <-time.After(5 * time.Second):
		t.Fatal("32 distinct zones did not all acquire within the budget")
	}
	close(releaseAll)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("goroutines did not release after the barrier opened")
	}

	for _, err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, ErrZoneBusy) {
			t.Fatalf("distinct zone misclassified as contended: %v", err)
		}
		t.Fatal(err)
	}
}
