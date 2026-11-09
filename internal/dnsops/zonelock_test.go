package dnsops

import (
	"context"
	"errors"
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
