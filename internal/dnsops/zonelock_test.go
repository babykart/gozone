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
// shared-lock acquisition does not leak this process's local mutex.
func TestZoneLocksSharedBackendFailureReleasesLocal(t *testing.T) {
	lockErr := errors.New("shared lock unavailable")
	backend := newFakeZoneLockBackend()
	backend.err = lockErr
	z := &ZoneLocks{shared: backend}
	ctx := context.Background()

	if _, err := z.Lock(ctx, "example.com."); !errors.Is(err, lockErr) {
		t.Fatalf("Lock error = %v, want %v", err, lockErr)
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
