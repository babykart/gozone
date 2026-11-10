package dnsops

import (
	"context"
	"hash/fnv"
	"sync"
	"time"
)

// zoneLockWaitBudget is the total time Lock spends trying to acquire the
// per-zone lock (local semaphore plus shared backend) before giving up with
// ErrZoneBusy. It is deliberately below the 15s HTTP WriteTimeout so a
// request never applies a write after the client disconnected. Unexported
// and a variable (not a constant) so tests can shorten it.
var zoneLockWaitBudget = 10 * time.Second

// zoneLockBackend is the database-side half of a per-zone lock. *database.DB
// implements it with the dialect-specific cluster-wide lock.
type zoneLockBackend interface {
	LockZone(ctx context.Context, zoneID string) (release func(), err error)
}

// ZoneLocks serializes read-modify-write record mutations per zone. The
// record write paths fetch the zone's RRSets, merge the submission into them
// and PATCH the result back; two concurrent mutations on the same RRSet can
// otherwise interleave their fetches, and the second PATCH silently drops the
// first's records.
//
// Lock first takes an in-process semaphore so goroutines of this process do
// not wait on the database unnecessarily, then takes the database-backed lock
// so every GoZone instance sharing the same MySQL or PostgreSQL database
// serializes the same fetch→merge→write sequence. SQLite keeps the no-op
// database lock: its single-connection pool already serializes one process,
// and SQLite is not a supported shared multi-instance backend.
//
// The instance lives on the Service so REST handlers, web handlers and MCP
// tools serialize against each other on the same zone; a write through one
// transport holds the same locks a write through another transport waits on.
//
// Acquisition is bounded by zoneLockWaitBudget: when the lock cannot be
// taken within that budget, Lock returns ErrZoneBusy so a contended caller
// fails fast instead of queueing behind a long critical section (and past
// the HTTP write deadline). A canceled parent context still surfaces
// ctx.Err(), which takes precedence over ErrZoneBusy.
//
// The lock state is a fixed pool of zoneLockShards one-token channels hashed
// by zone ID, so memory stays bounded regardless of how many distinct zone
// names are ever referenced — including names that turn out not to exist,
// which leave nothing behind. The trade-off is that distinct zones hashing
// to the same shard contend on one semaphore: mutual exclusion is unaffected
// (a collision only adds waiting bounded by the acquisition budget), and
// canonical zone IDs (lowercase + trailing dot) always map to the same
// shard.
type ZoneLocks struct {
	mu     sync.Mutex
	semas  [zoneLockShards]chan struct{}
	shared zoneLockBackend
}

// zoneLockShards is the size of the local semaphore pool. Power of two so
// the index is a single mask-grade modulo; large enough that distinct live
// zones rarely share a shard. The array is the whole of the lock state:
// memory is bounded at construction regardless of how many distinct zone
// names are ever touched, including names that turn out not to exist.
const zoneLockShards = 1024

// zoneLockShardIndex hashes a zone ID to its semaphore slot. FNV-1a 32 is
// deterministic across processes (tests can pin colliding pairs) and needs
// no seed: the hash only balances load between shards, it never crosses a
// security boundary.
func zoneLockShardIndex(zoneID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(zoneID)) // fnv.Write never errors; the discard is intentional.
	return h.Sum32() % zoneLockShards
}

// Lock acquires the local and shared locks for zoneID and returns one release
// function for both. The request-scoped critical section is:
//
//	release, err := locks.Lock(ctx, zoneID)
//	if err != nil { ... }
//	defer release()
//
// The acquisition context (zoneLockWaitBudget) is created once at entry and
// bounds both the local semaphore wait and the shared-backend wait. On
// ErrZoneBusy the caller should surface a retryable conflict, not retry
// internally. The local semaphore is released if the shared lock cannot be
// acquired.
func (z *ZoneLocks) Lock(ctx context.Context, zoneID string) (func(), error) {
	acqCtx, cancel := context.WithTimeout(ctx, zoneLockWaitBudget)
	defer cancel()

	releaseLocal, err := z.lockLocal(acqCtx, zoneID)
	if err != nil {
		// Same classification as the shared-backend failure below: a dead
		// parent always wins; an expired acquisition budget with a live
		// parent means contention.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrZoneBusy
	}
	released := false
	// The idempotence guard lives at the Lock level so the raw semaphore
	// drain in lockLocal's release can never be invoked twice.
	release := func() {
		if released {
			return
		}
		released = true
		releaseLocal()
	}
	if z.shared == nil {
		return release, nil
	}
	releaseShared, err := z.shared.LockZone(acqCtx, zoneID)
	if err != nil {
		release()
		// Classification order matters: a dead parent always wins (the
		// caller is gone); next, an expired acquisition budget with a live
		// parent means contention, i.e. ErrZoneBusy; anything else is a
		// genuine backend fault and is returned unchanged.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if acqCtx.Err() != nil {
			return nil, ErrZoneBusy
		}
		return nil, err
	}
	return func() {
		if released {
			return
		}
		released = true
		releaseShared()
		releaseLocal()
	}, nil
}

// semaphore returns the one-token channel for zoneID's shard, creating it on
// first use. Slot creation is the only critical section guarded by mu;
// acquisition waits on the channel outside the mutex so a contended zone
// never blocks unrelated slots from being handed out.
func (z *ZoneLocks) semaphore(zoneID string) chan struct{} {
	idx := zoneLockShardIndex(zoneID)
	z.mu.Lock()
	defer z.mu.Unlock()
	ch := z.semas[idx]
	if ch == nil {
		ch = make(chan struct{}, 1)
		z.semas[idx] = ch
	}
	return ch
}

// lockLocal acquires the in-process semaphore for zoneID, bounded by the
// caller's acquisition context. The semaphore slot is created lazily under
// mu so a zero-value ZoneLocks remains usable without a constructor.
// Acquisition and release never hold mu. The semaphore is a capacity-1
// channel so acquisition can respect context cancellation and deadline; the
// returned release func drains the token.
func (z *ZoneLocks) lockLocal(ctx context.Context, zoneID string) (func(), error) {
	ch := z.semaphore(zoneID)
	select {
	case ch <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return func() { <-ch }, nil
}
