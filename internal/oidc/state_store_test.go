package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/testutil"
)

// stateHashHex mirrors the production digest computation (sha256 hex of the
// state token) so tests can look up rows without depending on where the
// implementation parks that helper after the in-memory store is removed.
func stateHashHex(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// TestConsumeState_FreshThenReplay is the L-3 regression test against the
// DB-backed store: the first consumption of a state token returns
// (fresh=true, err=nil) and an immediate second consumption of the same
// state returns (fresh=false, err=nil) — a replay, not an error.
func TestConsumeState_FreshThenReplay(t *testing.T) {
	svc := &Service{db: testutil.NewTestDB(t)}
	ctx := context.Background()

	fresh, err := svc.consumeState(ctx, "state-abc")
	if err != nil || !fresh {
		t.Fatalf("first consume = (%v, %v), want (true, nil)", fresh, err)
	}

	fresh, err = svc.consumeState(ctx, "state-abc")
	if err != nil {
		t.Fatalf("replay consume returned error %v, want nil (replay is not a failure)", err)
	}
	if fresh {
		t.Error("second consume of the same state must report fresh=false (replay rejected)")
	}

	// A different state must still be consumable.
	fresh, err = svc.consumeState(ctx, "state-xyz")
	if err != nil || !fresh {
		t.Errorf("consume of a distinct state = (%v, %v), want (true, nil)", fresh, err)
	}
}

// TestConsumeState_CrossInstanceReplay is the multi-instance proof: two
// Service instances sharing ONE database. Instance A consuming a state must
// make instance B see a replay — the property the in-process map could never
// provide. This mirrors how existing oidc tests construct Service (a struct
// literal) while keying both instances on the same *database.DB.
func TestConsumeState_CrossInstanceReplay(t *testing.T) {
	db := testutil.NewTestDB(t)
	svcA := &Service{db: db}
	svcB := &Service{db: db}
	ctx := context.Background()

	fresh, err := svcA.consumeState(ctx, "state-shared")
	if err != nil || !fresh {
		t.Fatalf("instance A first consume = (%v, %v), want (true, nil)", fresh, err)
	}

	fresh, err = svcB.consumeState(ctx, "state-shared")
	if err != nil {
		t.Fatalf("instance B replay consume returned error %v, want nil", err)
	}
	if fresh {
		t.Error("instance B must see instance A's consumption as a replay (fresh=false)")
	}

	// And B can still consume its own fresh states.
	fresh, err = svcB.consumeState(ctx, "state-b-only")
	if err != nil || !fresh {
		t.Errorf("instance B consume of its own state = (%v, %v), want (true, nil)", fresh, err)
	}
}

// TestConsumeState_ConcurrentSingleWinner fires N goroutines at the same
// state behind a start barrier: exactly one consumer may observe fresh=true,
// every other must observe a replay, and no goroutine may see an error.
// Run under -race to prove the consumption path is data-race free.
func TestConsumeState_ConcurrentSingleWinner(t *testing.T) {
	svc := &Service{db: testutil.NewTestDB(t)}
	ctx := context.Background()
	const goroutines = 32

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var freshCount int32
	var errCount int32
	var mu sync.Mutex
	var errs []error

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // barrier: all goroutines consume concurrently
			fresh, err := svc.consumeState(ctx, "state-race")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errCount++
				errs = append(errs, err)
				return
			}
			if fresh {
				freshCount++
			}
		}()
	}
	close(start)
	wg.Wait()

	if errCount != 0 {
		t.Fatalf("%d concurrent consumes returned errors (want 0): %v", errCount, errs)
	}
	if freshCount != 1 {
		t.Errorf("fresh consumes = %d, want exactly 1 (all others must be replays)", freshCount)
	}
}

// TestConsumeState_RetentionBoundary pins the retention contract:
//   - expires_at is stored as a computed UTC time equal to consumed_at + stateTTL;
//   - the opportunistic sweep removes only rows with expires_at in the past;
//   - unexpired consumed rows survive the sweep and stay replay-rejected.
func TestConsumeState_RetentionBoundary(t *testing.T) {
	db := testutil.NewTestDB(t)
	svc := &Service{db: db}
	ctx := context.Background()

	fresh, err := svc.consumeState(ctx, "state-a")
	if err != nil || !fresh {
		t.Fatalf("consume state-a = (%v, %v), want (true, nil)", fresh, err)
	}

	// expires_at must be a computed UTC instant ~ consumed_at + stateTTL.
	var consumedAt, expiresAt time.Time
	if err := db.QueryRowContext(ctx,
		`SELECT consumed_at, expires_at FROM oidc_consumed_states WHERE state_hash = ?`,
		stateHashHex("state-a"),
	).Scan(&consumedAt, &expiresAt); err != nil {
		t.Fatalf("read stored row: %v", err)
	}
	if consumedAt.Location() != time.UTC || expiresAt.Location() != time.UTC {
		t.Errorf("stored locations = %v/%v, want UTC", consumedAt.Location(), expiresAt.Location())
	}
	diff := expiresAt.Sub(consumedAt)
	if diff < stateTTL || diff > stateTTL+2*time.Second {
		t.Errorf("expires_at - consumed_at = %v, want ≈ stateTTL (%v)", diff, stateTTL)
	}

	// Plant an already-expired consumed row directly.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashHex("state-expired"), time.Now().UTC().Add(-2*stateTTL), time.Now().UTC().Add(-stateTTL),
	); err != nil {
		t.Fatalf("plant expired row: %v", err)
	}

	// A fresh consumption triggers the opportunistic sweep.
	fresh, err = svc.consumeState(ctx, "state-b")
	if err != nil || !fresh {
		t.Fatalf("consume state-b = (%v, %v), want (true, nil)", fresh, err)
	}

	var expiredLeft int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oidc_consumed_states WHERE state_hash = ?`,
		stateHashHex("state-expired"),
	).Scan(&expiredLeft); err != nil {
		t.Fatalf("count expired rows: %v", err)
	}
	if expiredLeft != 0 {
		t.Error("sweep must remove rows with expires_at in the past")
	}

	var alive int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oidc_consumed_states WHERE state_hash = ?`,
		stateHashHex("state-a"),
	).Scan(&alive); err != nil {
		t.Fatalf("count state-a rows: %v", err)
	}
	if alive != 1 {
		t.Error("unexpired consumed row must survive the sweep")
	}

	// ... and it must still be replay-rejected.
	fresh, err = svc.consumeState(ctx, "state-a")
	if err != nil || fresh {
		t.Errorf("post-sweep consume of state-a = (%v, %v), want (false, nil)", fresh, err)
	}
}

// TestConsumeState_DBFailureFailClosed verifies the fail-closed contract:
// when the INSERT fails for any reason other than a unique violation (here,
// the table was dropped), consumeState must return fresh=false with a
// non-nil error — and the error must NOT be misclassified as a replay
// (errors.Is ErrUniqueViolation), because the caller treats an error as
// fatal while a replay is merely a rejection.
func TestConsumeState_DBFailureFailClosed(t *testing.T) {
	db := testutil.NewTestDB(t)
	svc := &Service{db: db}
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `DROP TABLE oidc_consumed_states`); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	fresh, err := svc.consumeState(ctx, "state-any")
	if err == nil {
		t.Fatal("consume against a missing table must return an error (fail closed)")
	}
	if fresh {
		t.Error("consume against a missing table must report fresh=false (fail closed)")
	}
	if errors.Is(err, database.ErrUniqueViolation) {
		t.Errorf("error %v must not be ErrUniqueViolation (that would mean replay, not failure)", err)
	}
}
