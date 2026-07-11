package middleware

import (
	"context"
	"testing"
	"time"
)

func TestSessionPolicy_RefreshThreshold(t *testing.T) {
	tests := []struct {
		name      string
		accessTTL time.Duration
		want      time.Duration
	}{
		{"zero ttl", 0, 0},
		{"floor 30s for tiny ttl", 1 * time.Minute, 30 * time.Second},
		{"10pct for medium ttl", 10 * time.Minute, 1 * time.Minute},
		{"capped at 5min for large ttl", 2 * time.Hour, 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := SessionPolicy{AccessTTL: tt.accessTTL}
			if got := p.RefreshThreshold(); got != tt.want {
				t.Errorf("RefreshThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionTracker_TouchSeedsAndAllows(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 10 * time.Minute})
	defer tr.Close()

	ctx := context.Background()
	iat := time.Unix(1000, 0)
	t0 := time.Unix(2000, 0)
	if !tr.Touch(ctx, "s1", iat, t0) {
		t.Fatal("first Touch must allow")
	}
	if got := tr.FirstSeen(ctx, "s1", iat, t0); !got.Equal(iat) {
		t.Errorf("FirstSeen = %v, want %v", got, iat)
	}
	t1 := t0.Add(5 * time.Minute)
	if !tr.Touch(ctx, "s1", iat, t1) {
		t.Fatal("Touch within idle must allow")
	}
	// Row persisted (cluster-visible).
	if sl, found, err := db.SessionGet(ctx, "s1"); err != nil || !found {
		t.Errorf("expected persisted session row, got found=%v err=%v", found, err)
	} else if !sl.FirstSeen.Equal(iat) {
		t.Errorf("persisted first_seen = %v, want %v", sl.FirstSeen, iat)
	}
}

func TestSessionTracker_TouchIdleExceededDenies(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 10 * time.Minute})
	defer tr.Close()

	ctx := context.Background()
	iat := time.Unix(1000, 0)
	t0 := time.Unix(2000, 0)
	tr.Touch(ctx, "s1", iat, t0)
	t1 := t0.Add(11 * time.Minute)
	if tr.Touch(ctx, "s1", iat, t1) {
		t.Error("Touch after idle must deny")
	}
	// Denied cluster-wide: the row is deleted.
	if _, found, _ := db.SessionGet(ctx, "s1"); found {
		t.Error("idle-denied session row should be deleted cluster-wide")
	}
}

func TestSessionTracker_TouchIdleZeroAlwaysAllows(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 0})
	defer tr.Close()
	ctx := context.Background()
	iat := time.Unix(1000, 0)
	tr.Touch(ctx, "s1", iat, time.Unix(2000, 0))
	if !tr.Touch(ctx, "s1", iat, time.Unix(2000, 0).Add(72*time.Hour)) {
		t.Error("with Idle=0 Touch must always allow")
	}
}

func TestSessionTracker_FirstSeenSeedsOnMiss(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer tr.Close()
	ctx := context.Background()
	iat := time.Unix(5000, 0)
	now := time.Unix(6000, 0)
	if got := tr.FirstSeen(ctx, "never", iat, now); !got.Equal(iat) {
		t.Errorf("FirstSeen on miss = %v, want %v", got, iat)
	}
	if got := tr.FirstSeen(ctx, "zero", time.Time{}, now); !got.Equal(now) {
		t.Errorf("FirstSeen with zero iat = %v, want %v", got, now)
	}
}

func TestSessionTracker_RememberPreservesFirstSeen(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer tr.Close()
	ctx := context.Background()
	first := time.Unix(1000, 0)
	last := time.Unix(2000, 0)
	tr.remember(ctx, "s1", first, last)
	if got := tr.FirstSeen(ctx, "s1", time.Unix(9999, 0), last); !got.Equal(first) {
		t.Errorf("FirstSeen after remember = %v, want %v", got, first)
	}
	// Persisted so a fresh tracker sharing the DB sees the same firstSeen.
	tr2 := NewSessionTracker(db, SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer tr2.Close()
	if got := tr2.FirstSeen(ctx, "s1", time.Unix(9999, 0), last); !got.Equal(first) {
		t.Errorf("FirstSeen on second tracker = %v, want persisted %v", got, first)
	}
}

func TestSessionTracker_NilDBIsNoOp(t *testing.T) {
	tr := NewSessionTracker(nil, SessionPolicy{Idle: time.Minute})
	ctx := context.Background()
	if !tr.Touch(ctx, "s", time.Now(), time.Now()) {
		t.Error("nil-db tracker Touch must allow")
	}
	tr.FirstSeen(ctx, "s", time.Now(), time.Now()) // must not panic
	tr.remember(ctx, "s", time.Now(), time.Now())  // must not panic
	tr.Close()                                     // must not panic / block
}

func TestSessionTracker_CloseIdempotent(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: time.Minute})
	tr.Close()
	tr.Close() // must not panic or block
}

func TestSessionTracker_DistinctSessionsIndependent(t *testing.T) {
	db := newTestAuthDB(t)
	tr := NewSessionTracker(db, SessionPolicy{Idle: time.Minute})
	defer tr.Close()
	ctx := context.Background()
	iat := time.Unix(1000, 0)
	now := time.Unix(2000, 0)
	tr.Touch(ctx, "a", iat, now)
	if tr.Touch(ctx, "a", iat, now.Add(2*time.Minute)) {
		t.Error("expected idle denial for a")
	}
	if !tr.Touch(ctx, "b", iat, now) {
		t.Error("distinct session b must be allowed")
	}
}

// TestSessionTracker_SharesStateAcrossInstances is the core multi-instance
// guarantee: a fresh tracker (cold cache) reading the shared sessions table
// honours the idle window established by another instance, and a denial on one
// instance is visible to the other.
func TestSessionTracker_SharesStateAcrossInstances(t *testing.T) {
	db := newTestAuthDB(t)
	ctx := context.Background()
	idle := 10 * time.Minute

	// Simulate another instance having recorded activity 15 minutes ago — i.e.
	// already past the idle window. A fresh instance must deny.
	past := time.Now().Add(-15 * time.Minute)
	if err := db.SessionInsert(ctx, "shared", past.Add(-time.Hour), past, past.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	tr := NewSessionTracker(db, SessionPolicy{Idle: idle})
	defer tr.Close()
	if tr.Touch(ctx, "shared", past, time.Now()) {
		t.Error("fresh instance must deny a session idle on another instance")
	}

	// A fresh, recent row must be allowed.
	fresh := time.Now()
	if err := db.SessionInsert(ctx, "fresh", fresh.Add(-time.Hour), fresh, fresh.Add(time.Hour)); err != nil {
		t.Fatalf("seed fresh session: %v", err)
	}
	if !tr.Touch(ctx, "fresh", fresh.Add(-time.Hour), fresh) {
		t.Error("fresh instance must allow a recently-active session")
	}
}

// TestSessionTracker_FirstSeenSurvivesRestart proves the absolute-cap anchor is
// durable: a new tracker reading the shared DB recovers the original first_seen
// rather than re-seeding it.
func TestSessionTracker_FirstSeenSurvivesRestart(t *testing.T) {
	db := newTestAuthDB(t)
	ctx := context.Background()
	login := time.Unix(100000, 0)

	trA := NewSessionTracker(db, SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	trA.Touch(ctx, "s", login, login)
	trA.Close()

	trB := NewSessionTracker(db, SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer trB.Close()
	if got := trB.FirstSeen(ctx, "s", time.Unix(999999, 0), time.Now()); !got.Equal(login) {
		t.Errorf("first_seen after restart = %v, want persisted %v", got, login)
	}
}

// TestSessionPurgeExpired verifies the DB purge that bounds the sessions table.
func TestSessionPurgeExpired(t *testing.T) {
	db := newTestAuthDB(t)
	ctx := context.Background()
	now := time.Now()
	// One expired row, one live row.
	if err := db.SessionInsert(ctx, "old", now.Add(-2*time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SessionInsert(ctx, "live", now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := db.SessionPurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 purged row, got %d", n)
	}
	if _, found, _ := db.SessionGet(ctx, "old"); found {
		t.Error("expired row should have been purged")
	}
	if _, found, _ := db.SessionGet(ctx, "live"); !found {
		t.Error("live row should remain")
	}
}
