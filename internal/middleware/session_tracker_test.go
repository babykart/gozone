package middleware

import (
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
	tr := NewSessionTracker(SessionPolicy{Idle: 10 * time.Minute})
	defer tr.Close()

	iat := time.Unix(1000, 0)
	t0 := time.Unix(2000, 0)
	if !tr.Touch("s1", iat, t0) {
		t.Fatal("first Touch must allow")
	}
	// firstSeen seeded from iat; within idle window.
	if got := tr.FirstSeen("s1", iat, t0); !got.Equal(iat) {
		t.Errorf("FirstSeen = %v, want %v", got, iat)
	}
	// Activity well within idle keeps it alive.
	t1 := t0.Add(5 * time.Minute)
	if !tr.Touch("s1", iat, t1) {
		t.Fatal("Touch within idle must allow")
	}
}

func TestSessionTracker_TouchIdleExceededDenies(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: 10 * time.Minute})
	defer tr.Close()

	iat := time.Unix(1000, 0)
	t0 := time.Unix(2000, 0)
	tr.Touch("s1", iat, t0)
	// 11 minutes later → idle exceeded.
	t1 := t0.Add(11 * time.Minute)
	if tr.Touch("s1", iat, t1) {
		t.Error("Touch after idle must deny")
	}
	// Denied entry is dropped so a subsequent request re-seeds from iat.
	if got := tr.FirstSeen("s1", iat, t1); !got.Equal(iat) {
		t.Errorf("after denial FirstSeen should re-seed from iat, got %v", got)
	}
}

func TestSessionTracker_TouchIdleZeroAlwaysAllows(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: 0}) // idle disabled
	defer tr.Close()
	iat := time.Unix(1000, 0)
	tr.Touch("s1", iat, time.Unix(2000, 0))
	// Even far in the future, idle=0 never denies.
	if !tr.Touch("s1", iat, time.Unix(2000, 0).Add(72*time.Hour)) {
		t.Error("with Idle=0 Touch must always allow")
	}
}

func TestSessionTracker_FirstSeenSeedsOnMiss(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer tr.Close()
	iat := time.Unix(5000, 0)
	now := time.Unix(6000, 0)
	// Never touched → FirstSeen seeds from iat.
	if got := tr.FirstSeen("never", iat, now); !got.Equal(iat) {
		t.Errorf("FirstSeen on miss = %v, want %v", got, iat)
	}
	// Zero iat → seeds from now.
	if got := tr.FirstSeen("zero", time.Time{}, now); !got.Equal(now) {
		t.Errorf("FirstSeen with zero iat = %v, want %v", got, now)
	}
}

func TestSessionTracker_RememberPreservesFirstSeen(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: time.Minute, Absolute: time.Hour})
	defer tr.Close()
	first := time.Unix(1000, 0)
	last := time.Unix(2000, 0)
	tr.remember("s1", first, last)
	if got := tr.FirstSeen("s1", time.Unix(9999, 0), last); !got.Equal(first) {
		t.Errorf("FirstSeen after remember = %v, want %v", got, first)
	}
}

func TestSessionTracker_NilTrackerNoOp(t *testing.T) {
	var tr *SessionTracker
	if !tr.Touch("s", time.Now(), time.Now()) {
		t.Error("nil tracker Touch must allow")
	}
	tr.FirstSeen("s", time.Now(), time.Now()) // must not panic
	tr.remember("s", time.Now(), time.Now())  // must not panic
	tr.Close()                                // must not panic
}

func TestSessionTracker_CloseIdempotent(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: time.Minute})
	tr.Close()
	tr.Close() // second Close must not panic
}

func TestSessionTracker_TouchKeysBySessionID(t *testing.T) {
	tr := NewSessionTracker(SessionPolicy{Idle: time.Minute})
	defer tr.Close()
	iat := time.Unix(1000, 0)
	now := time.Unix(2000, 0)
	// Two distinct session IDs are independent.
	tr.Touch("a", iat, now)
	if tr.Touch("a", iat, now.Add(2*time.Minute)) {
		// "a" is now idle > 1m → deny
		t.Error("expected idle denial for a")
	}
	// "b" never touched → allow.
	if !tr.Touch("b", iat, now) {
		t.Error("distinct session b must be allowed")
	}
}
