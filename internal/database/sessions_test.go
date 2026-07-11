package database

import (
	"context"
	"testing"
	"time"
)

func TestSessionsCRUD(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	first := time.Unix(1000, 0)
	last := time.Unix(2000, 0)
	exp := last.Add(time.Hour)

	// Initially absent.
	if _, found, err := db.SessionGet(ctx, "s1"); err != nil || found {
		t.Fatalf("expected absent session, got found=%v err=%v", found, err)
	}

	// Insert.
	if err := db.SessionInsert(ctx, "s1", first, last, exp); err != nil {
		t.Fatalf("insert: %v", err)
	}
	sl, found, err := db.SessionGet(ctx, "s1")
	if err != nil || !found {
		t.Fatalf("get after insert: found=%v err=%v", found, err)
	}
	if !sl.FirstSeen.Equal(first) || !sl.LastSeen.Equal(last) {
		t.Errorf("get = firstSeen %v lastSeen %v, want %v %v", sl.FirstSeen, sl.LastSeen, first, last)
	}

	// InsertIgnore preserves the earliest first_seen.
	later := time.Unix(5000, 0)
	if err := db.SessionInsert(ctx, "s1", later, later, exp); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	sl, _, _ = db.SessionGet(ctx, "s1")
	if !sl.FirstSeen.Equal(first) {
		t.Errorf("first_seen overwritten to %v, want preserved %v", sl.FirstSeen, first)
	}

	// Touch updates last_seen without touching first_seen, and reports that the
	// row matched (updated=true).
	touched := time.Unix(3000, 0)
	updated, err := db.SessionTouch(ctx, "s1", touched, exp)
	if err != nil {
		t.Fatalf("touch: %v", err)
	}
	if !updated {
		t.Error("SessionTouch on an existing row must report updated=true")
	}
	sl, _, _ = db.SessionGet(ctx, "s1")
	if !sl.LastSeen.Equal(touched) || !sl.FirstSeen.Equal(first) {
		t.Errorf("after touch = firstSeen %v lastSeen %v, want %v %v", sl.FirstSeen, sl.LastSeen, first, touched)
	}

	// Touch on a missing row reports updated=false (no resurrection) — the
	// behaviour SessionTracker relies on to detect a cluster-wide deletion
	// (REVIEW.md M-3).
	if u, err := db.SessionTouch(ctx, "ghost", touched, exp); err != nil || u {
		t.Errorf("SessionTouch on missing row = (updated=%v, err=%v), want (false, nil)", u, err)
	}

	// Delete.
	if err := db.SessionDelete(ctx, "s1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := db.SessionGet(ctx, "s1"); found {
		t.Error("session should be deleted")
	}
}
