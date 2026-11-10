package database

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSSOIDTokensCRUD(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	hint := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhLiJ9.sig"

	// Initially absent.
	if got, err := db.FindSSOIDToken(ctx, "s1"); err != nil || got != "" {
		t.Fatalf("expected absent hint, got %q err=%v", got, err)
	}

	// Store.
	exp1 := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if err := db.UpsertSSOIDToken(ctx, "s1", hint, exp1); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := db.FindSSOIDToken(ctx, "s1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got != hint {
		t.Errorf("find = %q, want stored hint", got)
	}

	// Upsert replaces a stale row for the same sid (fresh login reusing the
	// key must not keep the old token). Replace-semantics guard: both the
	// token AND the expiry must come from the second call — a "DO NOTHING"
	// style upsert would keep the old expiry while leaving the token
	// unchanged and slip past a token-only assertion.
	hint2 := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiLiJ9.sig2"
	exp2 := time.Date(2026, 11, 11, 14, 0, 0, 0, time.UTC)
	if err := db.UpsertSSOIDToken(ctx, "s1", hint2, exp2); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if got, _ := db.FindSSOIDToken(ctx, "s1"); got != hint2 {
		t.Errorf("re-upsert did not replace: got %q", got)
	}
	var storedExp time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT expires_at FROM sso_id_tokens WHERE session_id = 's1'",
	).Scan(&storedExp); err != nil {
		t.Fatalf("select expires_after re-upsert: %v", err)
	}
	if !storedExp.Equal(exp2) {
		t.Errorf("re-upsert must replace expires_at too: got %v, want %v", storedExp, exp2)
	}

	// Delete removes the row; a second delete is a no-op.
	if err := db.DeleteSSOIDToken(ctx, "s1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := db.FindSSOIDToken(ctx, "s1"); got != "" {
		t.Errorf("hint must be gone after delete, got %q", got)
	}
	if err := db.DeleteSSOIDToken(ctx, "s1"); err != nil {
		t.Errorf("delete of a missing row must not error: %v", err)
	}
}

func TestSSOIDTokensPurgeExpired(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// UTC, matching the production caller and the stored (normalized) wall
	// time: a local-zone cutoff compares against UTC walls lexicographically
	// and purges live rows.
	now := time.Now().UTC()

	if err := db.UpsertSSOIDToken(ctx, "stale", "tok-old", now.Add(-time.Minute)); err != nil {
		t.Fatalf("upsert stale: %v", err)
	}
	if err := db.UpsertSSOIDToken(ctx, "fresh", "tok-new", now.Add(time.Hour)); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	n, err := db.PurgeExpiredSSOIDTokens(ctx, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge deleted %d rows, want 1", n)
	}
	if got, _ := db.FindSSOIDToken(ctx, "stale"); got != "" {
		t.Error("expired hint must have been purged")
	}
	if got, _ := db.FindSSOIDToken(ctx, "fresh"); got != "tok-new" {
		t.Error("unexpired hint must survive the purge")
	}
}

// TestUpsertSSOIDToken_NormalizesExpiryToUTC pins the UTC normalization of
// expires_at: a local-zone wall time in the naive column would skew the
// purge cutoff by the zone offset and drop a still-live logout hint.
func TestUpsertSSOIDToken_NormalizesExpiryToUTC(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	zone := time.FixedZone("local-offset", 2*60*60) // UTC+2
	local := time.Date(2026, 10, 3, 12, 0, 0, 0, zone)
	if err := db.UpsertSSOIDToken(ctx, "utc", "tok", local); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var stored time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT expires_at FROM sso_id_tokens WHERE session_id = 'utc'",
	).Scan(&stored); err != nil {
		t.Fatalf("select expires_at: %v", err)
	}
	want := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	if !stored.Equal(want) {
		t.Errorf("stored expires_at = %v, want the UTC instant %v", stored, want)
	}
	if stored.Location() != time.UTC {
		t.Errorf("stored expires_at location = %v, want UTC (naive columns must hold UTC wall time)", stored.Location())
	}
}

// TestSSOIDTokenUpsertSQL pins the exact native upsert statement per dialect:
// a single atomic INSERT ... ON CONFLICT / ON DUPLICATE KEY UPDATE must back
// UpsertSSOIDToken so concurrent writers never interleave a DELETE+INSERT
// pair into a unique-violation window.
func TestSSOIDTokenUpsertSQL(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"sqlite",
			"INSERT INTO sso_id_tokens (session_id, id_token, expires_at) VALUES (?, ?, ?) " +
				"ON CONFLICT (session_id) DO UPDATE SET id_token = excluded.id_token, expires_at = excluded.expires_at"},
		{"mysql",
			"INSERT INTO sso_id_tokens (session_id, id_token, expires_at) VALUES (?, ?, ?) " +
				"ON DUPLICATE KEY UPDATE id_token = VALUES(id_token), expires_at = VALUES(expires_at)"},
		{"postgres",
			"INSERT INTO sso_id_tokens (session_id, id_token, expires_at) VALUES (?, ?, ?) " +
				"ON CONFLICT (session_id) DO UPDATE SET id_token = EXCLUDED.id_token, expires_at = EXCLUDED.expires_at"},
	}
	queries := map[string]string{
		"sqlite":   (&sqliteDialect{}).SSOIDTokenUpsert(),
		"mysql":    (&mysqlDialect{}).SSOIDTokenUpsert(),
		"postgres": (&postgresDialect{}).SSOIDTokenUpsert(),
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := queries[c.name]; got != c.query {
				t.Errorf("SSOIDTokenUpsert =\n%s\nwant:\n%s", got, c.query)
			}
		})
	}
}

// TestUpsertSSOIDToken_ConcurrentSameSession exercises the upsert from N
// goroutines racing on the same session_id with distinct (id_token,
// expires_at) pairs. The final row must be exactly one and its pair must be
// coherent (belong to exactly one writer), and no call may return an error.
//
// On SQLite this is a serialization smoke test (the single-connection pool
// serializes writers anyway); the unique-violation regression it guards —
// the old DELETE+INSERT pair letting a second transaction's INSERT land on a
// row whose DELETE has not committed yet — only manifests on the network
// dialects exercised by the dbmatrix CI jobs (PostgreSQL surfaces it as a
// 23505 unique violation, MySQL as a duplicate-key error).
func TestUpsertSSOIDToken_ConcurrentSameSession(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	const n = 8
	type pair struct {
		token string
		exp   time.Time
	}
	pairs := make([]pair, n)
	for i := range pairs {
		pairs[i] = pair{
			token: fmt.Sprintf("race-token-%d", i),
			exp:   time.Date(2026, 11, 11, 12, 0, i, 0, time.UTC),
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range pairs {
		wg.Add(1)
		go func(p pair) {
			defer wg.Done()
			<-start
			errs <- db.UpsertSSOIDToken(ctx, "race-sid", p.token, p.exp)
		}(pairs[i])
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent upsert returned error: %v", err)
		}
	}

	var count int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sso_id_tokens WHERE session_id = 'race-sid'",
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one row for race-sid, got %d", count)
	}

	var gotToken string
	var gotExp time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT id_token, expires_at FROM sso_id_tokens WHERE session_id = 'race-sid'",
	).Scan(&gotToken, &gotExp); err != nil {
		t.Fatalf("select winner row: %v", err)
	}
	coherent := false
	for _, p := range pairs {
		if p.token == gotToken && p.exp.Equal(gotExp) {
			coherent = true
			break
		}
	}
	if !coherent {
		t.Errorf("stored pair (%q, %v) matches no single writer's (id_token, expires_at) pair", gotToken, gotExp)
	}
}
