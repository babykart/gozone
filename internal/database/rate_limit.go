package database

import (
	"context"
	"time"
)

// HitRateLimit increments the fixed-window counter for (key, windowStart) and
// reports whether the resulting hit count is still within limit.
//
// It backs the cluster-wide login rate limiting: because the counter lives in
// the shared database, every instance of a multi-replica deployment draws from
// the same budget, so the effective ceiling no longer scales with the instance
// count (the in-process RateLimiter remains in front as a cheap pre-DB gate).
// windowStart must already be aligned to the window width by the caller (the
// middleware truncates to the minute); timestamps are stored UTC per project
// convention.
//
// The increment is a single dialect-specific upsert (see
// Dialect.RateLimitHitUpsert): it takes the row's exclusive lock directly, so
// concurrent hits serialize on one statement with no insert-then-update lock
// dance. On PostgreSQL and SQLite the upsert itself RETURNS the resulting
// count; MySQL has no RETURNING, so a follow-up SELECT in the same
// transaction reads this call's own write.
//
// Key material is a rate-limit bucket key (IP, username or masked API key),
// never a secret.
func (db *DB) HitRateLimit(ctx context.Context, key string, windowStart time.Time, limit int) (bool, error) {
	upsert, returnsCount := db.dialect.RateLimitHitUpsert()
	if returnsCount {
		var hits int
		if err := db.QueryRowContext(ctx, db.dialect.Rebind(upsert),
			key, windowStart.UTC(),
		).Scan(&hits); err != nil {
			return false, err
		}
		return hits <= limit, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() // #nosec G104 -- no-op after Commit

	if _, err := tx.ExecContext(ctx, db.dialect.Rebind(upsert),
		key, windowStart.UTC(),
	); err != nil {
		return false, err
	}
	var hits int
	if err := tx.QueryRowContext(ctx,
		`SELECT hits FROM rate_limit_counters WHERE bucket_key = ? AND window_start = ?`,
		key, windowStart.UTC(),
	).Scan(&hits); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return hits <= limit, nil
}

// PurgeRateLimitCounters deletes counter rows for windows that started before
// olderThan and returns the number of deleted rows. Called by the hourly
// background job; windows are one minute wide, so anything a few minutes old
// can never be incremented again.
func (db *DB) PurgeRateLimitCounters(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM rate_limit_counters WHERE window_start < ?`,
		olderThan.UTC(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
