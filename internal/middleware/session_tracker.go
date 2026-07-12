package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

// SessionPolicy describes the lifetime rules a SessionTracker enforces. A zero
// value (both durations 0) disables every check. The policy is fixed for the
// life of a tracker; it is captured by value so callers cannot mutate it after
// construction.
type SessionPolicy struct {
	// Idle bounds inactivity: a session whose last activity is older than Idle
	// is forced to re-authenticate. 0 disables the idle check.
	Idle time.Duration
	// Absolute caps the total lifetime of a session across refreshes. Once
	// exceeded (measured from the session's first sighting) the session is
	// forced to re-authenticate regardless of activity. 0 disables the absolute
	// cap. When > 0 and greater than the access-token TTL, the Auth middleware
	// transparently refreshes the access token near its expiry, effectively
	// sliding the session up to this cap.
	Absolute time.Duration
	// AccessTTL is the access-token lifetime (auth.session_duration_hours). It
	// drives the refresh threshold (a token is refreshed when less than ~10% of
	// AccessTTL remains, capped at 5 minutes).
	AccessTTL time.Duration
}

// RefreshThreshold returns the remaining-lifetime window below which an access
// token is transparently refreshed. It is 10% of the access TTL, capped at 5
// minutes and floored at 30 seconds so very short access TTLs still get a small
// window.
func (p SessionPolicy) RefreshThreshold() time.Duration {
	if p.AccessTTL <= 0 {
		return 0
	}
	th := p.AccessTTL / 10
	if th > 5*time.Minute {
		th = 5 * time.Minute
	}
	if th < 30*time.Second {
		th = 30 * time.Second
	}
	return th
}

// sessionWriteInterval bounds how often a single session's last_seen is written
// to the database, so the per-request hot path does at most one UPDATE per
// session per minute. Cross-instance idle enforcement therefore lags by at most
// this interval (acceptable given idle windows are typically tens of minutes).
const sessionWriteInterval = time.Minute

// cacheEntry is the per-session in-memory cache layered over the sessions table.
// It serves reads from memory (hot path) and coarsens writes so the DB is only
// touched ~once per sessionWriteInterval per active session.
type cacheEntry struct {
	firstSeen   time.Time
	lastSeen    time.Time
	lastWritten time.Time
}

// SessionTracker enforces idle/absolute session lifetime across instances. The
// authoritative state lives in the sessions table (shared by every GoZone
// instance); an in-memory cache serves the hot path and coarsens writes. The
// zero value (nil db) is a usable no-op tracker.
type SessionTracker struct {
	db       *database.DB
	policy   SessionPolicy
	mu       sync.Mutex
	cache    map[string]*cacheEntry
	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// NewSessionTracker returns a tracker enforcing the given policy against db. It
// starts a background goroutine that periodically evicts stale cache entries
// and purges expired session rows; the goroutine is stopped by Close. When db is
// nil the tracker is a no-op (every check passes) — used when idle/absolute are
// disabled.
func NewSessionTracker(db *database.DB, policy SessionPolicy) *SessionTracker {
	t := &SessionTracker{
		db:     db,
		policy: policy,
		cache:  make(map[string]*cacheEntry),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	if db != nil {
		go t.cleanup()
	}
	return t
}

// Touch records activity for sessionID and reports whether the session is still
// within the idle window. On the first sighting it seeds first_seen from iat and
// persists a row; on subsequent sightings it updates the in-memory last_seen and
// writes through to the DB at most once per sessionWriteInterval. Returns false
// when the session has been idle longer than policy.Idle (a forced
// re-authentication) — the row is then deleted cluster-wide.
//
// On a DB error Touch fails open (allows the request): the JWT's own expiry and
// the revocation list already bound the session, and a transient DB outage must
// not lock every user out. The error is logged.
func (t *SessionTracker) Touch(ctx context.Context, sessionID string, iat, now time.Time) bool {
	if t == nil || t.db == nil || sessionID == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.cache[sessionID]
	if !ok {
		e = t.loadOrSeedLocked(ctx, sessionID, iat, now)
		if e == nil {
			// loadOrSeed failed open and seeded a cache entry; allow.
			return true
		}
	}

	if t.policy.Idle > 0 && now.Sub(e.lastSeen) > t.policy.Idle {
		// Idle exceeded: drop cluster-wide so other instances deny too.
		delete(t.cache, sessionID)
		if err := t.db.SessionDelete(ctx, sessionID); err != nil {
			logger.Error("session tracker: delete on idle denial failed", "sid", sessionID, "error", err)
		}
		return false
	}

	e.lastSeen = now
	if now.Sub(e.lastWritten) >= sessionWriteInterval {
		updated, err := t.db.SessionTouch(ctx, sessionID, now, t.expiresAt(now))
		if err != nil {
			logger.Error("session tracker: touch write failed", "sid", sessionID, "error", err)
		} else if !updated {
			// The row is gone cluster-wide (deleted by another instance's
			// idle denial or an explicit logout). Honour that decision: drop
			// the cache entry and deny so this instance does not keep an
			// idle-expired session alive (REVIEW.md M-3).
			delete(t.cache, sessionID)
			return false
		} else {
			e.lastWritten = now
		}
	}
	return true
}

// loadOrSeedLocked handles a cache miss: it loads the row from the DB (so
// another instance's activity is visible) and caches it, or seeds+inserts a new
// row on first sighting. On DB error it seeds the cache from iat and returns nil
// (signal to the caller to fail open). The caller MUST hold t.mu.
func (t *SessionTracker) loadOrSeedLocked(ctx context.Context, sessionID string, iat, now time.Time) *cacheEntry {
	sl, found, err := t.db.SessionGet(ctx, sessionID)
	if err != nil {
		logger.Error("session tracker: get failed; failing open", "sid", sessionID, "error", err)
		first := seedTime(iat, now)
		t.cache[sessionID] = &cacheEntry{firstSeen: first, lastSeen: now, lastWritten: now}
		return nil
	}
	if !found {
		first := seedTime(iat, now)
		if err := t.db.SessionInsert(ctx, sessionID, first, now, t.expiresAt(now)); err != nil {
			logger.Error("session tracker: insert failed", "sid", sessionID, "error", err)
		}
		e := &cacheEntry{firstSeen: first, lastSeen: now, lastWritten: now}
		t.cache[sessionID] = e
		return e
	}
	// Existing row (possibly written by another instance). Seed lastWritten
	// from the DB last_seen so a stale remote value triggers a prompt write-back.
	e := &cacheEntry{firstSeen: sl.FirstSeen, lastSeen: sl.LastSeen, lastWritten: sl.LastSeen}
	t.cache[sessionID] = e
	return e
}

// FirstSeen returns the first-sighting time for sessionID (the anchor of the
// absolute cap), reading the in-memory cache and falling back to the DB, then
// iat. It never returns an error: a DB miss is seeded from iat.
func (t *SessionTracker) FirstSeen(ctx context.Context, sessionID string, iat, now time.Time) time.Time {
	if t == nil || t.db == nil {
		return seedTime(iat, now)
	}
	t.mu.Lock()
	if e, ok := t.cache[sessionID]; ok {
		t.mu.Unlock()
		return e.firstSeen
	}
	t.mu.Unlock()

	sl, found, err := t.db.SessionGet(ctx, sessionID)
	if err != nil || !found {
		return seedTime(iat, now)
	}
	return sl.FirstSeen
}

// remember records the firstSeen/lastSeen pair after a transparent token
// refresh (the SessionID is unchanged, so the absolute budget carries over). It
// updates the cache and writes through so the pair is shared across instances.
//
// The session row is seeded by Touch, which always runs before the refresh
// that triggers remember (see applySessionPolicy). remember therefore uses
// UPDATE (SessionTouch) rather than INSERT, so a row deleted by another
// instance's idle denial is not resurrected here (REVIEW.md M-3).
func (t *SessionTracker) remember(ctx context.Context, sessionID string, firstSeen, lastSeen time.Time) {
	if t == nil || t.db == nil || sessionID == "" {
		return
	}
	updated, err := t.db.SessionTouch(ctx, sessionID, lastSeen, t.expiresAt(lastSeen))
	if err != nil {
		logger.Error("session tracker: remember touch failed", "sid", sessionID, "error", err)
	}
	t.mu.Lock()
	if updated {
		t.cache[sessionID] = &cacheEntry{firstSeen: firstSeen, lastSeen: lastSeen, lastWritten: lastSeen}
	} else {
		// Row deleted cluster-wide: drop the cache so the next Touch does a
		// fresh SessionGet instead of acting on a stale local entry. Do NOT
		// re-insert — that would resurrect a session denied elsewhere.
		delete(t.cache, sessionID)
	}
	t.mu.Unlock()
}

// Close stops the background cleanup goroutine. Safe to call multiple times and
// on a no-op tracker.
func (t *SessionTracker) Close() {
	if t == nil || t.db == nil {
		return
	}
	t.stopOnce.Do(func() {
		close(t.stopCh)
		<-t.done
	})
}

// expiresAt is the hard expiry stored for purge purposes: the last activity
// plus twice the longest active window, so a row lingers long enough to evaluate
// idle/absolute after a gap but is eventually purged.
func (t *SessionTracker) expiresAt(lastSeen time.Time) time.Time {
	w := t.policy.Idle
	if t.policy.Absolute > w {
		w = t.policy.Absolute
	}
	if t.policy.AccessTTL > w {
		w = t.policy.AccessTTL
	}
	if w <= 0 {
		w = 30 * time.Minute
	}
	return lastSeen.Add(2 * w)
}

// cleanup evicts stale cache entries and purges expired DB rows every minute. It
// exits when Close is called.
func (t *SessionTracker) cleanup() {
	defer close(t.done)
	ttl := sessionPurgeTickWindow(t.policy)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// UTC: cache lastSeen values originate from UTC writes (Touch),
			// and the purge below is DB-bound (REVIEW.md M-1).
			cutoff := time.Now().UTC().Add(-ttl)
			t.mu.Lock()
			for sid, e := range t.cache {
				if e.lastSeen.Before(cutoff) {
					delete(t.cache, sid)
				}
			}
			t.mu.Unlock()
			// UTC cutoff feeds DELETE ... WHERE expires_at <= ?, matching how
			// expires_at is written by SessionTouch/SessionInsert (REVIEW.md M-1).
			if n, err := t.db.SessionPurgeExpired(context.Background(), time.Now().UTC()); err != nil {
				logger.Error("session tracker: purge expired failed", "error", err)
			} else if n > 0 {
				logger.Info("session tracker: purged expired sessions", "deleted", n)
			}
		case <-t.stopCh:
			return
		}
	}
}

// sessionPurgeTickWindow is the cache-eviction horizon (twice the longest
// active window), matching expiresAt so cache and DB agree on retention.
func sessionPurgeTickWindow(p SessionPolicy) time.Duration {
	w := p.Idle
	if p.Absolute > w {
		w = p.Absolute
	}
	if p.AccessTTL > w {
		w = p.AccessTTL
	}
	if w <= 0 {
		w = 30 * time.Minute
	}
	return 2 * w
}

// seedTime returns iat when it is a sensible past timestamp, otherwise now.
func seedTime(iat, now time.Time) time.Time {
	if iat.IsZero() || iat.After(now) {
		return now
	}
	return iat
}
