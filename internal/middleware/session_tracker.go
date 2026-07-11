package middleware

import (
	"sync"
	"time"
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

// sessionEntry is the per-session bookkeeping kept in memory by the tracker.
type sessionEntry struct {
	// firstSeen is the earliest observed activity for the session, seeded from
	// the token's issued-at on first sighting so the absolute budget survives
	// a tracker eviction / process restart (within the token's own lifetime).
	firstSeen time.Time
	// lastSeen is updated on every observed activity; drives the idle check.
	lastSeen time.Time
}

// SessionTracker keeps in-memory idle/absolute bookkeeping for live sessions,
// keyed by the stable Claims.SessionID (not the rotating jti). It is
// single-instance, consistent with the in-memory rate limiters: a SQLite
// deployment runs one process, and a restart resets idle windows (acceptable
// for an ops event). The zero value is a usable no-op tracker.
type SessionTracker struct {
	policy   SessionPolicy
	mu       sync.Mutex
	live     map[string]sessionEntry
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewSessionTracker returns a tracker enforcing the given policy and starts a
// background goroutine that periodically evicts idle entries so the map does
// not grow without bound. The goroutine is stopped by Close.
func NewSessionTracker(policy SessionPolicy) *SessionTracker {
	t := &SessionTracker{
		policy: policy,
		live:   make(map[string]sessionEntry),
		stopCh: make(chan struct{}),
	}
	go t.cleanup()
	return t
}

// Touch records activity for sessionID and reports whether the session is still
// within the idle window. On the first sighting of a session, firstSeen and
// lastSeen are seeded from iat (so the absolute budget reflects real login
// time, surviving eviction/restart). Returns false when the session has been
// idle longer than policy.Idle (a forced re-authentication).
func (t *SessionTracker) Touch(sessionID string, iat, now time.Time) bool {
	if t == nil || sessionID == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.live[sessionID]
	if !ok {
		// Seed from the token iat: a session that survived a restart keeps its
		// absolute budget (lastSeen resets to "now" so idle does not fire
		// immediately after restart).
		first := iat
		if first.IsZero() || first.After(now) {
			first = now
		}
		e = sessionEntry{firstSeen: first, lastSeen: now}
		t.live[sessionID] = e
		return true
	}
	if t.policy.Idle > 0 && now.Sub(e.lastSeen) > t.policy.Idle {
		// Stale: drop the entry so a later request re-seeds from the token iat.
		delete(t.live, sessionID)
		return false
	}
	e.lastSeen = now
	t.live[sessionID] = e
	return true
}

// FirstSeen returns the first-sighting time for sessionID, seeded from iat when
// the session is not currently tracked (evicted/restart). Used by the Auth
// middleware to evaluate the absolute cap and to decide whether to refresh.
func (t *SessionTracker) FirstSeen(sessionID string, iat, now time.Time) time.Time {
	if t == nil {
		if iat.IsZero() {
			return now
		}
		return iat
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.live[sessionID]; ok {
		return e.firstSeen
	}
	first := iat
	if first.IsZero() || first.After(now) {
		first = now
	}
	return first
}

// remember stores the firstSeen/lastSeen pair for sessionID. Used by the
// refresh path to carry over the absolute budget to the (unchanged) SessionID
// after a token rotation — no-op for a nil tracker.
func (t *SessionTracker) remember(sessionID string, firstSeen, lastSeen time.Time) {
	if t == nil || sessionID == "" {
		return
	}
	t.mu.Lock()
	t.live[sessionID] = sessionEntry{firstSeen: firstSeen, lastSeen: lastSeen}
	t.mu.Unlock()
}

// Close stops the background cleanup goroutine. Safe to call multiple times
// (mirrors RateLimiter.Close).
func (t *SessionTracker) Close() {
	if t == nil {
		return
	}
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
}

// cleanup evicts entries whose lastSeen is older than twice the longest active
// window, bounding memory while keeping enough history to evaluate idle after a
// brief gap. Runs every minute; exits when Close is called.
func (t *SessionTracker) cleanup() {
	ttl := t.policy.Idle
	if t.policy.Absolute > ttl {
		ttl = t.policy.Absolute
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	ttl *= 2
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-ttl)
			t.mu.Lock()
			for sid, e := range t.live {
				if e.lastSeen.Before(cutoff) {
					delete(t.live, sid)
				}
			}
			t.mu.Unlock()
		case <-t.stopCh:
			return
		}
	}
}
