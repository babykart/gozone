package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
)

// issueTokenWithSID builds a session token carrying a known SessionID and
// expiring expIn from now, so policy tests can place the token precisely
// relative to the refresh threshold and the absolute cap.
func issueTokenWithSID(t *testing.T, user *models.User, sid string, expIn time.Duration) string {
	t.Helper()
	tok, err := RefreshSessionToken(user, testSecret, expIn, "", sid)
	if err != nil {
		t.Fatalf("RefreshSessionToken: %v", err)
	}
	return tok
}

// runPolicy wraps AuthWithPolicy around a trivial 200 handler, feeds it a
// request carrying the given session cookie value, and returns the recorder.
func runPolicy(t *testing.T, db *database.DB, tracker *SessionTracker, accessTTL time.Duration, cookieValue, path string) *httptest.ResponseRecorder {
	t.Helper()
	mw := AuthWithPolicy(db, testSecret, tracker, accessTTL)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: cookieValue})
	}
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAuthWithPolicy_NilTrackerAllowsValidToken(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "poluser", "user", true)
	tok, err := GenerateToken(&models.User{ID: uid, Username: "poluser", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	rec := runPolicy(t, db, nil, 0, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Errorf("nil tracker (default) must allow a valid token: got %d", rec.Code)
	}
}

func TestAuthWithPolicy_IdleExpiryForcesReauth(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "idleuser", "user", true)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 1 * time.Minute})
	defer tr.Close()
	sid := "sid-idle"
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "idleuser", Role: "user"}, sid, time.Hour)

	// Seed the shared session row so the tracker sees the session as idle:
	// lastSeen 2 minutes ago, beyond the 1-minute idle window. Seeding via
	// SessionInsert (not remember, which is UPDATE-only post M-3) matches how
	// another instance would have persisted the activity.
	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-2*time.Minute), now.Add(-2*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for idle session, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == constants.SessionCookieName && c.Value != "" {
			t.Error("idle session cookie should be cleared")
		}
	}
}

func TestAuthWithPolicy_AbsoluteCapForcesReauth(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "absuser", "user", true)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 0, Absolute: 30 * time.Minute, AccessTTL: time.Hour})
	defer tr.Close()
	sid := "sid-abs"
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "absuser", Role: "user"}, sid, time.Hour)

	// Session first seen 31 minutes ago → beyond the 30-minute absolute cap.
	// Seed via SessionInsert (remember is UPDATE-only post M-3).
	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-31*time.Minute), now, now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for absolute-capped session, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestAuthWithPolicy_RefreshReissuesNearExpiry(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "refreshuser", "user", true)
	accessTTL := time.Hour // refresh threshold = 5 min (10% capped)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 0, Absolute: 2 * time.Hour, AccessTTL: accessTTL})
	defer tr.Close()
	sid := "sid-refresh"
	// Token expires in 1 minute → within the 5-minute threshold → refresh.
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "refreshuser", Role: "user"}, sid, time.Minute)
	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-5*time.Minute), now, now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, accessTTL, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (refresh keeps the session alive), got %d", rec.Code)
	}
	var newCookie string
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			newCookie = c.Value
			found = true
		}
	}
	if !found || newCookie == "" || newCookie == tok {
		t.Error("expected a refreshed session cookie distinct from the original")
	}
	// The old jti was revoked.
	claims, err := ParseToken(tok, testSecret)
	if err != nil {
		t.Fatalf("parse original token: %v", err)
	}
	revoked, err := db.IsTokenRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected the old jti to be revoked after refresh")
	}
	// The refreshed token keeps the SessionID and gets a fresh expiry.
	newClaims, err := ParseToken(newCookie, testSecret)
	if err != nil {
		t.Fatalf("parse refreshed token: %v", err)
	}
	if newClaims.SessionID != sid {
		t.Errorf("refreshed token SessionID = %q, want %q", newClaims.SessionID, sid)
	}
	if !newClaims.ExpiresAt.Time.After(time.Now().Add(50 * time.Minute)) {
		t.Error("refreshed token should have a fresh ~1h expiry")
	}
}

func TestAuthWithPolicy_NoRefreshWhenNotNearExpiry(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "freshuser", "user", true)
	accessTTL := time.Hour
	tr := NewSessionTracker(db, SessionPolicy{Idle: 0, Absolute: 2 * time.Hour, AccessTTL: accessTTL})
	defer tr.Close()
	sid := "sid-fresh"
	// 50 min of life left (> 5 min threshold) → no refresh.
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "freshuser", Role: "user"}, sid, 50*time.Minute)
	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-5*time.Minute), now, now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, accessTTL, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == constants.SessionCookieName && c.Value != "" && c.Value != tok {
			t.Error("token should not be refreshed when not near expiry")
		}
	}
}
