package middleware

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
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
	mw := AuthWithPolicy(db, testSecret, tracker, accessTTL, 0)
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
	// SessionInsert (not remember, which is UPDATE-only) matches how
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
	// Seed via SessionInsert (remember is UPDATE-only).
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

// TestAuthWithPolicy_IdleDenialRevokesReplayedToken is the replay regression:
// an idle-timeout denial must revoke the JWT, not just clear the cookie and
// delete the session row. Replaying the same still-unexpired token used to
// re-seed a fresh session (lastSeen = now) and pass — a stolen cookie then
// survived up to the token's exp after a single login redirect.
func TestAuthWithPolicy_IdleDenialRevokesReplayedToken(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "replayidle", "user", true)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 1 * time.Minute})
	defer tr.Close()
	sid := "sid-replay-idle"
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "replayidle", Role: "user"}, sid, time.Hour)

	// Row idle since 2 minutes (beyond the 1-minute window).
	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-2*time.Minute), now.Add(-2*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for idle session, got %d", rec.Code)
	}

	// The denied token's jti must be recorded in the revocation list…
	claims, err := ParseToken(tok, testSecret)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	revoked, err := db.IsTokenRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("idle denial must revoke the denied token's jti so it cannot be replayed")
	}

	// …so replaying the same cookie is rejected before any session logic.
	rec = runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("replayed token after idle denial must be rejected, got %d", rec.Code)
	}
}

// TestAuthWithPolicy_AbsoluteDenialRevokesReplayedToken mirrors the idle
// replay regression for the absolute cap: the denied token must land in the
// revocation list, so a replay cannot outlive the cap up to its exp.
func TestAuthWithPolicy_AbsoluteDenialRevokesReplayedToken(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "replayabs", "user", true)
	tr := NewSessionTracker(db, SessionPolicy{Idle: 0, Absolute: 30 * time.Minute, AccessTTL: time.Hour})
	defer tr.Close()
	sid := "sid-replay-abs"
	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "replayabs", Role: "user"}, sid, time.Hour)

	now := time.Now()
	if err := db.SessionInsert(context.Background(), sid, now.Add(-31*time.Minute), now, now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	rec := runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for absolute-capped session, got %d", rec.Code)
	}

	claims, err := ParseToken(tok, testSecret)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	revoked, err := db.IsTokenRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("absolute-cap denial must revoke the denied token's jti so it cannot be replayed")
	}

	rec = runPolicy(t, db, tr, time.Hour, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("replayed token after absolute-cap denial must be rejected, got %d", rec.Code)
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

// --- Transient users-read fault injection ---------------------------------
//
// flakySQLiteDriver wraps the in-memory SQLite driver so tests can fail
// every SELECT touching the users table on demand — a transient DB outage
// hitting exactly loadUser (IsTokenRevoked queries revoked_tokens, so the
// middleware gets past the revocation check before the fault fires). It
// backs TestAuth_TransientUserLoadErrorKeepsCookie in auth_test.go via
// database.NewWithOpener, the test-instrumentation seam.

// flakyUsersFault arms the users-table read fault. Package-level (not
// per-connection) because the SQLite pool is a single connection and the
// flag is only set around one ServeHTTP call per test.
var flakyUsersFault atomic.Bool

func init() {
	sql.Register("gozone_test_flaky_sqlite3", flakySQLiteDriver{})
}

type flakySQLiteDriver struct{}

func (flakySQLiteDriver) Open(dsn string) (driver.Conn, error) {
	c, err := (&sqlite3.SQLiteDriver{}).Open(dsn)
	if err != nil {
		return nil, err
	}
	return &flakySQLiteConn{Conn: c}, nil
}

type flakySQLiteConn struct {
	driver.Conn
}

func (c *flakySQLiteConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if flakyUsersFault.Load() && strings.Contains(query, "FROM users") {
		return nil, errors.New("fault injected: transient users read failure")
	}
	qc, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return qc.QueryContext(ctx, query, args)
}

func armUsersReadFault()    { flakyUsersFault.Store(true) }
func disarmUsersReadFault() { flakyUsersFault.Store(false) }

func newFlakyAuthDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewWithOpener(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}, func(_, dsn string) (*sql.DB, error) {
		return sql.Open("gozone_test_flaky_sqlite3", dsn)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// --- Password expiry via the session middleware ---------------------------
//
// The tests below exercise AuthWithPolicy's password.max_age_days
// enforcement for web sessions: an aged LOCAL password flips
// users.must_change_password in the DB, after which the existing
// force-change gate redirects every non-allowed path to /change-password;
// fresh passwords and a zero policy pass through; and an SSO-established
// session is exempt (the user authenticates against the IdP, so the local
// password age is irrelevant — forcing its change would deadlock them).
// There is no users.auth_provider column: SSO-ness of a session is carried
// carried by the JWT auth_provider claim (claims.AuthProvider), exactly as
// the existing force-change gate (auth.go isSSOSession) determines it. The
// aged-SSO case below mints its token with GenerateSessionToken(provider
// "keycloak").
func runPolicyWithPasswordMaxAge(t *testing.T, db *database.DB, tracker *SessionTracker, accessTTL time.Duration, maxAgeDays int, cookieValue, path string) *httptest.ResponseRecorder {
	t.Helper()
	mw := AuthWithPolicy(db, testSecret, tracker, accessTTL, maxAgeDays)
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

func backdatePasswordChangedAt(t *testing.T, db *database.DB, userID int64, age time.Duration) {
	t.Helper()
	if _, err := db.Exec("UPDATE users SET password_changed_at = ? WHERE id = ?",
		time.Now().Add(-age).UTC(), userID); err != nil {
		t.Fatalf("backdate password_changed_at: %v", err)
	}
}

func mustChangeFlag(t *testing.T, db *database.DB, userID int64) int {
	t.Helper()
	var v int
	if err := db.QueryRow("SELECT must_change_password FROM users WHERE id = ?", userID).Scan(&v); err != nil {
		t.Fatalf("read must_change_password: %v", err)
	}
	return v
}

// TestAuthWithPolicy_PasswordExpiryForcesChange pins the enforcement: a local
// session whose password aged past password.max_age_days must be redirected
// to /change-password and the flag persisted so later requests short-circuit
// on the loaded row.
func TestAuthWithPolicy_PasswordExpiryForcesChange(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "agedlocal", "user", true)
	backdatePasswordChangedAt(t, db, uid, 48*time.Hour)

	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "agedlocal", Role: "user"}, "sid-aged-local", time.Hour)

	rec := runPolicyWithPasswordMaxAge(t, db, nil, 0, 1, tok, "/dashboard")
	if rec.Code != http.StatusSeeOther || !strings.HasSuffix(rec.Header().Get("Location"), "/change-password") {
		t.Fatalf("aged local session with maxAgeDays=1 must redirect to /change-password: got %d %q",
			rec.Code, rec.Header().Get("Location"))
	}
	if v := mustChangeFlag(t, db, uid); v != 1 {
		t.Error("middleware must persist must_change_password=1 for the expired local password")
	}
}

// TestAuthWithPolicy_FreshPasswordPassesPolicy is the control: a password
// changed well inside the policy window authenticates normally and does not
// flip the flag.
func TestAuthWithPolicy_FreshPasswordPassesPolicy(t *testing.T) {
	db := newTestAuthDB(t)
	// seedTestUser inserts password_changed_at explicitly (now, UTC), so
	// this control starts inside the policy window.
	uid := seedTestUser(t, db, "freshpw", "user", true)

	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "freshpw", Role: "user"}, "sid-fresh-pw", time.Hour)

	rec := runPolicyWithPasswordMaxAge(t, db, nil, 0, 1, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh password with maxAgeDays=1 must pass: got %d", rec.Code)
	}
	if v := mustChangeFlag(t, db, uid); v != 0 {
		t.Error("fresh password must not flip must_change_password")
	}
}

// TestAuthWithPolicy_PasswordExpiryDisabledPasses pins the disabled-policy
// semantics: maxAgeDays=0 (the default) never expires web sessions, even
// with an ancient password_changed_at. Runs live today via the zero
// maxAgeDays harness branch.
func TestAuthWithPolicy_PasswordExpiryDisabledPasses(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "expdis", "user", true)
	backdatePasswordChangedAt(t, db, uid, 400*24*time.Hour)

	tok := issueTokenWithSID(t, &models.User{ID: uid, Username: "expdis", Role: "user"}, "sid-exp-dis", time.Hour)

	rec := runPolicyWithPasswordMaxAge(t, db, nil, 0, 0, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("maxAgeDays=0 must disable expiry: got %d", rec.Code)
	}
	if v := mustChangeFlag(t, db, uid); v != 0 {
		t.Error("maxAgeDays=0 must not flip must_change_password")
	}
}

// TestAuthWithPolicy_PasswordExpirySSOBypass verifies the SSO exemption: an
// SSO-established session (JWT auth_provider claim set) with an aged local
// password passes through and the flag is NOT flipped — the local password
// is irrelevant to an IdP-authenticated session.
func TestAuthWithPolicy_PasswordExpirySSOBypass(t *testing.T) {
	db := newTestAuthDB(t)
	uid := seedTestUser(t, db, "agedsso", "user", true)
	backdatePasswordChangedAt(t, db, uid, 48*time.Hour)

	tok, err := GenerateSessionToken(&models.User{ID: uid, Username: "agedsso", Role: "user"}, testSecret, time.Hour, "keycloak")
	if err != nil {
		t.Fatal(err)
	}

	rec := runPolicyWithPasswordMaxAge(t, db, nil, 0, 1, tok, "/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("aged SSO session must pass despite maxAgeDays=1: got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if v := mustChangeFlag(t, db, uid); v != 0 {
		t.Error("SSO session must not flip must_change_password")
	}
}
