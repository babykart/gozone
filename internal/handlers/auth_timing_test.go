package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/testutil"
)

// Recording spy over the sqlite3 driver
// ---------------------------------------------------------------------------
//
// TestLogin_UnknownUserMatchesKnownUserReadShape pins the READ SHAPE of the
// login failure path: an unknown username must issue the same two lock-status
// reads as a wrong password for a real user — the manual-lock read (SELECT
// ... manual_lock_until) and the automatic-lock status read (SELECT ...
// locked_until) — otherwise the number of round trips distinguishes the two
// and leaks account existence. The failed-login counter transaction stays
// known-path-only by design (see the sentinel-read comment in Login), so the
// parity claim is scoped to those two reads, not the whole statement set. A
// behavioural test cannot pin this (both paths already return the same 303),
// so the spy wraps mattn's sqlite3 driver at the database/sql driver
// boundary, records every statement seen through Prepare (the prepared path)
// or ExecContext (the direct-exec path database/sql prefers when the
// connection implements driver.ExecerContext — which sqlite3 does), and
// passes everything through unchanged (NO forced failures here). Statements
// are recorded verbatim (trimmed) so assertions can match on query text.
//
// The connection is opened through database.NewWithOpener so dialect
// selection, DSN rewriting, pool tuning (SQLite runs a single connection)
// and migrations all behave exactly as production; the single shared
// in-memory database persists for the lifetime of the test.
//
// Only the timing tests use the spy; the slice is mutex-guarded for the race
// detector.

var (
	loginSpyMu      sync.Mutex
	loginSpyQueries []string
)

func loginSpyRecord(query string) {
	loginSpyMu.Lock()
	defer loginSpyMu.Unlock()
	loginSpyQueries = append(loginSpyQueries, strings.TrimSpace(query))
}

// loginSpyReset drops everything recorded so far; tests call it once the
// seeding noise is done so only the login statements are asserted on.
func loginSpyReset() {
	loginSpyMu.Lock()
	defer loginSpyMu.Unlock()
	loginSpyQueries = nil
}

func loginSpySnapshot() []string {
	loginSpyMu.Lock()
	defer loginSpyMu.Unlock()
	return append([]string(nil), loginSpyQueries...)
}

// loginSpyHasContaining reports whether a recorded statement contains the
// given query-text needle (e.g. a column name that only one read uses).
func loginSpyHasContaining(markers []string, needle string) bool {
	for _, m := range markers {
		if strings.Contains(m, needle) {
			return true
		}
	}
	return false
}

// loginSpyHasSelectContaining reports whether a recorded SELECT statement
// contains the needle — used to pin a read specifically, so a later UPDATE
// referencing the same column cannot satisfy the assertion.
func loginSpyHasSelectContaining(markers []string, needle string) bool {
	for _, m := range markers {
		if strings.HasPrefix(m, "SELECT") && strings.Contains(m, needle) {
			return true
		}
	}
	return false
}

// loginSpyConnector is a database/sql driver.Connector over the sqlite3
// driver whose connections record every statement and pass it through.
type loginSpyConnector struct {
	dsn string
}

func (c *loginSpyConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite3.SQLiteDriver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &loginSpyConn{Conn: conn}, nil
}

func (c *loginSpyConnector) Driver() driver.Driver { return &sqlite3.SQLiteDriver{} }

type loginSpyConn struct {
	driver.Conn
}

func (c *loginSpyConn) Prepare(query string) (driver.Stmt, error) {
	loginSpyRecord(query)
	return c.Conn.Prepare(query)
}

func (c *loginSpyConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	loginSpyRecord(query)
	ec, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, errors.New("loginSpyConn: inner driver lacks ExecerContext")
	}
	return ec.ExecContext(ctx, query, args)
}

// newLoginSpyDB opens the schema through the recording spy connector.
func newLoginSpyDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewWithOpener(
		&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"},
		func(_ string, dsn string) (*sql.DB, error) {
			return sql.OpenDB(&loginSpyConnector{dsn: dsn}), nil
		},
	)
	if err != nil {
		t.Fatalf("open spy database: %v", err)
	}
	t.Cleanup(func() { db.Close() }) // #nosec G104 -- test cleanup
	return db
}

// newLoginSpyHandler mirrors newTestHandler but routes the database through
// the recording spy. Tmpl is nil: Login never renders a template on the
// failure paths under test (every failure redirects), and the mock PDNS is
// unused by Login.
func newLoginSpyHandler(t *testing.T) *Handler {
	t.Helper()
	_, pdnsClient := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	h := &Handler{
		DB:   newLoginSpyDB(t),
		PDNS: pdnsClient,
		Cfg:  config.DefaultConfig(),
		Tmpl: nil,
	}
	h.Cfg.Password = config.PasswordConfig{}
	h.Cfg.LoginLock.MaxFailedAttempts = 10
	h.Cfg.LoginLock.LockoutDurationMinutes = 15
	return h
}

func loginSpyPost(t *testing.T, h *Handler, form string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)
	return w
}

func assertInvalidCredentialsRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login?error="+invalidCredentialsError) {
		t.Errorf("expected redirect to /login?error=%s, got %q", invalidCredentialsError, loc)
	}
}

// TestLogin_UnknownUserMatchesKnownUserReadShape pins that the unknown-user
// failure path issues the same two lock-status reads as the known-user
// wrong-password path: the manual-lock read (SELECT ... manual_lock_until)
// and the automatic-lock status read (SELECT ... locked_until) run on BOTH
// paths, plus the login_attempts INSERT each, so the round-trip count of
// those reads cannot distinguish an unknown username from a wrong password.
// The failed-login counter transaction remains known-path-only by design and
// is deliberately not asserted here. The sentinel reads target user ID 0 (no
// row), so they must also leave no state: a second unknown-user attempt
// behaves identically and no users UPDATE appears.
func TestLogin_UnknownUserMatchesKnownUserReadShape(t *testing.T) {
	h := newLoginSpyHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	insertReturnID(t, h.DB,
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"knownuser", "known@example.com", string(hash), "user",
	)

	// Unknown username: without the sentinel reads this path would issue
	// neither the manual-lock read nor the lock-status read, and the read
	// profile would differ from the known-user failure path.
	loginSpyReset()
	assertInvalidCredentialsRedirect(t, loginSpyPost(t, h, "username=nosuchuser&password=whatever"))

	markers := loginSpySnapshot()
	if !loginSpyHasSelectContaining(markers, "manual_lock_until") {
		t.Errorf("unknown-user path: no manual-lock read recorded; statements: %v", markers)
	}
	if !loginSpyHasSelectContaining(markers, "locked_until") {
		t.Errorf("unknown-user path: no lock-status read recorded; statements: %v", markers)
	}
	if !loginSpyHasContaining(markers, "INSERT INTO login_attempts") {
		t.Errorf("unknown-user path: no login_attempts INSERT recorded; statements: %v", markers)
	}
	for _, m := range markers {
		if strings.HasPrefix(m, "UPDATE users") {
			t.Errorf("unknown-user path must not write users state; statement: %s", m)
		}
	}

	// The sentinel reads left no state: a second unknown-user attempt is
	// identical and still redirects to the generic error.
	loginSpyReset()
	assertInvalidCredentialsRedirect(t, loginSpyPost(t, h, "username=nosuchuser&password=whatever"))
	for _, m := range loginSpySnapshot() {
		if strings.HasPrefix(m, "UPDATE users") {
			t.Errorf("second unknown-user attempt must not write users state; statement: %s", m)
		}
	}

	// Sanity symmetry: the known-user wrong-password path issues the same two
	// reads (the UPDATE inside the counter transaction also references
	// locked_until, hence the SELECT-only pin).
	loginSpyReset()
	assertInvalidCredentialsRedirect(t, loginSpyPost(t, h, "username=knownuser&password=wrong"))

	markers = loginSpySnapshot()
	if !loginSpyHasSelectContaining(markers, "manual_lock_until") {
		t.Errorf("known-user path: no manual-lock read recorded; statements: %v", markers)
	}
	if !loginSpyHasSelectContaining(markers, "locked_until") {
		t.Errorf("known-user path: no lock-status read recorded; statements: %v", markers)
	}
	if !loginSpyHasContaining(markers, "INSERT INTO login_attempts") {
		t.Errorf("known-user path: no login_attempts INSERT recorded; statements: %v", markers)
	}
}

// TestLegacyCostPads pins the cost-band padding rule: the pad count is
// 2^(configuredCost-storedCost)-1 — stored-cost compares that scale the
// padded total to exactly the configured band — whenever the stored hash's
// embedded cost parses AND is strictly below the configured cost, clamped to
// legacyCostPadCap for extreme gaps. A hash at or above the configured cost,
// or one whose cost cannot be parsed (malformed hashes fail before the
// compare anyway), needs no pad.
func TestLegacyCostPads(t *testing.T) {
	cost4, err := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	if err != nil {
		t.Fatalf("bcrypt cost 4: %v", err)
	}
	cost9, err := bcrypt.GenerateFromPassword([]byte("goodpass"), 9)
	if err != nil {
		t.Fatalf("bcrypt cost 9: %v", err)
	}
	cost10, err := bcrypt.GenerateFromPassword([]byte("goodpass"), 10)
	if err != nil {
		t.Fatalf("bcrypt cost 10: %v", err)
	}
	cost12, err := bcrypt.GenerateFromPassword([]byte("goodpass"), 12)
	if err != nil {
		t.Fatalf("bcrypt cost 12: %v", err)
	}

	cases := []struct {
		name           string
		storedHash     []byte
		configuredCost int
		want           int
	}{
		{"legacy cost four below", cost4, 10, 63},
		{"legacy cost one below", cost9, 10, 1},
		{"cost matches configured", cost10, 10, 0},
		{"cost above configured", cost12, 10, 0},
		{"extreme gap clamped to cap", cost4, 31, legacyCostPadCap},
		{"unparseable hash", []byte("not-a-hash"), 10, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := legacyCostPads(tc.storedHash, tc.configuredCost); got != tc.want {
				t.Errorf("legacyCostPads(%q, %d) = %d, want %d", tc.storedHash, tc.configuredCost, got, tc.want)
			}
		})
	}
}

// newTimingTestHandler builds a Handler with a plain in-memory database (no
// statement spy) at the given bcrypt cost, for tests that count compares
// instead of statements. Tmpl is nil: Login never renders a template on the
// failure paths under test.
func newTimingTestHandler(t *testing.T, bcryptCost int) *Handler {
	t.Helper()
	_, pdnsClient := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	h := &Handler{
		DB:   newTestDB(t),
		PDNS: pdnsClient,
		Cfg:  config.DefaultConfig(),
		Tmpl: nil,
	}
	h.Cfg.Password = config.PasswordConfig{}
	h.Cfg.Auth.BcryptCost = bcryptCost
	h.Cfg.LoginLock.MaxFailedAttempts = 10
	h.Cfg.LoginLock.LockoutDurationMinutes = 15
	return h
}

// TestLogin_LegacyCostPaddingCount is the deterministic guard for the
// cost-band padding: with bcrypt cost 10 configured, a wrong password against
// a cost-4 stored hash must perform exactly 1 + (2^6 - 1) = 64 compares (one
// real compare plus 63 stored-cost pads, landing the total in the configured
// band), and a cost-10 stored hash exactly 1 (no pads). The count is pinned
// through the bcryptCompare seam, so no wall-clock assertion is needed. No
// test in this package runs in parallel, so the package-level seam swap is
// live only for the duration of this serial test.
func TestLogin_LegacyCostPaddingCount(t *testing.T) {
	orig := bcryptCompare
	t.Cleanup(func() { bcryptCompare = orig })

	cases := []struct {
		name       string
		storedCost int
		wantCalls  int
	}{
		{"legacy lower cost padded", 4, 64},
		{"configured cost unpadded", 10, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTimingTestHandler(t, 10)

			hash, err := bcrypt.GenerateFromPassword([]byte("goodpass"), tc.storedCost)
			if err != nil {
				t.Fatalf("bcrypt cost %d: %v", tc.storedCost, err)
			}
			insertReturnID(t, h.DB,
				`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
				"paddingcount", "padding@example.com", string(hash), "user",
			)

			// Pre-build the package-level dummy hash at the configured cost so
			// its generation cannot interleave with the login below (mirrors
			// TestLogin_CredentialRotatedDuringBcryptDenied).
			ensureDummyHash(h.Cfg.Auth.BcryptCost)

			calls := 0
			bcryptCompare = func(hashedPassword, password []byte) error {
				calls++
				return orig(hashedPassword, password)
			}

			assertInvalidCredentialsRedirect(t, loginSpyPost(t, h, "username=paddingcount&password=wrong"))
			if calls != tc.wantCalls {
				t.Errorf("compare calls = %d, want exactly %d (1 real compare + pads)", calls, tc.wantCalls)
			}
		})
	}
}
