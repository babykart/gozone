// Package testutil provides reusable test helpers for GoZone packages.
//
// It includes factories for in-memory SQLite databases, mock PowerDNS
// HTTP servers, and user/API key seeding functions.
package testutil

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/pdns"
)

// NewTestDB creates an in-memory SQLite database with the full GoZone
// schema (users, activity_logs, api_keys, settings) already migrated.
//
// The database is automatically closed when the test finishes via t.Cleanup.
func NewTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			first_name TEXT NOT NULL DEFAULT '',
			last_name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			zone_id TEXT,
			action TEXT NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			last_used_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL UNIQUE,
			value TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// PDNSHandlerFunc is the signature for mock PowerDNS handler functions.
type PDNSHandlerFunc func(w http.ResponseWriter, r *http.Request)

// NewTestPDNSServer creates an httptest.Server and a PowerDNS client
// configured to talk to it. The handler parameter controls the server
// responses; pass nil to return 500 for all requests.
//
// The server is automatically closed when the test finishes via t.Cleanup.
func NewTestPDNSServer(t *testing.T, handler PDNSHandlerFunc) (*httptest.Server, *pdns.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler != nil {
			handler(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	client := pdns.NewClient(&config.PowerDNSConfig{
		APIURL:   srv.URL,
		APIKey:   "test",
		ServerID: "localhost",
	})
	return srv, client
}

// SeedTestUser inserts a user with a bcrypt-hashed password into the database.
//
// The password is hashed with cost 4 for test performance.
// Returns the new user's ID.
func SeedTestUser(t *testing.T, db *sql.DB, username, password, role string, enabled bool) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	result, err := db.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, username+"@test.local", string(hash), "Test", "User", role, enabledVal,
	)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	return id
}

// SeedTestAPIKey inserts an API key for the given user into the database.
//
// Pass nil for expiresAt to create a non-expiring key.
func SeedTestAPIKey(t *testing.T, db *sql.DB, userID int64, keyHash string, expiresAt *time.Time) {
	t.Helper()
	var expires interface{}
	if expiresAt != nil {
		expires = *expiresAt
	}
	_, err := db.Exec(
		`INSERT INTO api_keys (user_id, key_hash, description, expires_at) VALUES (?, ?, ?, ?)`,
		userID, keyHash, "test key", expires,
	)
	if err != nil {
		t.Fatal(err)
	}
}
