// Package testutil provides reusable test helpers for GoZone packages.
//
// It includes factories for in-memory SQLite databases, mock PowerDNS
// HTTP servers, and user/API key seeding functions.
package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/pdns"
)

// NewTestDB creates an in-memory SQLite database with the full GoZone
// schema (users, activity_logs, api_keys, settings) already migrated.
//
// The database is automatically closed when the test finishes via t.Cleanup.
func NewTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) // #nosec G104
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
func SeedTestUser(t *testing.T, db *database.DB, username, password, role string, enabled bool) int64 {
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
// The raw key is SHA-256 hashed before storage. Pass nil for expiresAt
// to create a non-expiring key.
func SeedTestAPIKey(t *testing.T, db *database.DB, userID int64, rawKey string, expiresAt *time.Time) {
	t.Helper()
	var expires interface{}
	if expiresAt != nil {
		expires = *expiresAt
	}
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	_, err := db.Exec(
		`INSERT INTO api_keys (user_id, key_hash, description, expires_at) VALUES (?, ?, ?, ?)`,
		userID, keyHash, "test key", expires,
	)
	if err != nil {
		t.Fatal(err)
	}
}
